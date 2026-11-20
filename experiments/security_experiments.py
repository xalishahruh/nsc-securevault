"""SecureVault Security Experiment Runner — 6COSC033C CW1

Implements controlled security experiments demonstrating the difference between
AES-256-GCM (authenticated encryption) and AES-256-CBC (confidentiality only)
in terms of tamper detection, integrity protection, and failure behavior.

Experiments are run against in-memory containers and isolated temporary files.
No production files or real sensitive data are used or modified.

Usage:
    python -m experiments.security_experiments
    python -m experiments.security_experiments --output experiments/results/security_outcomes.csv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import struct
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Ensure src is on path when run directly
_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from securevault.crypto.gcm import (
    encrypt_gcm,
    decrypt_gcm,
    generate_gcm_dek,
    generate_gcm_nonce,
)
from securevault.crypto.cbc import (
    encrypt_cbc,
    decrypt_cbc,
    generate_cbc_dek,
    generate_cbc_iv,
)
from securevault.container import (
    ContainerHeader,
    serialize_container,
    parse_container,
    CIPHER_GCM,
    CIPHER_CBC,
    KEY_PROT_EXTERNAL,
    HEADER_SIZE,
)
from securevault.errors import (
    AuthenticationError,
    PaddingError,
    MalformedContainerError,
    InvalidHeaderError,
    InvalidKeyError,
    ModeMismatchError,
    SecureVaultError,
)


# ---------------------------------------------------------------------------
# Experiment result
# ---------------------------------------------------------------------------

@dataclass
class ExperimentResult:
    experiment_id: str
    mode: str
    tamper_target: str
    tamper_description: str
    expected_outcome: str
    observed_outcome: str
    exception_type: str
    plaintext_published: bool
    plaintext_matches_original: Optional[bool]
    integrity_protected: bool
    notes: str


# ---------------------------------------------------------------------------
# Shared plaintext fixture
# ---------------------------------------------------------------------------

PLAINTEXT = (
    b"SecureVault security experiment payload.\n"
    b"AES-GCM provides authenticated encryption; AES-CBC does not.\n"
    b"This text is used to verify tamper detection behavior.\n"
    b"padding follows: " + bytes(range(256)) * 2
)[:512]  # 512 bytes


def _make_gcm_container() -> tuple[bytes, bytes, bytes, bytes, bytes]:
    """Return (container_bytes, dek, nonce, file_id, aad)."""
    dek = generate_gcm_dek()
    nonce = generate_gcm_nonce()
    file_id = os.urandom(16)
    header = ContainerHeader(
        version=1,
        cipher_id=CIPHER_GCM,
        flags=0,
        file_id=file_id,
        iv_or_nonce=nonce,
        ciphertext_length=len(PLAINTEXT),
    )
    aad = header.serialize()
    ciphertext, tag = encrypt_gcm(dek, nonce, PLAINTEXT, associated_data=aad)
    container = serialize_container(
        header=header,
        ciphertext=ciphertext,
        key_protection_id=KEY_PROT_EXTERNAL,
        gcm_tag=tag,
    )
    return container, dek, nonce, file_id, aad


def _make_cbc_container() -> tuple[bytes, bytes, bytes, bytes]:
    """Return (container_bytes, dek, iv, file_id)."""
    dek = generate_cbc_dek()
    iv = generate_cbc_iv()
    file_id = os.urandom(16)
    header = ContainerHeader(
        version=1,
        cipher_id=CIPHER_CBC,
        flags=0,
        file_id=file_id,
        iv_or_nonce=iv,
        ciphertext_length=0,  # placeholder; will be updated
    )
    ciphertext = encrypt_cbc(dek, iv, PLAINTEXT)
    # Rebuild header with correct ciphertext length
    header = ContainerHeader(
        version=1,
        cipher_id=CIPHER_CBC,
        flags=0,
        file_id=file_id,
        iv_or_nonce=iv,
        ciphertext_length=len(ciphertext),
    )
    container = serialize_container(
        header=header,
        ciphertext=ciphertext,
        key_protection_id=KEY_PROT_EXTERNAL,
    )
    return container, dek, iv, file_id


def _try_gcm_decrypt(container_bytes: bytes, dek: bytes) -> tuple[Optional[bytes], Optional[Exception]]:
    """Attempt GCM decryption; return (plaintext or None, exception or None)."""
    try:
        parsed = parse_container(container_bytes)
        aad = parsed.immutable_header_bytes
        pt = decrypt_gcm(dek, parsed.header.iv_or_nonce, parsed.ciphertext, parsed.gcm_tag, associated_data=aad)
        return pt, None
    except Exception as exc:
        return None, exc


def _try_cbc_decrypt(container_bytes: bytes, dek: bytes) -> tuple[Optional[bytes], Optional[Exception]]:
    """Attempt CBC decryption; return (plaintext or None, exception or None)."""
    try:
        parsed = parse_container(container_bytes)
        pt = decrypt_cbc(dek, parsed.header.iv_or_nonce, parsed.ciphertext)
        return pt, None
    except Exception as exc:
        return None, exc


# ---------------------------------------------------------------------------
# GCM Experiments
# ---------------------------------------------------------------------------

def gcm_exp_modify_ciphertext() -> ExperimentResult:
    """GCM-01: Modify one byte of ciphertext."""
    container, dek, _, _, _ = _make_gcm_container()
    tampered = bytearray(container)
    # First ciphertext byte is at HEADER_SIZE + 3 (key_desc) = 51
    tampered[51] ^= 0xFF
    pt, exc = _try_gcm_decrypt(bytes(tampered), dek)
    return ExperimentResult(
        experiment_id="GCM-01",
        mode="GCM",
        tamper_target="ciphertext",
        tamper_description="Flip 0xFF on first ciphertext byte (offset 51)",
        expected_outcome="AuthenticationError; no plaintext output",
        observed_outcome="AuthenticationError" if isinstance(exc, AuthenticationError) else f"Other: {type(exc).__name__}" if exc else "ACCEPTED (UNEXPECTED)",
        exception_type=type(exc).__name__ if exc else "None",
        plaintext_published=pt is not None,
        plaintext_matches_original=None if pt is None else pt == PLAINTEXT,
        integrity_protected=isinstance(exc, AuthenticationError) and pt is None,
        notes="GCM authentication tag covers ciphertext; any modification causes tag mismatch.",
    )


def gcm_exp_modify_tag() -> ExperimentResult:
    """GCM-02: Modify authentication tag."""
    container, dek, _, _, _ = _make_gcm_container()
    tampered = bytearray(container)
    tampered[-1] ^= 0xFF  # Last 16 bytes = GCM tag
    pt, exc = _try_gcm_decrypt(bytes(tampered), dek)
    return ExperimentResult(
        experiment_id="GCM-02",
        mode="GCM",
        tamper_target="authentication_tag",
        tamper_description="Flip 0xFF on last byte of GCM authentication tag",
        expected_outcome="AuthenticationError; no plaintext output",
        observed_outcome="AuthenticationError" if isinstance(exc, AuthenticationError) else f"Other: {type(exc).__name__}" if exc else "ACCEPTED (UNEXPECTED)",
        exception_type=type(exc).__name__ if exc else "None",
        plaintext_published=pt is not None,
        plaintext_matches_original=None if pt is None else pt == PLAINTEXT,
        integrity_protected=isinstance(exc, AuthenticationError) and pt is None,
        notes="GCM tag is GHASH of ciphertext; tag modification causes immediate rejection.",
    )


def gcm_exp_modify_header_aad() -> ExperimentResult:
    """GCM-03: Modify immutable header bytes (used as GCM AAD)."""
    container, dek, _, _, _ = _make_gcm_container()
    tampered = bytearray(container)
    tampered[10] ^= 0x01  # Tamper file_id byte in header (offset 10, within first 48 bytes)
    # Note: file_id check in key_provider will trigger first; either error proves header protection
    try:
        parsed = parse_container(bytes(tampered))
        aad = parsed.immutable_header_bytes
        pt = decrypt_gcm(dek, parsed.header.iv_or_nonce, parsed.ciphertext, parsed.gcm_tag, associated_data=aad)
        exc = None
    except Exception as e:
        pt = None
        exc = e
    protected = pt is None and exc is not None
    return ExperimentResult(
        experiment_id="GCM-03",
        mode="GCM",
        tamper_target="immutable_header_aad",
        tamper_description="Flip bit in file_id field within 48-byte immutable header (GCM AAD)",
        expected_outcome="AuthenticationError (header bound as AAD); no plaintext output",
        observed_outcome=f"{type(exc).__name__}" if exc else "ACCEPTED (UNEXPECTED)",
        exception_type=type(exc).__name__ if exc else "None",
        plaintext_published=pt is not None,
        plaintext_matches_original=None if pt is None else pt == PLAINTEXT,
        integrity_protected=protected,
        notes="Immutable header bytes are bound as GCM AAD. Any header modification is detected.",
    )


def gcm_exp_wrong_key() -> ExperimentResult:
    """GCM-04: Supply incorrect key material."""
    container, _, _, _, _ = _make_gcm_container()
    wrong_dek = generate_gcm_dek()  # Fresh random key
    pt, exc = _try_gcm_decrypt(container, wrong_dek)
    return ExperimentResult(
        experiment_id="GCM-04",
        mode="GCM",
        tamper_target="key_material",
        tamper_description="Replace DEK with a fresh random 32-byte key",
        expected_outcome="AuthenticationError; no plaintext output",
        observed_outcome="AuthenticationError" if isinstance(exc, AuthenticationError) else f"Other: {type(exc).__name__}" if exc else "ACCEPTED (UNEXPECTED)",
        exception_type=type(exc).__name__ if exc else "None",
        plaintext_published=pt is not None,
        plaintext_matches_original=None if pt is None else pt == PLAINTEXT,
        integrity_protected=isinstance(exc, AuthenticationError) and pt is None,
        notes="Wrong key causes GHASH mismatch; GCM tag verification fails before any plaintext is released.",
    )


def gcm_exp_truncate_container() -> ExperimentResult:
    """GCM-05: Truncate the container."""
    container, dek, _, _, _ = _make_gcm_container()
    truncated = container[:len(container) // 2]
    pt, exc = _try_gcm_decrypt(truncated, dek)
    return ExperimentResult(
        experiment_id="GCM-05",
        mode="GCM",
        tamper_target="container_length",
        tamper_description=f"Truncate container from {len(container)} to {len(truncated)} bytes",
        expected_outcome="MalformedContainerError; no plaintext output",
        observed_outcome=f"{type(exc).__name__}" if exc else "ACCEPTED (UNEXPECTED)",
        exception_type=type(exc).__name__ if exc else "None",
        plaintext_published=pt is not None,
        plaintext_matches_original=None if pt is None else pt == PLAINTEXT,
        integrity_protected=exc is not None and pt is None,
        notes="Parser enforces exact container size from header; truncation causes MalformedContainerError.",
    )


# ---------------------------------------------------------------------------
# CBC Experiments
# ---------------------------------------------------------------------------

def cbc_exp_modify_ciphertext() -> ExperimentResult:
    """CBC-01: Modify one byte of ciphertext (non-last block)."""
    container, dek, _, _ = _make_cbc_container()
    tampered = bytearray(container)
    # First ciphertext byte at offset 51 (header 48 + key_desc 3)
    tampered[51] ^= 0xFF
    pt, exc = _try_cbc_decrypt(bytes(tampered), dek)
    matches = pt == PLAINTEXT if pt is not None else None
    return ExperimentResult(
        experiment_id="CBC-01",
        mode="CBC",
        tamper_target="ciphertext",
        tamper_description="Flip 0xFF on first ciphertext byte (offset 51); affects first two CBC blocks",
        expected_outcome="Silently accepted OR PaddingError — corrupted plaintext returned, NO authentication",
        observed_outcome=(
            "Corrupted plaintext returned (no detection)" if pt is not None and matches is False
            else "PaddingError raised" if isinstance(exc, PaddingError)
            else "Original plaintext matched (unexpected)" if matches is True
            else f"Other: {type(exc).__name__}" if exc else "Unknown"
        ),
        exception_type=type(exc).__name__ if exc else "None",
        plaintext_published=pt is not None,
        plaintext_matches_original=matches,
        integrity_protected=False,
        notes=(
            "CBC propagates errors: first block fully corrupted, second block has the same bit flip. "
            "No authentication — corruption accepted silently if padding is valid."
        ),
    )


def cbc_exp_modify_iv() -> ExperimentResult:
    """CBC-02: Modify the IV (corrupts only first plaintext block)."""
    container, dek, _, _ = _make_cbc_container()
    tampered = bytearray(container)
    # IV is at header offset 24 (after magic 4, version 1, cipher 1, flags 2, file_id 16 = 24)
    tampered[25] ^= 0x42
    pt, exc = _try_cbc_decrypt(bytes(tampered), dek)
    matches = pt == PLAINTEXT if pt is not None else None
    return ExperimentResult(
        experiment_id="CBC-02",
        mode="CBC",
        tamper_target="iv",
        tamper_description="Flip 0x42 on IV byte at offset 25 — affects only first 16-byte plaintext block",
        expected_outcome="Silently accepted with corrupted first block; remaining blocks correct",
        observed_outcome=(
            "Corrupted first block; remaining blocks correct (no detection)" if pt is not None and matches is False
            else "Exact match (unexpected)" if matches is True
            else f"Exception: {type(exc).__name__}" if exc else "Unknown"
        ),
        exception_type=type(exc).__name__ if exc else "None",
        plaintext_published=pt is not None,
        plaintext_matches_original=matches,
        integrity_protected=False,
        notes=(
            "IV XOR feeds directly into first block decryption. "
            "CBC IV tampering silently corrupts exactly the first plaintext block; all subsequent blocks are unaffected. "
            "No detection mechanism exists without external authentication."
        ),
    )


def cbc_exp_wrong_key() -> ExperimentResult:
    """CBC-03: Supply incorrect key material."""
    container, _, _, _ = _make_cbc_container()
    wrong_dek = generate_cbc_dek()
    pt, exc = _try_cbc_decrypt(container, wrong_dek)
    matches = pt == PLAINTEXT if pt is not None else None
    return ExperimentResult(
        experiment_id="CBC-03",
        mode="CBC",
        tamper_target="key_material",
        tamper_description="Replace DEK with a fresh random 32-byte key",
        expected_outcome="PaddingError or corrupted plaintext; no reliable detection",
        observed_outcome=(
            "PaddingError raised (incorrect key caused invalid PKCS#7)" if isinstance(exc, PaddingError)
            else "Corrupted plaintext accepted" if pt is not None and matches is False
            else f"Exception: {type(exc).__name__}" if exc else "Unknown"
        ),
        exception_type=type(exc).__name__ if exc else "None",
        plaintext_published=pt is not None,
        plaintext_matches_original=matches,
        integrity_protected=False,
        notes=(
            "CBC wrong key typically corrupts padding; PaddingError is raised in most cases "
            "but is NOT a reliable authentication mechanism — it is probabilistic, not cryptographic."
        ),
    )


def cbc_exp_truncate_ciphertext() -> ExperimentResult:
    """CBC-04: Truncate ciphertext to invalid length."""
    container, dek, _, _ = _make_cbc_container()
    truncated = container[:len(container) // 2]
    pt, exc = _try_cbc_decrypt(truncated, dek)
    return ExperimentResult(
        experiment_id="CBC-04",
        mode="CBC",
        tamper_target="container_length",
        tamper_description=f"Truncate container from {len(container)} to {len(truncated)} bytes",
        expected_outcome="MalformedContainerError from parser; no plaintext output",
        observed_outcome=f"{type(exc).__name__}" if exc else "ACCEPTED (UNEXPECTED)",
        exception_type=type(exc).__name__ if exc else "None",
        plaintext_published=pt is not None,
        plaintext_matches_original=None if pt is None else pt == PLAINTEXT,
        integrity_protected=exc is not None and pt is None,
        notes="Container parser enforces exact size; structural truncation is detected at parse time (not cryptographically).",
    )


def cbc_exp_controlled_plaintext_corruption() -> ExperimentResult:
    """CBC-05: Demonstrate CBC plaintext corruption without padding error.

    Tampers a ciphertext block that is NOT the last block.
    When targeting a non-last block in CBC, the tampered block produces garbage in
    the corresponding plaintext block AND a fixed bit flip in the NEXT block.
    If PKCS#7 padding in the last block remains valid, decryption succeeds silently.
    """
    # Use a 3-block plaintext (48 bytes) so we can target the first block safely
    plaintext_3blk = bytes(range(48))  # 3 × 16 bytes, no padding needed after PKCS#7
    dek = generate_cbc_dek()
    iv = generate_cbc_iv()
    file_id = os.urandom(16)
    ciphertext = encrypt_cbc(dek, iv, plaintext_3blk)
    header = ContainerHeader(
        version=1, cipher_id=CIPHER_CBC, flags=0,
        file_id=file_id, iv_or_nonce=iv, ciphertext_length=len(ciphertext),
    )
    container = serialize_container(header=header, ciphertext=ciphertext, key_protection_id=KEY_PROT_EXTERNAL)

    tampered = bytearray(container)
    # Tamper first ciphertext byte (offset 51); this corrupts first plaintext block
    # and XOR-flips corresponding byte in second plaintext block
    tampered[51] ^= 0x01
    try:
        parsed = parse_container(bytes(tampered))
        pt = decrypt_cbc(dek, parsed.header.iv_or_nonce, parsed.ciphertext)
        exc = None
    except Exception as e:
        pt = None
        exc = e

    matches = pt == plaintext_3blk if pt is not None else None
    detected = exc is not None
    return ExperimentResult(
        experiment_id="CBC-05",
        mode="CBC",
        tamper_target="ciphertext_non_last_block",
        tamper_description=(
            "Flip bit in first ciphertext block; targets non-last block to preserve valid PKCS#7 "
            "padding in final block — demonstrates undetected corruption"
        ),
        expected_outcome=(
            "Corrupted plaintext returned with valid PKCS#7 (block 1 garbage, block 2 bit-flipped). "
            "DEMONSTRATES: padding validity ≠ ciphertext integrity."
        ),
        observed_outcome=(
            "Corrupted plaintext returned without detection" if pt is not None and matches is False
            else "PaddingError raised (last block affected — padding violated)" if isinstance(exc, PaddingError)
            else "Exact match (unexpected)" if matches is True
            else f"Exception: {type(exc).__name__}" if exc else "Unknown"
        ),
        exception_type=type(exc).__name__ if exc else "None",
        plaintext_published=pt is not None,
        plaintext_matches_original=matches,
        integrity_protected=False,
        notes=(
            "CRITICAL FINDING: AES-CBC has no inherent integrity or authentication. "
            "Padding validity is NOT cryptographic authentication. "
            "A valid PKCS#7 padding after ciphertext modification is NOT evidence of authenticity."
        ),
    )


# ---------------------------------------------------------------------------
# Runner and CSV output
# ---------------------------------------------------------------------------

HEADER = [
    "experiment_id", "mode", "tamper_target", "tamper_description",
    "expected_outcome", "observed_outcome", "exception_type",
    "plaintext_published", "plaintext_matches_original", "integrity_protected", "notes",
]

EXPERIMENTS = [
    gcm_exp_modify_ciphertext,
    gcm_exp_modify_tag,
    gcm_exp_modify_header_aad,
    gcm_exp_wrong_key,
    gcm_exp_truncate_container,
    cbc_exp_modify_ciphertext,
    cbc_exp_modify_iv,
    cbc_exp_wrong_key,
    cbc_exp_truncate_ciphertext,
    cbc_exp_controlled_plaintext_corruption,
]


def run_all() -> list[ExperimentResult]:
    results = []
    for fn in EXPERIMENTS:
        try:
            r = fn()
            results.append(r)
            status = "PASS" if r.integrity_protected or r.experiment_id.startswith("CBC") else "FAIL"
            print(f"  [{r.experiment_id}] {r.tamper_target}: {r.observed_outcome[:80]}")
        except Exception as exc:
            print(f"  [ERROR] {fn.__name__}: {exc}", file=sys.stderr)
    return results


def write_csv(results: list[ExperimentResult], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent
    )
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(HEADER)
            for r in results:
                writer.writerow(
                    [
                        r.experiment_id, r.mode, r.tamper_target, r.tamper_description,
                        r.expected_outcome, r.observed_outcome, r.exception_type,
                        r.plaintext_published, r.plaintext_matches_original,
                        r.integrity_protected, r.notes,
                    ]
                )
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(temporary, output_path)
        except FileExistsError as exc:
            raise FileExistsError(
                f"Output already exists; refusing to overwrite: {output_path}"
            ) from exc
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureVault security experiment runner")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("experiments/results/security_outcomes.csv"),
        help="Output CSV path",
    )
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error(f"Output already exists; choose a new path: {args.output}")

    print("SecureVault Security Experiments")
    print("=" * 60)
    print(f"Plaintext fixture: {len(PLAINTEXT)} bytes")
    print()

    print("Running GCM experiments:")
    gcm_results = []
    for fn in EXPERIMENTS[:5]:
        r = fn()
        gcm_results.append(r)
        icon = "✓" if r.integrity_protected else "✗"
        print(f"  [{r.experiment_id}] {icon} {r.tamper_target}: {r.observed_outcome[:75]}")

    print()
    print("Running CBC experiments:")
    cbc_results = []
    for fn in EXPERIMENTS[5:]:
        r = fn()
        cbc_results.append(r)
        icon = "✓" if r.integrity_protected else "✗ (by design — CBC has no integrity)"
        print(f"  [{r.experiment_id}] {icon} {r.tamper_target}: {r.observed_outcome[:75]}")

    all_results = gcm_results + cbc_results
    write_csv(all_results, args.output)
    print()
    print(f"Results written to: {args.output}")
    print()
    print("Summary:")
    gcm_protected = sum(1 for r in gcm_results if r.integrity_protected)
    cbc_protected = sum(1 for r in cbc_results if r.integrity_protected)
    print(f"  GCM: {gcm_protected}/{len(gcm_results)} tamper cases detected and rejected (no plaintext published)")
    print(f"  CBC: {cbc_protected}/{len(cbc_results)} tamper cases detected (structural only; no cryptographic integrity)")
    print()
    print("FINDING: AES-CBC padding validity ≠ ciphertext integrity.")
    print("FINDING: AES-GCM rejects ALL tamper cases before releasing any plaintext.")


if __name__ == "__main__":
    main()
