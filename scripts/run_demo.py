"""Reproducible 10-step end-to-end demonstration for SecureVault.

Demonstrates:
  1. Input file selection / SHA-256 baseline
  2. AES-GCM encryption (.svlt + .svkey)
  3. AES-GCM decryption
  4. Exact-byte verification (SHA-256)
  5. AES-CBC encryption (.svlt + .svkey)
  6. AES-CBC decryption
  7. Exact-byte verification (SHA-256)
  8. Wrong-key rejection failure
  9. Tampered GCM container rejection failure
 10. Existing-output preservation (no-clobber)

Usage:
    python -m scripts.run_demo
    or
    python scripts/run_demo.py
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = REPO_ROOT / "demo"
SAMPLE_FILE = DEMO_DIR / "samples" / "sample.txt"


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_cmd(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="securevault-demo-") as directory:
        return _run_demo(Path(directory))


def _run_demo(work_dir: Path) -> int:
    python_bin = sys.executable
    print("=" * 70)
    print("SecureVault: End-to-End Coursework Demonstration (6COSC033C CW1)")
    print("=" * 70)

    # Step 1: Ensure sample file exists
    SAMPLE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not SAMPLE_FILE.exists():
        content = (
            b"SecureVault Coursework Sample Payload - 6COSC033C CW1.\n"
            b"Demonstrates AES-256-GCM authenticated encryption vs AES-256-CBC.\n"
        )
        content = content + bytes([i % 256 for i in range(1024 - len(content))])
        SAMPLE_FILE.write_bytes(content)

    orig_hash = sha256_of(SAMPLE_FILE)
    print(f"\n[1/10] Input sample file:")
    print(f"       Path:    {SAMPLE_FILE}")
    print(f"       Size:    {SAMPLE_FILE.stat().st_size} bytes")
    print(f"       SHA-256: {orig_hash}")

    gcm_svlt = work_dir / "sample_gcm.svlt"
    gcm_key = work_dir / "sample_gcm.svkey"
    gcm_rec = work_dir / "sample_gcm_recovered.txt"

    cbc_svlt = work_dir / "sample_cbc.svlt"
    cbc_key = work_dir / "sample_cbc.svkey"
    cbc_rec = work_dir / "sample_cbc_recovered.txt"

    # Step 2: GCM Encryption
    print(f"\n[2/10] Encrypting with AES-256-GCM...")
    res = run_cmd([
        python_bin, "-m", "securevault", "encrypt",
        "--mode", "gcm",
        "--input", str(SAMPLE_FILE),
        "--output", str(gcm_svlt),
        "--key-output", str(gcm_key),
    ])
    if res.returncode != 0:
        print(f"FAILED:\n{res.stderr}")
        return 1
    print(res.stdout.strip())

    # Step 3: GCM Decryption
    print(f"\n[3/10] Decrypting AES-256-GCM container...")
    res = run_cmd([
        python_bin, "-m", "securevault", "decrypt",
        "--input", str(gcm_svlt),
        "--output", str(gcm_rec),
        "--key-file", str(gcm_key),
        "--require-mode", "gcm",
    ])
    if res.returncode != 0:
        print(f"FAILED:\n{res.stderr}")
        return 1
    print(res.stdout.strip())

    # Step 4: GCM Exact-byte verification
    rec_hash_gcm = sha256_of(gcm_rec)
    print(f"\n[4/10] GCM Exact-byte Verification:")
    print(f"       Original SHA-256:  {orig_hash}")
    print(f"       Recovered SHA-256: {rec_hash_gcm}")
    if orig_hash != rec_hash_gcm:
        print("       ERROR: Hashes do not match!")
        return 1
    print("       RESULT: MATCH - Exact byte-for-byte recovery confirmed.")

    # Step 5: CBC Encryption
    print(f"\n[5/10] Encrypting with AES-256-CBC...")
    res = run_cmd([
        python_bin, "-m", "securevault", "encrypt",
        "--mode", "cbc",
        "--input", str(SAMPLE_FILE),
        "--output", str(cbc_svlt),
        "--key-output", str(cbc_key),
    ])
    if res.returncode != 0:
        print(f"FAILED:\n{res.stderr}")
        return 1
    print(res.stdout.strip())

    # Step 6: CBC Decryption
    print(f"\n[6/10] Decrypting AES-256-CBC container...")
    res = run_cmd([
        python_bin, "-m", "securevault", "decrypt",
        "--input", str(cbc_svlt),
        "--output", str(cbc_rec),
        "--key-file", str(cbc_key),
        "--require-mode", "cbc",
    ])
    if res.returncode != 0:
        print(f"FAILED:\n{res.stderr}")
        return 1
    print(res.stdout.strip())

    # Step 7: CBC Exact-byte verification
    rec_hash_cbc = sha256_of(cbc_rec)
    print(f"\n[7/10] CBC Exact-byte Verification:")
    print(f"       Original SHA-256:  {orig_hash}")
    print(f"       Recovered SHA-256: {rec_hash_cbc}")
    if orig_hash != rec_hash_cbc:
        print("       ERROR: Hashes do not match!")
        return 1
    print("       RESULT: MATCH - Exact byte-for-byte recovery confirmed.")

    # Step 8: Wrong-key failure
    print(f"\n[8/10] Demonstrating wrong-key failure handling...")
    res = run_cmd([
        python_bin, "-m", "securevault", "decrypt",
        "--input", str(gcm_svlt),
        "--output", str(work_dir / "wrong_key_out.txt"),
        "--key-file", str(cbc_key),  # Mismatched key
    ])
    print(f"       Exit code: {res.returncode} (expected: 2)")
    print(f"       Captured error: {res.stderr.strip()}")
    if res.returncode != 2 or "InvalidKeyError" not in res.stderr or (work_dir / "wrong_key_out.txt").exists():
        return 1
    print("       RESULT: PASSED - Wrong key rejected safely, no plaintext released.")

    # Step 9: Tampered GCM container failure
    print(f"\n[9/10] Demonstrating tampered GCM container rejection...")
    tampered_gcm = work_dir / "tampered.svlt"
    raw = bytearray(gcm_svlt.read_bytes())
    raw[-1] ^= 0xFF  # Tamper tag byte
    tampered_gcm.write_bytes(raw)

    res = run_cmd([
        python_bin, "-m", "securevault", "decrypt",
        "--input", str(tampered_gcm),
        "--output", str(work_dir / "tampered_out.txt"),
        "--key-file", str(gcm_key),
    ])
    print(f"       Exit code: {res.returncode} (expected: 2)")
    print(f"       Captured error: {res.stderr.strip()}")
    if res.returncode != 2 or "AuthenticationError" not in res.stderr or (work_dir / "tampered_out.txt").exists():
        return 1
    print("       RESULT: PASSED - Tampered container rejected via AuthenticationError.")

    # Step 10: Existing-output preservation (no-clobber)
    print(f"\n[10/10] Demonstrating existing-output preservation (no-clobber default)...")
    res = run_cmd([
        python_bin, "-m", "securevault", "encrypt",
        "--mode", "gcm",
        "--input", str(SAMPLE_FILE),
        "--output", str(gcm_svlt),  # Already exists!
        "--key-output", str(work_dir / "new.svkey"),
    ])
    print(f"       Exit code: {res.returncode} (expected: 2)")
    print(f"       Captured error: {res.stderr.strip()}")
    if res.returncode != 2 or "FileExistsSecurityError" not in res.stderr:
        return 1
    print("       RESULT: PASSED - FileExistsSecurityError raised; existing container preserved.")

    print("\n" + "=" * 70)
    print("ALL 10 DEMONSTRATION STEPS COMPLETED AND VERIFIED SUCCESSFULLY.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
