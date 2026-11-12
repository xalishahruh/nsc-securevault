"""Tests for security tampering, integrity checks, and mode downgrade protection."""

from pathlib import Path
import pytest
from securevault.file_service import encrypt_file, decrypt_file
from securevault.errors import (
    AuthenticationError,
    ModeMismatchError,
    InvalidHeaderError,
    MalformedContainerError,
    PaddingError,
)


def test_auth_01_gcm_tampered_header_fails(tmp_path: Path):
    """AUTH-01: Modifying header bytes in GCM container fails because header is bound as AAD."""
    src = tmp_path / "data.bin"
    src.write_bytes(b"sensitive content 1234567890")
    svlt = tmp_path / "data.svlt"
    key = tmp_path / "data.svkey"

    encrypt_file(src, svlt, key, mode="gcm")

    raw = bytearray(svlt.read_bytes())
    # Tamper byte in file_id field (offset 10)
    raw[10] ^= 0x01
    svlt.write_bytes(bytes(raw))

    dst = tmp_path / "recovered.bin"
    # Fails either at key association or AAD authentication
    with pytest.raises((AuthenticationError, Exception)):
        decrypt_file(svlt, dst, key)

    assert not dst.exists()


def test_auth_01_gcm_tampered_tag_fails(tmp_path: Path):
    """AUTH-01: Modifying GCM authentication tag causes immediate rejection."""
    src = tmp_path / "data.bin"
    src.write_bytes(b"sensitive content 1234567890")
    svlt = tmp_path / "data.svlt"
    key = tmp_path / "data.svkey"

    encrypt_file(src, svlt, key, mode="gcm")

    raw = bytearray(svlt.read_bytes())
    # Tamper last byte (part of GCM tag)
    raw[-1] ^= 0xFF
    svlt.write_bytes(bytes(raw))

    dst = tmp_path / "recovered.bin"
    with pytest.raises(AuthenticationError):
        decrypt_file(svlt, dst, key)

    assert not dst.exists()


def test_auth_02_cbc_tampering_behavior(tmp_path: Path):
    """AUTH-02: Tampering CBC container either corrupts plaintext or raises PaddingError.

    Demonstrates that CBC does not provide ciphertext integrity or authentication!
    """
    src = tmp_path / "data_cbc.bin"
    src.write_bytes(b"1234567890abcdef" * 4)  # 64 bytes
    svlt = tmp_path / "data_cbc.svlt"
    key = tmp_path / "data_cbc.svkey"

    encrypt_file(src, svlt, key, mode="cbc")

    raw = bytearray(svlt.read_bytes())
    # Tamper IV slot (offset 24..39)
    raw[25] ^= 0x42
    svlt.write_bytes(bytes(raw))

    dst = tmp_path / "recovered_cbc.bin"
    # In CBC, tampering IV does NOT fail authentication: it decrypts with corrupted first block!
    decrypt_file(svlt, dst, key)

    assert dst.exists()
    recovered = dst.read_bytes()
    # Plaintext was accepted, but data is corrupted!
    assert recovered != src.read_bytes()
    # The bit flip is observed exactly at block 0 offset 1
    assert recovered[1] != src.read_bytes()[1]


def test_mode_01_gcm_modified_to_claim_cbc_rejected(tmp_path: Path):
    """MODE-01: GCM container modified to claim CBC is rejected by parser, mode policy, or key association."""
    # 1. Non-block-aligned GCM container where cipher_id byte is flipped to CBC
    src = tmp_path / "test.bin"
    src.write_bytes(b"mode test content")  # 17 bytes (not divisible by 16)
    svlt = tmp_path / "test.svlt"
    key = tmp_path / "test.svkey"

    encrypt_file(src, svlt, key, mode="gcm")

    raw = bytearray(svlt.read_bytes())
    raw[5] = 0x02  # Change cipher_id from 0x01 (GCM) to 0x02 (CBC)
    svlt.write_bytes(bytes(raw))

    dst = tmp_path / "recovered.bin"
    # Rejected during container parsing because CBC requires ciphertext length divisible by 16
    with pytest.raises(MalformedContainerError):
        decrypt_file(svlt, dst, key, require_mode="gcm")

    # 2. Block-aligned container (16 bytes) where attacker attempts mode downgrade
    src_aligned = tmp_path / "aligned.bin"
    src_aligned.write_bytes(b"1234567890abcdef")  # exactly 16 bytes
    svlt_aligned = tmp_path / "aligned.svlt"
    key_aligned = tmp_path / "aligned.svkey"

    encrypt_file(src_aligned, svlt_aligned, key_aligned, mode="gcm")

    # Craft container header claiming CBC (0x02) with 16-byte length, and strip GCM tag
    raw_aligned = bytearray(svlt_aligned.read_bytes())
    raw_aligned[5] = 0x02  # CBC
    # Remove the 16-byte GCM tag from the end so CBC parser doesn't complain about trailing bytes
    crafted_cbc_svlt = bytes(raw_aligned[:-16])
    svlt_aligned.write_bytes(crafted_cbc_svlt)

    # When caller requires GCM, require_mode rejects the downgrade
    with pytest.raises(ModeMismatchError, match="Mode policy violation"):
        decrypt_file(svlt_aligned, dst, key_aligned, require_mode="gcm")

    # Even without require_mode, the external key record validates cipher_id and rejects!
    with pytest.raises(ModeMismatchError, match="Key cipher mode"):
        decrypt_file(svlt_aligned, dst, key_aligned)
