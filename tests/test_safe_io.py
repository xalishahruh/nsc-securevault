"""Tests for safe file staging, atomic commit, and no-overwrite guarantees."""

import os
from pathlib import Path
import pytest
from securevault.file_service import (
    encrypt_file,
    decrypt_file,
    _safe_write_bytes,
)
from securevault.errors import (
    FileExistsSecurityError,
    SameFileError,
    AuthenticationError,
)


def test_io_01_no_overwrite_by_default(tmp_path: Path):
    """IO-01: Existing target file is never overwritten unless overwrite=True."""
    target = tmp_path / "protected.bin"
    target.write_bytes(b"original data")

    with pytest.raises(FileExistsSecurityError):
        _safe_write_bytes(target, b"new data", overwrite=False)

    assert target.read_bytes() == b"original data"


def test_io_01_same_file_alias_rejected(tmp_path: Path):
    """IO-01: Encrypting or decrypting where src == dst must be rejected."""
    sample = tmp_path / "file.txt"
    sample.write_bytes(b"hello world")
    key_file = tmp_path / "file.svkey"

    with pytest.raises(SameFileError):
        encrypt_file(sample, sample, key_output_path=key_file, mode="gcm")


def test_io_02_staging_cleanup_on_failure(tmp_path: Path):
    """IO-02: If GCM decryption fails, staged output is cleaned up and target is never created."""
    plain_src = tmp_path / "secret.txt"
    plain_src.write_bytes(b"confidential information")
    svlt_file = tmp_path / "secret.svlt"
    key_file = tmp_path / "secret.svkey"

    encrypt_file(plain_src, svlt_file, key_output_path=key_file, mode="gcm")

    # Corrupt the container file so authentication will fail
    corrupted_data = bytearray(svlt_file.read_bytes())
    corrupted_data[-1] ^= 0x55  # flip tag byte
    svlt_file.write_bytes(bytes(corrupted_data))

    recovered_dst = tmp_path / "recovered.txt"

    with pytest.raises(AuthenticationError):
        decrypt_file(svlt_file, recovered_dst, key_file_path=key_file)

    # Destination MUST NOT exist
    assert not recovered_dst.exists()

    # No leftover temporary staging files in destination directory
    staging_files = list(tmp_path.glob(".svlt_tmp_*"))
    assert len(staging_files) == 0


def test_io_01_permissions_owner_only(tmp_path: Path):
    """Verify owner-restricted permissions (0600) on POSIX platforms."""
    target = tmp_path / "private.bin"
    _safe_write_bytes(target, b"confidential", file_mode=0o600)

    if os.name == "posix":
        stat_mode = target.stat().st_mode & 0o777
        assert stat_mode == 0o600

