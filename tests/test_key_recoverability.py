"""Regression tests for key recoverability, path validation, and safe failure handling (C02)."""

from pathlib import Path
import pytest
from securevault.file_service import encrypt_file, decrypt_file, _safe_write_bytes
from securevault.key_provider import ExternalKeyRecord
from securevault.errors import (
    FileExistsSecurityError,
    FileServiceError,
    SameFileError,
)


def test_encrypt_rejects_none_key_destination(tmp_path: Path):
    """C02: Calling encrypt_file with key_output_path=None must fail before encryption."""
    src = tmp_path / "data.bin"
    src.write_bytes(b"recoverability test")
    dst = tmp_path / "data.svlt"

    with pytest.raises(ValueError, match="valid key_output_path must be provided"):
        encrypt_file(src, dst, key_output_path=None)

    assert not dst.exists()


def test_encrypt_rejects_overwrite_flag(tmp_path: Path):
    """C02: Calling encrypt_file with overwrite=True is rejected to prevent uncoordinated loss."""
    src = tmp_path / "data.bin"
    src.write_bytes(b"content")
    dst = tmp_path / "data.svlt"
    key = tmp_path / "data.svkey"

    with pytest.raises(FileServiceError, match="Overwriting existing container or key files is not supported"):
        encrypt_file(src, dst, key, overwrite=True)

    assert not dst.exists()
    assert not key.exists()


def test_encrypt_rejects_identical_container_and_key_path(tmp_path: Path):
    """C02: Path conflict where container and key target the same path."""
    src = tmp_path / "data.bin"
    src.write_bytes(b"conflict test")
    target = tmp_path / "conflict.bin"

    with pytest.raises(SameFileError, match="cannot be the same file"):
        encrypt_file(src, target, key_output_path=target)

    assert not target.exists()


def test_encrypt_rejects_existing_key_destination(tmp_path: Path):
    """C02: If key destination already exists, refuse before creating container."""
    src = tmp_path / "data.bin"
    src.write_bytes(b"content")
    dst = tmp_path / "data.svlt"
    key = tmp_path / "data.svkey"
    key.write_bytes(b"pre-existing key content")

    with pytest.raises(FileExistsSecurityError):
        encrypt_file(src, dst, key, overwrite=False)

    assert not dst.exists()
    assert key.read_bytes() == b"pre-existing key content"


def test_encrypt_rejects_existing_container_destination(tmp_path: Path):
    """C02: If container destination already exists, refuse before creating key."""
    src = tmp_path / "data.bin"
    src.write_bytes(b"content")
    dst = tmp_path / "data.svlt"
    dst.write_bytes(b"pre-existing container")
    key = tmp_path / "data.svkey"

    with pytest.raises(FileExistsSecurityError):
        encrypt_file(src, dst, key, overwrite=False)

    assert not key.exists()
    assert dst.read_bytes() == b"pre-existing container"


def test_encrypt_container_publication_failure_preserves_published_key_and_warns(tmp_path: Path, monkeypatch):
    """C02: When container publication fails, the published key is preserved and a warning is emitted."""
    src = tmp_path / "data.bin"
    src.write_bytes(b"rollback test payload")
    dst = tmp_path / "data.svlt"
    key = tmp_path / "data.svkey"

    orig_safe_write = _safe_write_bytes

    def mock_safe_write(target, data, overwrite=False, file_mode=0o600):
        if target == dst:
            raise FileServiceError("Injected failure writing container")
        return orig_safe_write(target, data, overwrite, file_mode)

    monkeypatch.setattr("securevault.file_service._safe_write_bytes", mock_safe_write)

    # Must raise original exception and emit observable UserWarning
    with pytest.warns(UserWarning, match=r"Container publication failed; preserved published key at"):
        with pytest.raises(FileServiceError, match="Injected failure writing container"):
            encrypt_file(src, dst, key, overwrite=False)

    # Container does NOT exist
    assert not dst.exists()
    # Key file MUST BE PRESERVED on disk (no automatic deletion)
    assert key.exists()
    # Key file is valid and contains recoverable DEK
    record = ExternalKeyRecord.parse(key.read_bytes())
    assert len(record.dek) == 32


@pytest.mark.parametrize("mode", ["gcm", "cbc"])
def test_encrypt_key_recoverability_gcm_and_cbc(tmp_path: Path, mode: str):
    """C02: Verify full encrypt-key-decrypt roundtrip recovery for both AES-GCM and AES-CBC."""
    src = tmp_path / f"roundtrip_{mode}.bin"
    payload = f"testing {mode} key preservation and recovery".encode("ascii")
    src.write_bytes(payload)

    dst = tmp_path / f"roundtrip_{mode}.svlt"
    key = tmp_path / f"roundtrip_{mode}.svkey"
    rec = tmp_path / f"roundtrip_{mode}.recovered"

    result = encrypt_file(src, dst, key, mode=mode)
    assert key.exists()
    assert result["key_path"] == str(key)

    record = ExternalKeyRecord.parse(key.read_bytes())
    assert len(record.dek) == 32
    assert record.cipher_id == (1 if mode == "gcm" else 2)

    decrypt_file(dst, rec, key_file_path=key, require_mode=mode)
    assert rec.read_bytes() == payload

