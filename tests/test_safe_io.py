"""Tests for safe file staging, atomic commit, and no-overwrite guarantees."""

import errno
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest
from securevault.container import KEY_PROT_KWP, parse_container, serialize_container
from securevault.file_service import (
    encrypt_file,
    decrypt_file,
    _safe_write_bytes,
    _read_bounded,
)
from securevault.errors import (
    FileExistsSecurityError,
    FileServiceError,
    SameFileError,
    AuthenticationError,
    PathSecurityError,
    ModeMismatchError,
)


@pytest.mark.parametrize("alias", [False, True])
def test_decrypt_overwrite_preserves_key(tmp_path, alias):
    source = tmp_path / "source"
    container = tmp_path / "encrypted"
    key = tmp_path / "key"
    source.write_bytes(b"keep the key recoverable")
    encrypt_file(source, container, key)
    original = key.read_bytes()
    destination = key
    if alias:
        destination = tmp_path / "alias"
        os.link(key, destination)
    with pytest.raises(SameFileError):
        decrypt_file(container, destination, key, overwrite=True)
    assert key.read_bytes() == destination.read_bytes() == original


def test_bounded_reader_rejects_oversize_and_non_regular_inputs(tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"abc")
    assert _read_bounded(source, 3) == b"abc"
    with pytest.raises(FileServiceError, match="limit"):
        _read_bounded(source, 2)
    with pytest.raises(PathSecurityError):
        _read_bounded(tmp_path, 3)


def test_standalone_decrypt_requires_external_key_protection(tmp_path):
    source, container, key, output = (tmp_path / name for name in ("source", "container", "key", "output"))
    source.write_bytes(b"same authenticated payload")
    encrypt_file(source, container, key)
    parsed = parse_container(container.read_bytes())
    container.write_bytes(serialize_container(
        header=parsed.header,
        ciphertext=parsed.ciphertext,
        key_protection_id=KEY_PROT_KWP,
        key_record=b"\x00" * 64,
        gcm_tag=parsed.gcm_tag,
    ))
    with pytest.raises(ModeMismatchError, match="external-key"):
        decrypt_file(container, output, key)
    assert not output.exists()


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


def test_safe_write_unsupported_hardlinks_fails_closed(tmp_path: Path, monkeypatch):
    """C01 Regression: When hard links are unsupported, fail closed with FileServiceError."""
    def fake_link(src, dst):
        raise OSError(errno.ENOTSUP, "Operation not supported on filesystem")

    monkeypatch.setattr(os, "link", fake_link)

    target = tmp_path / "unsupported_link.bin"
    with pytest.raises(FileServiceError, match="Atomic exclusive publication unsupported or failed"):
        _safe_write_bytes(target, b"payload", overwrite=False)

    # Destination MUST NOT be created (no fallback to clobbering replace)
    assert not target.exists()
    # Temporary staging file MUST be cleaned up
    assert len(list(tmp_path.glob(".svlt_tmp_*"))) == 0


def test_safe_write_existing_destination_rejected_at_link(tmp_path: Path, monkeypatch):
    """C01 Regression: Race condition where destination appears before link must raise FileExistsSecurityError."""
    # Simulate race condition: target was not there at initial check, but exists at link()
    target = tmp_path / "race_target.bin"

    # Make initial target.exists() return False once, then True
    orig_exists = Path.exists
    call_count = 0

    def mock_exists(self):
        nonlocal call_count
        if self == target:
            call_count += 1
            if call_count == 1:
                return False  # Pass the preliminary exists check
        return orig_exists(self)

    # Create target so os.link will fail with FileExistsError
    target.write_bytes(b"prior content")
    monkeypatch.setattr(Path, "exists", mock_exists)

    with pytest.raises(FileExistsSecurityError):
        _safe_write_bytes(target, b"new content", overwrite=False)

    assert target.read_bytes() == b"prior content"
    assert len(list(tmp_path.glob(".svlt_tmp_*"))) == 0


def test_safe_write_concurrent_writers_exclusive(tmp_path: Path):
    """C01 Regression: Multiple concurrent writers contending for the same non-overwrite destination."""
    target = tmp_path / "concurrent.bin"
    num_threads = 10
    barrier = threading.Barrier(num_threads)
    results = {"success": 0, "rejected": 0}
    lock = threading.Lock()

    def worker(worker_id: int):
        data = f"worker_{worker_id}_data".encode("ascii")
        barrier.wait()
        try:
            _safe_write_bytes(target, data, overwrite=False)
            with lock:
                results["success"] += 1
        except FileExistsSecurityError:
            with lock:
                results["rejected"] += 1

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, i) for i in range(num_threads)]
        for f in futures:
            f.result()

    # Exactly one thread succeeds, all others are rejected safely
    assert results["success"] == 1
    assert results["rejected"] == num_threads - 1
    assert target.exists()
    assert len(list(tmp_path.glob(".svlt_tmp_*"))) == 0


def test_safe_write_publication_failure_cleans_up_staging(tmp_path: Path, monkeypatch):
    """C01 Regression: Unexpected I/O error during link fails closed and cleans up staging file."""
    def fake_link(src, dst):
        raise OSError(errno.EIO, "Simulated disk I/O error")

    monkeypatch.setattr(os, "link", fake_link)

    target = tmp_path / "io_fail.bin"
    with pytest.raises(FileServiceError, match="Atomic exclusive publication unsupported or failed"):
        _safe_write_bytes(target, b"data", overwrite=False)

    assert not target.exists()
    assert len(list(tmp_path.glob(".svlt_tmp_*"))) == 0


def test_safe_write_post_publication_cleanup_failure_preserves_target(tmp_path: Path, monkeypatch):
    """C01 Regression: Failure to remove staging link after publication emits an observable warning and preserves target."""
    orig_unlink = Path.unlink

    def mock_unlink(self, *args, **kwargs):
        if ".svlt_tmp_" in str(self):
            raise OSError(errno.EACCES, "Simulated permission error on unlink")
        return orig_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", mock_unlink)

    target = tmp_path / "published.bin"

    # Verifies that cleanup failure emits an observable warning without raising an exception to the caller
    with pytest.warns(UserWarning, match=r"Failed to remove temporary staging file \.svlt_tmp_"):
        _safe_write_bytes(target, b"vital data", overwrite=False)

    # Target file MUST exist with exact payload, never rolled back or unlinked
    assert target.exists()
    assert target.read_bytes() == b"vital data"

