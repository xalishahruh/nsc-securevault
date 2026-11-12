"""End-to-end functional tests covering arbitrary file types and CLI operations."""

import os
from pathlib import Path
import pytest
from securevault.file_service import encrypt_file, decrypt_file, inspect_file
from securevault.cli import main


@pytest.mark.parametrize("mode", ["gcm", "cbc"])
@pytest.mark.parametrize("file_size", [0, 1, 15, 16, 17, 31, 32, 63, 64, 1024, 65536])
def test_func_01_02_boundary_sizes_e2e(tmp_path: Path, mode: str, file_size: int):
    """FUNC-01 & FUNC-02: Round-trip byte-for-byte exactness across edge case sizes."""
    original_data = os.urandom(file_size) if file_size > 0 else b""
    src = tmp_path / f"in_{mode}_{file_size}.bin"
    src.write_bytes(original_data)

    svlt = tmp_path / f"out_{mode}_{file_size}.svlt"
    key = tmp_path / f"out_{mode}_{file_size}.svkey"
    rec = tmp_path / f"rec_{mode}_{file_size}.bin"

    encrypt_file(src, svlt, key, mode=mode)
    decrypt_file(svlt, rec, key, require_mode=mode)

    assert rec.read_bytes() == original_data


def test_func_03_file_format_compatibility(tmp_path: Path):
    """FUNC-03: Arbitrary binary file format compatibility (synthetic text, PDF header, JPEG magic, MP4 header)."""
    fixtures = {
        "sample.txt": b"Plain text file content\nLine 2\nLine 3",
        "sample.pdf": b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF",
        "sample.jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xdb\x00C\x00\xff\xd9",
        "sample.mp4": b"\x00\x00\x00 ftypisom\x00\x00\x02\x00isomiso2mp41\x00\x00\x00\x08free",
    }

    for name, data in fixtures.items():
        src = tmp_path / name
        src.write_bytes(data)

        for mode in ("gcm", "cbc"):
            svlt = tmp_path / f"{name}.{mode}.svlt"
            key = tmp_path / f"{name}.{mode}.svkey"
            recovered = tmp_path / f"{name}.{mode}.restored"

            encrypt_file(src, svlt, key, mode=mode)
            decrypt_file(svlt, recovered, key)

            assert recovered.read_bytes() == data


def test_cli_roundtrip_and_inspect(tmp_path: Path):
    """Verify CLI encrypt, decrypt, and inspect subcommands via main()."""
    src = tmp_path / "doc.txt"
    src.write_bytes(b"Top secret coursework document!")
    svlt = tmp_path / "doc.svlt"
    key = tmp_path / "doc.svkey"
    restored = tmp_path / "doc.restored"

    # 1. Encrypt via CLI
    ret = main(["encrypt", "--mode", "gcm", "-i", str(src), "-o", str(svlt), "-k", str(key)])
    assert ret == 0
    assert svlt.exists()
    assert key.exists()

    # 2. Inspect via CLI
    ret = main(["inspect", "-i", str(svlt)])
    assert ret == 0

    # 3. Decrypt via CLI
    ret = main(["decrypt", "-i", str(svlt), "-o", str(restored), "-k", str(key), "--require-mode", "gcm"])
    assert ret == 0
    assert restored.read_bytes() == src.read_bytes()

