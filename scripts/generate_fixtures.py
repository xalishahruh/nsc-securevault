"""Deterministic synthetic fixture generator for SecureVault testing and benchmarking."""

import argparse
import hashlib
from pathlib import Path


def generate_deterministic_bytes(size: int, seed: bytes = b"securevault-seed-2026") -> bytes:
    """Generate deterministically pseudorandom bytes of exact length using SHA-256 stream."""
    if size == 0:
        return b""
    chunks = []
    generated = 0
    counter = 0
    while generated < size:
        h = hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
        needed = min(len(h), size - generated)
        chunks.append(h[:needed])
        generated += needed
        counter += 1
    return b"".join(chunks)


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic fixtures for SecureVault")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("fixtures"),
        help="Target directory to write synthetic fixtures",
    )
    args = parser.parse_args()

    out_dir: Path = args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    # Benchmark sizes: 1 KiB, 1 MiB, 10 MiB
    bench_sizes = {
        "file_1k.bin": 1024,
        "file_1m.bin": 1024 * 1024,
        "file_10m.bin": 10 * 1024 * 1024,
    }

    print(f"Generating synthetic benchmark fixtures in {out_dir.resolve()}...")
    for filename, size in bench_sizes.items():
        file_path = out_dir / filename
        data = generate_deterministic_bytes(size, seed=filename.encode("utf-8"))
        file_path.write_bytes(data)
        print(f"  [+] Created {filename} ({len(data):,} bytes)")

    # Synthetic format fixtures
    formats = {
        "sample.txt": b"SecureVault Synthetic Text Document\nCoursework 6COSC033C\nDeterministic payload.\n",
        "sample.pdf": b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n",
        "sample.jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00C\x00\xff\xd9",
    }
    for filename, content in formats.items():
        (out_dir / filename).write_bytes(content)
        print(f"  [+] Created {filename} ({len(content):,} bytes)")

    print("[OK] Fixture generation complete.")


if __name__ == "__main__":
    main()

