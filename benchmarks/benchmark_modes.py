'''Benchmark runner for SecureVault AES implementations.

This module provides a reproducible benchmark comparing AES‑256‑GCM and
AES‑256‑CBC encryption and decryption performance across three fixture
sizes (1 KiB, 1 MiB, 10 MiB).  The runner is deliberately lightweight – it
uses only the project's public crypto helpers and records timing
information in a CSV file without persisting any secret material.

The benchmark can be executed directly:

    python -m benchmarks.benchmark_modes

A small API (``run_benchmark``) is also exposed for the test suite so the
observation count can be constrained.
'''  # noqa: D400,D401

from __future__ import annotations

import csv
import os
import platform
import ssl
import sys
import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Tuple

from securevault.crypto.gcm import (
    GCM_KEY_SIZE,
    GCM_NONCE_SIZE,
    encrypt_gcm,
    decrypt_gcm,
    generate_gcm_dek,
    generate_gcm_nonce,
)
from securevault.crypto.cbc import (
    CBC_BLOCK_SIZE,
    CBC_IV_SIZE,
    encrypt_cbc,
    decrypt_cbc,
    generate_cbc_dek,
    generate_cbc_iv,
)

# ---------------------------------------------------------------------------
# Helper data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BenchmarkResult:
    mode: str               # 'gcm' or 'cbc'
    operation: str          # 'encrypt' or 'decrypt'
    size_bytes: int
    repeat: int
    elapsed_ns: int
    python_version: str
    os: str
    cpu_count: int | None
    cryptography_version: str
    openssl_version: str

    def as_tuple(self) -> Tuple:
        return (
            self.mode,
            self.operation,
            self.size_bytes,
            self.repeat,
            self.elapsed_ns,
            self.python_version,
            self.os,
            self.cpu_count,
            self.cryptography_version,
            self.openssl_version,
        )

# ---------------------------------------------------------------------------
# Deterministic fixture generation
# ---------------------------------------------------------------------------

def _deterministic_fixture(size: int) -> bytes:
    """Return a deterministic ``bytes`` object of *size*.

    The function uses a simple deterministic PRNG based on SHA‑256 to avoid
    any reliance on the system's random source.  The same seed (``b'benchmark'``)
    is used for every call, so the output is reproducible across runs and
    platforms.
    """
    import hashlib

    out = bytearray()
    seed = b"benchmark"
    while len(out) < size:
        seed = hashlib.sha256(seed).digest()
        out.extend(seed)
    return bytes(out[:size])

# ---------------------------------------------------------------------------
# Core benchmark logic
# ---------------------------------------------------------------------------

def _run_one(
    mode: str,
    plaintext: bytes,
    encrypt_func: Callable[[bytes, bytes, bytes], Tuple[bytes, bytes] | bytes],
    decrypt_func: Callable[[bytes, bytes, bytes, bytes | None], bytes],
    key: bytes,
    nonce_or_iv: bytes,
) -> Tuple[int, int, bytes, bytes | None]:
    """Perform a single encrypt/decrypt cycle and return timings.

    Returns ``(enc_ns, dec_ns, ciphertext, tag)`` where *tag* is ``None``
    for CBC.
    """
    # ---- encryption timing ------------------------------------------------
    start_enc = time.perf_counter_ns()
    if mode == "gcm":
        ciphertext, tag = encrypt_func(key, nonce_or_iv, plaintext)
    else:  # cbc
        ciphertext = encrypt_func(key, nonce_or_iv, plaintext)  # type: ignore[arg-type]
        tag = None
    end_enc = time.perf_counter_ns()
    enc_ns = end_enc - start_enc

    # ---- decryption timing ------------------------------------------------
    start_dec = time.perf_counter_ns()
    if mode == "gcm":
        # type: ignore[arg-type]
        decrypted = decrypt_func(key, nonce_or_iv, ciphertext, tag)  # type: ignore[arg-type]
    else:
        decrypted = decrypt_func(key, nonce_or_iv, ciphertext)  # type: ignore[arg-type]
    end_dec = time.perf_counter_ns()
    dec_ns = end_dec - start_dec

    # Verify correctness (outside timing)
    if decrypted != plaintext:
        raise AssertionError("Decryption output does not match original plaintext")

    return enc_ns, dec_ns, ciphertext, tag


def run_benchmark(
    repeats: int = 30,
    output_path: str | None = None,
) -> List[BenchmarkResult]:
    """Execute the benchmark.

    Parameters
    ----------
    repeats:
        Number of repetitions per (mode, size, operation) configuration.
    output_path:
        Destination CSV file.  If ``None`` a default
        ``benchmarks/results/benchmark_results.csv`` is used.

    Returns
    -------
    List[BenchmarkResult]
        Collected observations; also written to the CSV.
    """
    sizes = [1024, 1024 * 1024, 10 * 1024 * 1024]
    modes = ["gcm", "cbc"]

    # Resolve output location and ensure directory exists.
    if output_path is None:
        output_path = os.path.join("benchmarks", "results", "benchmark_results.csv")
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    results: List[BenchmarkResult] = []

    # Gather static environment metadata once.
    env_meta = dict(
        python_version=sys.version.replace("\n", " ").strip(),
        os=platform.platform(),
        cpu_count=os.cpu_count(),
        cryptography_version=__import__("cryptography").__version__,
        openssl_version=ssl.OPENSSL_VERSION,
    )

    for mode in modes:
        for size in sizes:
            plaintext = _deterministic_fixture(size)
            # Generate fresh key and nonce/IV for each repetition – the cost of
            # generation is deliberately excluded from timing by performing it
            # before the loop.
            for i in range(repeats):
                if mode == "gcm":
                    key = generate_gcm_dek()
                    nonce = generate_gcm_nonce()
                    encrypt_fn = lambda k, n, p: encrypt_gcm(k, n, p)
                    # decrypt_gcm expects (dek, nonce, ciphertext, tag)
                    decrypt_fn = decrypt_gcm
                else:  # cbc
                    key = generate_cbc_dek()
                    nonce = generate_cbc_iv()
                    encrypt_fn = lambda k, iv, p: encrypt_cbc(k, iv, p)
                    decrypt_fn = decrypt_cbc

                enc_ns, dec_ns, _, _ = _run_one(
                    mode,
                    plaintext,
                    encrypt_fn,
                    decrypt_fn,
                    key,
                    nonce,
                )

                results.append(
                    BenchmarkResult(
                        mode=mode,
                        operation="encrypt",
                        size_bytes=size,
                        repeat=i,
                        elapsed_ns=enc_ns,
                        **env_meta,  # type: ignore[arg-type]
                    )
                )
                results.append(
                    BenchmarkResult(
                        mode=mode,
                        operation="decrypt",
                        size_bytes=size,
                        repeat=i,
                        elapsed_ns=dec_ns,
                        **env_meta,  # type: ignore[arg-type]
                    )
                )

    # Write CSV – include a header row.
    header = [
        "mode",
        "operation",
        "size_bytes",
        "repeat",
        "elapsed_ns",
        "python_version",
        "os",
        "cpu_count",
        "cryptography_version",
        "openssl_version",
    ]
    with out_file.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        for r in results:
            writer.writerow(r.as_tuple())

    return results


def main() -> None:
    """Entry‑point for manual execution.

    The function simply runs ``run_benchmark`` with the default configuration
    and prints a short summary.
    """
    start = time.perf_counter()
    results = run_benchmark()
    duration = time.perf_counter() - start
    print(f"Benchmark completed: {len(results)} observations in {duration:.2f}s")
    print(f"CSV written to {os.path.abspath('benchmarks/results/benchmark_results.csv')}")


if __name__ == "__main__":
    # Suppress noisy library warnings that are unrelated to the benchmark.
    warnings.filterwarnings("ignore", category=UserWarning)
    main()
