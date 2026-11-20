"""Benchmark runner for SecureVault AES implementations.

This module provides a reproducible benchmark comparing AES-256-GCM and
AES-256-CBC encryption and decryption performance across three fixture
sizes (1 KiB, 1 MiB, 10 MiB).

The metric is in-memory cryptographic API execution time: the public API call
and its internal allocations are included; fixture/key generation, decryption
input preparation, validation, and CSV I/O are excluded. Warm-ups and an
untimed round-trip precede measurements. Encryption and decryption order
alternates by repeat. Scheduler, cache, frequency, thermal, and platform
effects remain limitations; this is not hardware-instruction or file-I/O time.

Measurement Boundaries and Timing Definitions:
----------------------------------------------
The benchmark strictly isolates the raw cryptographic operation within the
timed interval using `time.perf_counter_ns()`:

- Encryption Measurement Boundary:
  INCLUDED: Only the raw invocation of `encrypt_gcm(dek, nonce, plaintext)` or
            `encrypt_cbc(dek, iv, plaintext)`.
  EXCLUDED: Fixture generation, DEK and nonce/IV generation, allocation of
            buffers, verification, and CSV I/O.

- Decryption Measurement Boundary:
  INCLUDED: Only the raw invocation of `decrypt_gcm(dek, nonce, ciphertext, tag)`
            or `decrypt_cbc(dek, iv, ciphertext)`.
  EXCLUDED: Fixture generation, preparation of valid ciphertext and tags,
            DEK and nonce/IV generation, post-decryption plaintext equality
            validation, and CSV I/O. All decryption inputs (valid ciphertext,
            tag, key, and IV/nonce) are fully prepared in advance prior to
            starting the timed decryption interval.

Order and Bias Controls:
------------------------
- Warm-up iterations: Untimed warm-up cycles are run before measuring each
  configuration to eliminate cold-start cache and interpreter artifacts.
- Order Alternation: Within each configuration, the order of encryption and
  decryption measurement is balanced and alternated (even repetitions measure
  encryption then decryption; odd repetitions measure decryption then encryption)
  to mitigate systematic order bias.
- Correctness Validation: An untimed round-trip validation is performed before
  any measurements are collected for each configuration.
"""

from __future__ import annotations

import csv
import hashlib
import os
import platform
import tempfile
import ssl
import sys
import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from securevault.crypto.cbc import (
    encrypt_cbc,
    decrypt_cbc,
    generate_cbc_dek,
    generate_cbc_iv,
)
from securevault.crypto.gcm import (
    encrypt_gcm,
    decrypt_gcm,
    generate_gcm_dek,
    generate_gcm_nonce,
)

BENCHMARK_SIZES: Tuple[int, ...] = (1024, 1024 * 1024, 10 * 1024 * 1024)
BENCHMARK_MODES: Tuple[str, ...] = ("gcm", "cbc")
TIMING_BOUNDARY_DEF: str = "crypto_primitive_only_excluding_setup_io_and_validation"


@dataclass(frozen=True)
class BenchmarkResult:
    mode: str
    operation: str
    size_bytes: int
    repeat: int
    elapsed_ns: int
    python_version: str
    os: str
    cpu: str
    cpu_count: int | None
    cryptography_version: str
    openssl_version: str
    run_parameters: str
    timing_boundary: str

    def as_tuple(self) -> Tuple:
        return (
            self.mode,
            self.operation,
            self.size_bytes,
            self.repeat,
            self.elapsed_ns,
            self.python_version,
            self.os,
            self.cpu,
            self.cpu_count,
            self.cryptography_version,
            self.openssl_version,
            self.run_parameters,
            self.timing_boundary,
        )


def get_cryptography_openssl_version() -> str:
    """Return the OpenSSL version string actually used by cryptography."""
    try:
        from cryptography.hazmat.backends.openssl.backend import backend

        return backend.openssl_version_text()
    except Exception:
        return ssl.OPENSSL_VERSION


def get_cpu_info() -> str:
    """Return descriptive CPU architecture / processor information."""
    processor = platform.processor()
    machine = platform.machine()
    if processor and machine and processor != machine:
        return f"{processor} ({machine})"
    return processor or machine or "unknown"


def _deterministic_fixture(size: int) -> bytes:
    """Return deterministic bytes of given size generated via SHA-256 chaining.

    The fixture is completely reproducible and does not consume OS entropy.
    """
    out = bytearray()
    seed = b"SecureVault-AES-Benchmark-Deterministic-Seed"
    while len(out) < size:
        seed = hashlib.sha256(seed).digest()
        out.extend(seed)
    return bytes(out[:size])


def _publish_csv(path: Path, header: list[str], rows: List[Tuple]) -> None:
    """Atomically publish a CSV without replacing existing evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(header)
            writer.writerows(rows)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise FileExistsError(f"Output already exists; refusing to overwrite: {path}") from exc
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def run_benchmark(
    repeats: int = 30,
    warmup_iterations: int = 2,
    output_path: str | Path | None = None,
) -> List[BenchmarkResult]:
    """Execute the AES benchmark experiment and persist observations to CSV.

    Parameters
    ----------
    repeats:
        Number of repetitions per (mode, size, operation) configuration.
        Default is 30, producing 2 * 3 * 30 * 2 = 360 observations.
    warmup_iterations:
        Number of untimed warm-up cycles executed before timing each configuration.
    output_path:
        Destination CSV path. If None, defaults to
        benchmarks/results/benchmark_results.csv.

    Returns
    -------
    List[BenchmarkResult]
        All collected observations.
    """
    if not isinstance(repeats, int) or isinstance(repeats, bool):
        raise TypeError(f"repeats must be an integer; got {type(repeats).__name__}")
    if repeats <= 0:
        raise ValueError(f"repeats must be a positive integer; got {repeats}")
    if not isinstance(warmup_iterations, int) or isinstance(warmup_iterations, bool):
        raise TypeError(f"warmup_iterations must be an integer; got {type(warmup_iterations).__name__}")
    if warmup_iterations < 0:
        raise ValueError(f"warmup_iterations cannot be negative; got {warmup_iterations}")

    if output_path is None:
        out_file = Path("benchmarks") / "results" / "benchmark_results.csv"
    else:
        out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    results: List[BenchmarkResult] = []

    env_meta = dict(
        python_version=sys.version.replace("\n", " ").strip(),
        os=platform.platform(),
        cpu=get_cpu_info(),
        cpu_count=os.cpu_count(),
        cryptography_version=__import__("cryptography").__version__,
        openssl_version=get_cryptography_openssl_version(),
        run_parameters=f"repeats={repeats};warmup={warmup_iterations}",
        timing_boundary=TIMING_BOUNDARY_DEF,
    )

    for mode in BENCHMARK_MODES:
        for size in BENCHMARK_SIZES:
            plaintext = _deterministic_fixture(size)

            # 1. Untimed round-trip correctness validation before collecting measurements
            if mode == "gcm":
                v_key = generate_gcm_dek()
                v_nonce = generate_gcm_nonce()
                v_ct, v_tag = encrypt_gcm(v_key, v_nonce, plaintext)
                v_rec = decrypt_gcm(v_key, v_nonce, v_ct, v_tag)
            else:
                v_key = generate_cbc_dek()
                v_iv = generate_cbc_iv()
                v_ct = encrypt_cbc(v_key, v_iv, plaintext)
                v_rec = decrypt_cbc(v_key, v_iv, v_ct)

            if v_rec != plaintext:
                raise AssertionError(f"Pre-measurement validation failed for mode={mode}, size={size}")

            # 2. Untimed warm-up iterations
            for _ in range(warmup_iterations):
                if mode == "gcm":
                    w_key, w_nonce = generate_gcm_dek(), generate_gcm_nonce()
                    w_ct, w_tag = encrypt_gcm(w_key, w_nonce, plaintext)
                    _ = decrypt_gcm(w_key, w_nonce, w_ct, w_tag)
                else:
                    w_key, w_iv = generate_cbc_dek(), generate_cbc_iv()
                    w_ct = encrypt_cbc(w_key, w_iv, plaintext)
                    _ = decrypt_cbc(w_key, w_iv, w_ct)

            # 3. Timed observations with precomputed decryption inputs and order alternation
            for i in range(repeats):
                # Prepare encryption inputs (independent key and IV/nonce)
                if mode == "gcm":
                    enc_key = generate_gcm_dek()
                    enc_iv_or_nonce = generate_gcm_nonce()
                else:
                    enc_key = generate_cbc_dek()
                    enc_iv_or_nonce = generate_cbc_iv()

                # Prepare valid decryption inputs in advance before timed decryption
                if mode == "gcm":
                    dec_key = generate_gcm_dek()
                    dec_iv_or_nonce = generate_gcm_nonce()
                    dec_ct, dec_tag = encrypt_gcm(dec_key, dec_iv_or_nonce, plaintext)
                else:
                    dec_key = generate_cbc_dek()
                    dec_iv_or_nonce = generate_cbc_iv()
                    dec_ct = encrypt_cbc(dec_key, dec_iv_or_nonce, plaintext)
                    dec_tag = None

                # Balanced / alternating measurement order to reduce fixed-order bias
                if i % 2 == 0:
                    # Encrypt first
                    t0 = time.perf_counter_ns()
                    if mode == "gcm":
                        enc_result = encrypt_gcm(enc_key, enc_iv_or_nonce, plaintext)
                    else:
                        enc_result = encrypt_cbc(enc_key, enc_iv_or_nonce, plaintext)
                    t1 = time.perf_counter_ns()
                    enc_elapsed_ns = t1 - t0

                    # Decrypt second
                    t2 = time.perf_counter_ns()
                    if mode == "gcm":
                        rec = decrypt_gcm(dec_key, dec_iv_or_nonce, dec_ct, dec_tag)
                    else:
                        rec = decrypt_cbc(dec_key, dec_iv_or_nonce, dec_ct)
                    t3 = time.perf_counter_ns()
                    dec_elapsed_ns = t3 - t2
                else:
                    # Decrypt first
                    t0 = time.perf_counter_ns()
                    if mode == "gcm":
                        rec = decrypt_gcm(dec_key, dec_iv_or_nonce, dec_ct, dec_tag)
                    else:
                        rec = decrypt_cbc(dec_key, dec_iv_or_nonce, dec_ct)
                    t1 = time.perf_counter_ns()
                    dec_elapsed_ns = t1 - t0

                    # Encrypt second
                    t2 = time.perf_counter_ns()
                    if mode == "gcm":
                        enc_result = encrypt_gcm(enc_key, enc_iv_or_nonce, plaintext)
                    else:
                        enc_result = encrypt_cbc(enc_key, enc_iv_or_nonce, plaintext)
                    t3 = time.perf_counter_ns()
                    enc_elapsed_ns = t3 - t2

                if mode == "gcm":
                    enc_ct, enc_tag = enc_result
                    enc_rec = decrypt_gcm(enc_key, enc_iv_or_nonce, enc_ct, enc_tag)
                else:
                    enc_rec = decrypt_cbc(enc_key, enc_iv_or_nonce, enc_result)
                if enc_rec != plaintext:
                    raise AssertionError(f"Encryption output verification failed for {mode} size={size} repeat={i}")

                # Post-timing untimed verification
                if rec != plaintext:
                    raise AssertionError(f"Decryption mismatch at repeat {i} for mode={mode}, size={size}")

                results.append(
                    BenchmarkResult(
                        mode=mode,
                        operation="encrypt",
                        size_bytes=size,
                        repeat=i,
                        elapsed_ns=enc_elapsed_ns,
                        **env_meta,
                    )
                )
                results.append(
                    BenchmarkResult(
                        mode=mode,
                        operation="decrypt",
                        size_bytes=size,
                        repeat=i,
                        elapsed_ns=dec_elapsed_ns,
                        **env_meta,
                    )
                )

    header = [
        "mode",
        "operation",
        "size_bytes",
        "repeat",
        "elapsed_ns",
        "python_version",
        "os",
        "cpu",
        "cpu_count",
        "cryptography_version",
        "openssl_version",
        "run_parameters",
        "timing_boundary",
    ]
    _publish_csv(out_file, header, [r.as_tuple() for r in results])

    return results


def main() -> None:
    """CLI entry point for running the AES benchmark runner."""
    start = time.perf_counter()
    results = run_benchmark()
    duration = time.perf_counter() - start
    print(f"Benchmark completed: {len(results)} observations in {duration:.2f}s")
    print(f"CSV written to {os.path.abspath('benchmarks/results/benchmark_results.csv')}")


if __name__ == "__main__":
    warnings.filterwarnings("ignore", category=UserWarning)
    main()
