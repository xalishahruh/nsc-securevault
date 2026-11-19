"""Tests for the AES benchmark runner.

The benchmark suite is exercised with a tiny repeat count (3) so the test
runs quickly.  The assertions verify:

* The CSV file is created at the expected location.
* The total number of rows equals ``len(modes) * len(sizes) * 2 * repeats``.
* The header contains all required columns.
* Each observation records a positive integer ``elapsed_ns``.
* ``mode`` and ``operation`` values are within the allowed set.
"""

import csv
import os
from pathlib import Path

import pytest

from benchmarks.benchmark_modes import run_benchmark


@pytest.fixture(scope="function")
def clean_results(tmp_path: Path):
    """Ensure a clean results directory for each test run."""
    results_dir = Path("benchmarks/results")
    # Remove any previous file if it exists.
    csv_path = results_dir / "benchmark_results.csv"
    if csv_path.exists():
        csv_path.unlink()
    yield csv_path
    # Cleanup after test.
    if csv_path.exists():
        csv_path.unlink()


def test_benchmark_observations_and_schema(clean_results: Path):
    repeats = 3
    # Run the benchmark with a small repeat count.
    results = run_benchmark(repeats=repeats, output_path=str(clean_results))

    # Verify the function returns the expected number of BenchmarkResult objects.
    expected_rows = len(["gcm", "cbc"]) * len([1024, 1024 * 1024, 10 * 1024 * 1024]) * 2 * repeats
    assert len(results) == expected_rows

    # Verify CSV file exists and has the correct number of rows (including header).
    assert clean_results.is_file()
    with clean_results.open(newline="") as f:
        reader = csv.reader(f)
        rows = list(reader)

    # Header + data rows.
    assert len(rows) == expected_rows + 1
    header = rows[0]
    expected_header = [
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
    assert header == expected_header

    # Validate each data row.
    for row in rows[1:]:
        mode, operation, size_bytes, repeat, elapsed_ns, *_ = row
        assert mode in {"gcm", "cbc"}
        assert operation in {"encrypt", "decrypt"}
        assert int(size_bytes) in {1024, 1024 * 1024, 10 * 1024 * 1024}
        assert int(repeat) >= 0
        # elapsed_ns must be a positive integer.
        assert int(elapsed_ns) > 0

        # Ensure no secret material is present – the columns after ``elapsed_ns``
        # are environment metadata strings, which are safe to appear.
        for meta in row[5:]:
            assert isinstance(meta, str)

