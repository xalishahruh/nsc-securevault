"""Tests for the AES benchmark runner.

All tests output to pytest's isolated tmp_path fixture to guarantee
that existing benchmark artifacts in the repository are never touched
or deleted.
"""

from __future__ import annotations

import csv
import threading
from pathlib import Path

import pytest

from benchmarks.benchmark_modes import (
    BENCHMARK_MODES,
    BENCHMARK_SIZES,
    TIMING_BOUNDARY_DEF,
    get_cpu_info,
    get_cryptography_openssl_version,
    _publish_csv,
    run_benchmark,
)


def test_benchmark_schema_and_metadata(tmp_path: Path) -> None:
    """Verify CSV schema, headers, and reproducibility metadata."""
    repeats = 2
    warmup = 1
    out_csv = tmp_path / "benchmark_output.csv"

    results = run_benchmark(
        repeats=repeats,
        warmup_iterations=warmup,
        output_path=out_csv,
    )

    expected_count = len(BENCHMARK_MODES) * len(BENCHMARK_SIZES) * 2 * repeats
    assert len(results) == expected_count

    assert out_csv.is_file()
    with out_csv.open("r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        rows = list(reader)

    # 1 header line + expected data rows
    assert len(rows) == expected_count + 1
    header = rows[0]
    expected_header = [
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
    assert header == expected_header

    expected_openssl = get_cryptography_openssl_version()
    expected_cpu = get_cpu_info()

    for row in rows[1:]:
        (
            mode,
            operation,
            size_bytes,
            repeat,
            elapsed_ns,
            py_ver,
            os_name,
            cpu,
            cpu_count,
            crypto_ver,
            openssl_ver,
            params,
            boundary,
        ) = row

        assert mode in BENCHMARK_MODES
        assert operation in {"encrypt", "decrypt"}
        assert int(size_bytes) in BENCHMARK_SIZES
        assert int(repeat) in range(repeats)
        assert int(elapsed_ns) > 0
        assert py_ver
        assert os_name
        assert cpu == expected_cpu
        assert int(cpu_count) > 0
        assert crypto_ver
        assert openssl_ver == expected_openssl
        assert params == f"repeats={repeats};warmup={warmup}"
        assert boundary == TIMING_BOUNDARY_DEF


def test_benchmark_configuration_coverage(tmp_path: Path) -> None:
    """Ensure all expected combinations of mode, size, and operation are covered."""
    out_csv = tmp_path / "coverage.csv"
    results = run_benchmark(repeats=1, warmup_iterations=0, output_path=out_csv)

    covered_configurations = {
        (r.mode, r.size_bytes, r.operation)
        for r in results
    }

    expected_configurations = {
        (m, s, op)
        for m in BENCHMARK_MODES
        for s in BENCHMARK_SIZES
        for op in ("encrypt", "decrypt")
    }

    assert covered_configurations == expected_configurations
    assert len(results) == len(expected_configurations)


def test_benchmark_default_observation_count(tmp_path: Path) -> None:
    """Verify that default execution produces exactly 360 observations."""
    out_csv = tmp_path / "default_360.csv"
    results = run_benchmark(output_path=out_csv)

    # 2 modes * 3 sizes * 30 repetitions * 2 operations = 360 observations
    assert len(results) == 360

    with out_csv.open("r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        rows = list(reader)

    # Header + 360 observations
    assert len(rows) == 361


def test_benchmark_invalid_parameters(tmp_path: Path) -> None:
    """Ensure invalid repetition counts or warm-up counts fail safely."""
    out_csv = tmp_path / "should_not_exist.csv"

    with pytest.raises(ValueError, match="repeats must be a positive integer"):
        run_benchmark(repeats=0, output_path=out_csv)

    with pytest.raises(ValueError, match="repeats must be a positive integer"):
        run_benchmark(repeats=-5, output_path=out_csv)

    with pytest.raises(TypeError, match="repeats must be an integer"):
        run_benchmark(repeats="30", output_path=out_csv)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="repeats must be an integer"):
        run_benchmark(repeats=True, output_path=out_csv)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="warmup_iterations cannot be negative"):
        run_benchmark(repeats=1, warmup_iterations=-1, output_path=out_csv)

    with pytest.raises(TypeError, match="warmup_iterations must be an integer"):
        run_benchmark(repeats=1, warmup_iterations="2", output_path=out_csv)  # type: ignore[arg-type]

    assert not out_csv.exists()


def test_preservation_of_existing_output_artifacts(tmp_path: Path) -> None:
    """Ensure running benchmarks never clobbers or deletes unrelated artifacts."""
    sentinel_path = tmp_path / "sentinel.csv"
    sentinel_content = "sentinel_header\nsentinel_data_12345\n"
    sentinel_path.write_text(sentinel_content, encoding="utf-8")

    # Run benchmark targeting a distinct destination
    new_csv = tmp_path / "new_benchmark.csv"
    run_benchmark(repeats=1, warmup_iterations=0, output_path=new_csv)

    # Verify sentinel artifact remains completely intact
    assert sentinel_path.exists()
    assert sentinel_path.read_text(encoding="utf-8") == sentinel_content

    # Also verify that repo results directory (if exists) is preserved
    real_repo_results = Path("benchmarks") / "results" / "benchmark_results.csv"
    if real_repo_results.exists():
        repo_data_before = real_repo_results.read_bytes()
        with pytest.raises(FileExistsError):
            run_benchmark(repeats=1, warmup_iterations=0, output_path=new_csv)
        assert real_repo_results.read_bytes() == repo_data_before


def test_existing_output_is_never_overwritten(tmp_path: Path) -> None:
    output = tmp_path / "evidence.csv"
    output.write_text("original\n", encoding="utf-8")
    with pytest.raises(FileExistsError):
        _publish_csv(output, ["header"], [("new",)])
    assert output.read_text(encoding="utf-8") == "original\n"


def test_concurrent_publication_has_single_winner(tmp_path: Path) -> None:
    output = tmp_path / "shared.csv"
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def publish(value: str) -> None:
        barrier.wait()
        try:
            _publish_csv(output, ["value"], [(value,)])
            outcomes.append("published")
        except FileExistsError:
            outcomes.append("exists")

    threads = [threading.Thread(target=publish, args=(str(i),)) for i in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["exists", "published"]
    assert output.read_text(encoding="utf-8").splitlines()[1] in {"0", "1"}


def test_publication_write_failure_leaves_no_final_or_temp_file(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "evidence.csv"

    class BrokenWriter:
        def writerow(self, row):
            raise OSError("simulated write failure")

        def writerows(self, rows):
            raise OSError("simulated write failure")

    monkeypatch.setattr("benchmarks.benchmark_modes.csv.writer", lambda _: BrokenWriter())
    with pytest.raises(OSError, match="simulated write failure"):
        _publish_csv(output, ["header"], [("value",)])
    assert not output.exists()
    assert list(tmp_path.iterdir()) == []


def test_unsupported_hard_link_preserves_existing_target_and_cleans_temp(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "evidence.csv"
    output.write_text("original\n", encoding="utf-8")

    def unsupported(*args):
        raise OSError("hard links unsupported")

    monkeypatch.setattr("benchmarks.benchmark_modes.os.link", unsupported)
    with pytest.raises(OSError, match="hard links unsupported"):
        _publish_csv(output, ["header"], [("new",)])
    assert output.read_text(encoding="utf-8") == "original\n"
    assert list(tmp_path.iterdir()) == [output]
