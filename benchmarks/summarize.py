"""Validate raw SecureVault benchmark observations and write summaries."""

from __future__ import annotations

import argparse
import csv
import math
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, median, stdev
from typing import Sequence

from benchmarks.benchmark_modes import (
    BENCHMARK_MODES,
    BENCHMARK_SIZES,
    _publish_csv,
)

RAW_COLUMNS = (
    "mode", "operation", "size_bytes", "repeat", "elapsed_ns",
    "python_version", "os", "cpu", "cpu_count", "cryptography_version",
    "openssl_version", "run_parameters", "timing_boundary",
)
OPERATIONS = ("encrypt", "decrypt")


class DatasetError(ValueError):
    """Raw benchmark data is malformed or incomplete."""


@dataclass(frozen=True)
class Observation:
    mode: str
    operation: str
    size_bytes: int
    repeat: int
    elapsed_ns: int
    metadata: tuple[str, ...]


def _integer(value: str, name: str, *, positive: bool = False) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise DatasetError(f"{name} must be an integer: {value!r}") from exc
    if str(number) != value.strip():
        raise DatasetError(f"{name} must be an integer: {value!r}")
    if positive and number <= 0:
        raise DatasetError(f"{name} must be positive")
    return number


def load_observations(path: str | Path) -> tuple[list[Observation], int]:
    """Load and strictly validate a complete benchmark run."""
    try:
        fh = Path(path).open(encoding="utf-8", newline="")
    except OSError as exc:
        raise DatasetError(f"Cannot open input CSV: {exc}") from exc
    with fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None or tuple(reader.fieldnames) != RAW_COLUMNS:
            raise DatasetError(f"CSV header must exactly match: {', '.join(RAW_COLUMNS)}")
        observations = []
        seen = set()
        metadata_values = set()
        repetitions = set()
        for line, row in enumerate(reader, start=2):
            if None in row or any(value is None or not value.strip() for value in row.values()):
                raise DatasetError(f"Malformed or missing field on line {line}")
            mode, operation = row["mode"], row["operation"]
            if mode not in BENCHMARK_MODES:
                raise DatasetError(f"Unsupported mode on line {line}: {mode}")
            if operation not in OPERATIONS:
                raise DatasetError(f"Unsupported operation on line {line}: {operation}")
            size = _integer(row["size_bytes"], "size_bytes", positive=True)
            repeat = _integer(row["repeat"], "repeat")
            elapsed = _integer(row["elapsed_ns"], "elapsed_ns", positive=True)
            if size not in BENCHMARK_SIZES:
                raise DatasetError(f"Unsupported size on line {line}: {size}")
            if repeat < 0:
                raise DatasetError(f"repeat must be nonnegative on line {line}")
            key = (mode, size, operation, repeat)
            if key in seen:
                raise DatasetError(f"Duplicate observation on line {line}: {key}")
            seen.add(key)
            repetitions.add(repeat)
            metadata_values.add(tuple(row[name] for name in RAW_COLUMNS[5:]))
            observations.append(Observation(mode, operation, size, repeat, elapsed,
                                            tuple(row[name] for name in RAW_COLUMNS[5:])))
    if not observations:
        raise DatasetError("Input CSV contains no observations")
    if len(metadata_values) != 1:
        raise DatasetError("Environment metadata and run parameters must be consistent")
    if any(index < 0 for index in repetitions):
        raise DatasetError("Invalid repetition indices")
    repeat_count = max(repetitions) + 1
    if repetitions != set(range(repeat_count)):
        raise DatasetError("Repetition indices must be contiguous from zero")
    expected = {(mode, size, op, rep) for mode in BENCHMARK_MODES
                for size in BENCHMARK_SIZES for op in OPERATIONS
                for rep in range(repeat_count)}
    if seen != expected:
        missing = len(expected - seen)
        raise DatasetError(f"Incomplete benchmark matrix: {missing} observations missing")
    # The runner records repeats=N;warmup=N in every row.
    parameters = next(iter(metadata_values))[-2]
    try:
        params = dict(item.split("=", 1) for item in parameters.split(";"))
        declared_repeats = _integer(params["repeats"], "run_parameters.repeats", positive=True)
        warmup = _integer(params["warmup"], "run_parameters.warmup")
        if warmup < 0 or set(params) != {"repeats", "warmup"}:
            raise DatasetError("Invalid run_parameters metadata")
    except (KeyError, ValueError) as exc:
        if isinstance(exc, DatasetError):
            raise
        raise DatasetError("Invalid run_parameters metadata") from exc
    if declared_repeats != repeat_count:
        raise DatasetError("Declared repetition count does not match observation coverage")
    return observations, repeat_count


def summarize(observations: Sequence[Observation]) -> tuple[list[dict], list[dict]]:
    grouped: dict[tuple[str, int, str], list[int]] = defaultdict(list)
    for observation in observations:
        grouped[(observation.mode, observation.size_bytes, observation.operation)].append(observation.elapsed_ns)
    if len(grouped) != len(BENCHMARK_MODES) * len(BENCHMARK_SIZES) * len(OPERATIONS):
        raise DatasetError("Complete benchmark matrix is required")
    rows = []
    for (mode, size, operation), values in sorted(grouped.items()):
        if len(values) < 2:
            raise DatasetError("At least two repetitions are required for sample standard deviation")
        avg = mean(values)
        rows.append({"mode": mode, "size_bytes": size, "operation": operation,
                     "observation_count": len(values), "mean_ms": avg / 1_000_000,
                     "median_ms": median(values) / 1_000_000,
                     "sample_stdev_ms": stdev(values) / 1_000_000,
                     "min_ms": min(values) / 1_000_000, "max_ms": max(values) / 1_000_000,
                     "throughput_MiB_s": (size / 1_048_576) / (avg / 1_000_000_000)})
    by_key = {(r["mode"], r["size_bytes"], r["operation"]): r for r in rows}
    comparisons = []
    for size in BENCHMARK_SIZES:
        for operation in OPERATIONS:
            gcm = by_key[("gcm", size, operation)]["mean_ms"]
            cbc = by_key[("cbc", size, operation)]["mean_ms"]
            comparisons.append({"size_bytes": size, "operation": operation,
                                "gcm_mean_ms": gcm, "cbc_mean_ms": cbc,
                                "difference_percent": 100 * (gcm - cbc) / cbc})
    return rows, comparisons


SUMMARY_COLUMNS = ("mode", "size_bytes", "operation", "observation_count", "mean_ms", "median_ms",
                   "sample_stdev_ms", "min_ms", "max_ms", "throughput_MiB_s")
COMPARISON_COLUMNS = ("size_bytes", "operation", "gcm_mean_ms", "cbc_mean_ms", "difference_percent")


def analyze(input_path: str | Path, output_dir: str | Path) -> tuple[Path, Path, list[dict], list[dict]]:
    observations, _ = load_observations(input_path)
    summaries, comparisons = summarize(observations)
    output_dir = Path(output_dir)
    summary_path = output_dir / "results_summary.csv"
    comparison_path = output_dir / "mode_comparison.csv"
    # Publish both only after all input validation and computation have succeeded.
    _publish_csv(summary_path, list(SUMMARY_COLUMNS), [tuple(row[c] for c in SUMMARY_COLUMNS) for row in summaries])
    try:
        _publish_csv(comparison_path, list(COMPARISON_COLUMNS), [tuple(row[c] for c in COMPARISON_COLUMNS) for row in comparisons])
    except Exception:
        # Preserve already published summary; avoid deleting evidence. Report partial publication.
        raise
    return summary_path, comparison_path, summaries, comparisons


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="raw benchmark CSV")
    parser.add_argument("--output-dir", required=True, type=Path, help="new/empty output directory")
    args = parser.parse_args(argv)
    try:
        summary, comparison, _, comparisons = analyze(args.input, args.output_dir)
    except (DatasetError, OSError) as exc:
        print(f"summarize: error: {exc}", file=sys.stderr)
        return 1
    print(f"Summary: {summary}")
    print(f"Comparison: {comparison}")
    print("Negative difference_percent means GCM has lower mean execution time.")
    for row in comparisons:
        print(f"{row['size_bytes']} bytes {row['operation']}: {row['difference_percent']:.2f}% GCM vs CBC")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
