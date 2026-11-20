from __future__ import annotations

import csv
from pathlib import Path

import pytest

from benchmarks.benchmark_modes import BENCHMARK_MODES, BENCHMARK_SIZES
from benchmarks.summarize import DatasetError, RAW_COLUMNS, analyze, load_observations, main, summarize


def dataset(path: Path, *, repeats: int = 2, mutate=None) -> Path:
    metadata = ["Py", "OS", "CPU", "4", "crypto", "OpenSSL", f"repeats={repeats};warmup=1", "boundary"]
    rows = []
    for mode in BENCHMARK_MODES:
        for size in BENCHMARK_SIZES:
            for op in ("encrypt", "decrypt"):
                for repeat in range(repeats):
                    value = 1_000_000 * (repeat + (1 if mode == "gcm" else 2))
                    rows.append([mode, op, str(size), str(repeat), str(value), *metadata])
    if mutate:
        rows = mutate(rows)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(RAW_COLUMNS)
        writer.writerows(rows)
    return path


def test_statistics_and_formulas(tmp_path: Path) -> None:
    raw = dataset(tmp_path / "raw.csv")
    observations, _ = load_observations(raw)
    summaries, comparisons = summarize(observations)
    row = next(r for r in summaries if (r["mode"], r["size_bytes"], r["operation"]) == ("gcm", 1024, "encrypt"))
    assert row["mean_ms"] == 1.5
    assert row["median_ms"] == 1.5
    assert row["sample_stdev_ms"] == pytest.approx(2**-0.5)
    assert row["min_ms"] == 1
    assert row["max_ms"] == 2
    assert row["throughput_MiB_s"] == pytest.approx((1024 / 1_048_576) / 0.0015)
    assert comparisons[0]["difference_percent"] == pytest.approx(-40.0)


@pytest.mark.parametrize("mutate", [
    lambda rows: rows[:-1],
    lambda rows: rows + [rows[0]],
    lambda rows: [r for r in rows if not (r[0] == "gcm" and r[1] == "encrypt" and r[2] == "1024" and r[3] == "1")],
    lambda rows: [["bad", *rows[0][1:]], *rows[1:]],
    lambda rows: [[*rows[0][:4], "0", *rows[0][5:]], *rows[1:]],
    lambda rows: [[*rows[0][:5], "OTHER", *rows[0][6:]], *rows[1:]],
    lambda rows: [[*rows[0][:2], "7", *rows[0][3:]], *rows[1:]],
    lambda rows: [[*rows[0][:1], "run", *rows[0][2:]], *rows[1:]],
    lambda rows: [[*rows[0][:5], "", *rows[0][6:]], *rows[1:]],
])
def test_rejects_invalid_or_incomplete_data(tmp_path: Path, mutate) -> None:
    with pytest.raises(DatasetError):
        load_observations(dataset(tmp_path / "invalid.csv", mutate=mutate))


def test_rejects_metadata_mismatch_and_single_repeat(tmp_path: Path) -> None:
    raw = dataset(tmp_path / "metadata.csv", mutate=lambda rows: [rows[0], [*rows[1][:-3], "repeats=2;warmup=1", *rows[1][-2:]], *rows[2:]])
    with pytest.raises(DatasetError, match="metadata"):
        load_observations(raw)
    one = dataset(tmp_path / "one.csv", repeats=1)
    with pytest.raises(DatasetError, match="two repetitions"):
        summarize(load_observations(one)[0])


def test_outputs_and_preserves_existing(tmp_path: Path) -> None:
    raw = dataset(tmp_path / "raw.csv")
    out = tmp_path / "out"
    summary, comparison, _, _ = analyze(raw, out)
    assert len(list(csv.DictReader(summary.open()))) == 12
    assert len(list(csv.DictReader(comparison.open()))) == 6
    before = summary.read_bytes()
    with pytest.raises(FileExistsError):
        analyze(raw, out)
    assert summary.read_bytes() == before


def test_current_benchmark_schema_compatibility(tmp_path: Path) -> None:
    assert tuple(RAW_COLUMNS) == ("mode", "operation", "size_bytes", "repeat", "elapsed_ns", "python_version", "os", "cpu", "cpu_count", "cryptography_version", "openssl_version", "run_parameters", "timing_boundary")


def test_cli_reports_invalid_csv_with_nonzero_status(tmp_path: Path, capsys) -> None:
    bad = tmp_path / "bad.csv"
    bad.write_text("wrong,header\n", encoding="utf-8")
    assert main(["--input", str(bad), "--output-dir", str(tmp_path / "out")]) == 1
    assert "error:" in capsys.readouterr().err
