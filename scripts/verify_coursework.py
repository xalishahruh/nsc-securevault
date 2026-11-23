"""Reproduce the C12 checks from an extracted tree and clean installation.

Run from the extracted root with python -m scripts.verify_coursework --output-dir DIR.
DIR must be a new directory outside the source tree.
"""

import argparse
import csv
import itertools
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
from collections import defaultdict
from math import isclose
from pathlib import Path

import cryptography
import pytest
import securevault
from cryptography.hazmat.backends.openssl.backend import backend


def run(*args):
    command = [sys.executable, *args]
    print("+ python", *args, flush=True)
    subprocess.run(command, check=True)


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def verify_binary_cli():
    def cli(action, *args, code=0, detail=None):
        proc = subprocess.run(
            [sys.executable, "-m", "securevault", action, *map(str, args)],
            text=True, capture_output=True, check=False,
        )
        check(proc.returncode == code, f"{action} had exit code {proc.returncode} instead of {code}")
        check(detail is None or detail in proc.stderr, f"{action} diagnostic missing {detail}")

    with tempfile.TemporaryDirectory(prefix="securevault-c12-binary-") as temp:
        root = Path(temp).resolve()
        source = root / "binary"
        original = bytes(range(256)) * 31 + b"\x00\xff\x80"
        source.write_bytes(original)
        for mode in ("gcm", "cbc"):
            encrypted, key, output = (root / f"{mode}.{suffix}" for suffix in ("svlt", "svkey", "recovered"))
            cli("encrypt", "--mode", mode, "--input", source, "--output", encrypted, "--key-output", key)
            cli("decrypt", "--input", encrypted, "--key-file", key, "--output", output, "--require-mode", mode)
            check(output.read_bytes() == original, f"{mode} binary recovery differs")
            raw = bytearray(encrypted.read_bytes())
            if mode == "gcm":
                wrong_key = root / "wrong.svkey"
                mutated = bytearray(key.read_bytes())
                mutated[-1] ^= 1  # Only the DEK changes. Association fields stay valid.
                wrong_key.write_bytes(mutated)
                rejected = root / "rejected"
                cli("decrypt", "--input", encrypted, "--key-file", wrong_key, "--output", rejected,
                    "--require-mode", mode, code=2, detail="AuthenticationError")
                check(not rejected.exists(), "Wrong GCM key published plaintext")
                raw[-1] ^= 1
                encrypted.write_bytes(raw)
                cli("decrypt", "--input", encrypted, "--key-file", key, "--output", rejected,
                    "--require-mode", mode, code=2, detail="AuthenticationError")
                check(not rejected.exists(), "GCM tag failure published plaintext")
            else:
                raw[24] ^= 1  # CBC IV begins at byte 24.
                encrypted.write_bytes(raw)
                changed = root / "cbc.corrupted"
                cli("decrypt", "--input", encrypted, "--key-file", key, "--output", changed, "--require-mode", mode)
                check(changed.read_bytes() == bytes([original[0] ^ 1]) + original[1:],
                      "Unexpected CBC IV-tamper outcome")
    print(f"Binary CLI: {len(original)} bytes recovered exactly in both modes. Wrong GCM key and tag rejected "
          "with no output. CBC IV change produced the expected unauthenticated output.", flush=True)


def rows(path):
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def verify_statistics(raw, folder):
    groups = defaultdict(dict)
    configs = set(itertools.product(("gcm", "cbc"), ("encrypt", "decrypt"), (1024, 1048576, 10485760)))
    for row in rows(raw):
        key = row["mode"], row["operation"], int(row["size_bytes"])
        trial, ns = int(row["repeat"]), int(row["elapsed_ns"])
        check(ns > 0 and trial not in groups[key], "Nonpositive or duplicate benchmark observation")
        groups[key][trial] = ns
    check(groups.keys() == configs and all(set(v) == set(range(30)) for v in groups.values()),
          "Incomplete 360-observation benchmark matrix")
    summary, comparisons = rows(folder / "results_summary.csv"), rows(folder / "mode_comparison.csv")
    check({(r["mode"], r["operation"], int(r["size_bytes"])) for r in summary} == configs
          and len(summary) == 12 and len(comparisons) == 6, "Incomplete benchmark summary")
    check(len({(r["operation"], r["size_bytes"]) for r in comparisons}) == 6, "Duplicate comparison")
    for row in summary:
        size = int(row["size_bytes"])
        values = list(groups[(row["mode"], row["operation"], size)].values())
        mean = statistics.mean(values)
        expected = {
            "observation_count": 30, "mean_ms": mean / 1e6, "median_ms": statistics.median(values) / 1e6,
            "sample_stdev_ms": statistics.stdev(values) / 1e6, "min_ms": min(values) / 1e6,
            "max_ms": max(values) / 1e6, "throughput_MiB_s": (size / 2**20) / (mean / 1e9),
        }
        check(all(isclose(float(row[k]), v, rel_tol=1e-12) for k, v in expected.items()),
              "Benchmark summary calculation mismatch")
    for row in comparisons:
        size, op = int(row["size_bytes"]), row["operation"]
        gcm, cbc = (statistics.mean(groups[(mode, op, size)].values()) / 1e6 for mode in ("gcm", "cbc"))
        expected = {"gcm_mean_ms": gcm, "cbc_mean_ms": cbc, "difference_percent": 100 * (gcm - cbc) / cbc}
        check(all(isclose(float(row[k]), v, rel_tol=1e-12) for k, v in expected.items()),
              "Benchmark comparison calculation mismatch")
    print(f"{raw.name}: independently verified 360 observations, 12 summaries and six comparisons.", flush=True)


def verify_figures(output):
    os.environ["MPLCONFIGDIR"] = str(output / "matplotlib-cache")
    from figures import generate_figures as figures
    from PIL import Image, ImageChops

    originals = Path("figures")
    figures.FIGURES_DIR = output / "figures"
    figures.main()
    for name in ("F1_architecture.svg", "F2_container_layout.svg", "F3_performance.png", "F4_tamper_behavior.png"):
        left, right = originals / name, figures.FIGURES_DIR / name
        if left.suffix == ".svg":
            check(left.read_bytes() == right.read_bytes(), f"SVG mismatch: {name}")
        else:
            with Image.open(left) as first, Image.open(right) as second:
                check(first.size == second.size and
                      ImageChops.difference(first.convert("RGB"), second.convert("RGB")).getbbox() is None,
                      f"PNG pixels differ: {name}")
        print(f"Verified {name}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    output = parser.parse_args().output_dir.resolve()
    root = Path.cwd().resolve()
    check(not output.is_relative_to(root), "Output must be outside the extracted tree")
    check(Path(securevault.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()),
          "SecureVault must be installed in the active acceptance virtual environment")
    output.mkdir()
    environment = {
        "os": platform.platform(), "machine": platform.machine(), "python": sys.version,
        "cryptography": cryptography.__version__, "openssl": backend.openssl_version_text(),
        "pytest": pytest.__version__, "installation": "non-editable, virtual environment site-packages",
    }
    (output / "environment.json").write_text(json.dumps(environment, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(environment), flush=True)
    run("-m", "pip", "check")
    run("-m", "compileall", "-q", "src", "benchmarks", "experiments", "tests", "figures", "scripts")
    verify_binary_cli()
    run("-O", "scripts/run_demo.py")
    run("-m", "pytest", "-q")

    history = Path("benchmarks/results")
    fresh = output / "fresh.csv"
    run("-m", "benchmarks.benchmark_modes", "--output", str(fresh), "--repeats", "30")
    for kind, raw in (("historical", history / "benchmark_results.csv"), ("fresh", fresh)):
        destination = output / kind
        run("-m", "benchmarks.summarize", "--input", str(raw), "--output-dir", str(destination))
        verify_statistics(raw, destination)
        if kind == "historical":
            for name in ("results_summary.csv", "mode_comparison.csv"):
                check((history / name).read_bytes() == (destination / name).read_bytes(),
                      f"Historical statistics changed: {name}")
    security = output / "security.csv"
    run("-m", "experiments.security_experiments", "--output", str(security))
    historical_security = {row["experiment_id"]: row for row in rows(Path("experiments/results/security_outcomes.csv"))}
    fresh_security = {row["experiment_id"]: row for row in rows(security)}
    check(fresh_security.keys() == historical_security.keys() and len(fresh_security) == 10,
          "Security experiment IDs changed")
    for ident, row in fresh_security.items():
        if ident == "CBC-03":
            check((row["exception_type"], row["plaintext_returned"], row["plaintext_matches_original"]) in {
                ("PaddingError", "False", ""), ("None", "True", "False"),
            }, "Unexpected CBC wrong-key outcome")
        else:
            old = historical_security[ident]
            check(row["exception_type"] == old["exception_type"] and
                  row["plaintext_returned"] == old["plaintext_published"] and
                  row["plaintext_matches_original"] == old["plaintext_matches_original"],
                  f"Security experiment outcome changed: {ident}")
    verify_figures(output)
    print("C12 reproducibility checks passed.", flush=True)


if __name__ == "__main__":
    main()
