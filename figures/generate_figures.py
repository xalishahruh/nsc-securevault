"""Generate report-ready figures for SecureVault coursework (6COSC033C CW1).

Figures produced:
  F1 — Architecture diagram (SVG text-based)
  F2 — .svlt container layout diagram
  F3 — AES performance comparison (actual benchmark data)
  F4 — Tamper behavior comparison

All figures are written to figures/ and are reproducible from the same input data.
Requires: matplotlib, the benchmark CSV at benchmarks/results/benchmark_results.csv.
"""

from __future__ import annotations

import csv
import io
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.gridspec import GridSpec
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("WARNING: matplotlib not available. Only SVG text figures will be generated.", file=sys.stderr)

FIGURES_DIR = Path("figures")
BENCHMARK_CSV = Path("benchmarks/results/benchmark_results.csv")
SUMMARY_CSV = Path("benchmarks/results/results_summary.csv")
SECURITY_CSV = Path("experiments/results/security_outcomes.csv")

SIZE_LABELS = {1024: "1 KiB", 1048576: "1 MiB", 10485760: "10 MiB"}
SIZES_ORDERED = [1024, 1048576, 10485760]


def ensure_figures_dir() -> None:
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# F1 — Architecture Diagram (SVG)
# ---------------------------------------------------------------------------

ARCHITECTURE_SVG = """\
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="820" height="520" font-family="monospace,DejaVu Sans Mono,Courier New">
  <style>
    .box { fill:#f0f4f8; stroke:#2d6a9f; stroke-width:1.5; rx:6; ry:6; }
    .crypto { fill:#e8f5e9; stroke:#2e7d32; stroke-width:1.5; }
    .security { fill:#fff3e0; stroke:#e65100; stroke-width:1.5; }
    .storage { fill:#fce4ec; stroke:#880e4f; stroke-width:1.5; }
    .key { fill:#ede7f6; stroke:#4527a0; stroke-width:1.5; }
    .title { font-size:13px; font-weight:bold; fill:#1a237e; }
    .sub { font-size:10px; fill:#333; }
    .small { font-size:9px; fill:#555; }
    .arrow { stroke:#555; stroke-width:1.4; fill:none; marker-end:url(#arr); }
  </style>
  <defs>
    <marker id="arr" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="#555"/>
    </marker>
  </defs>

  <!-- Title -->
  <text x="410" y="28" text-anchor="middle" class="title" font-size="15">SecureVault — System Architecture (6COSC033C CW1)</text>

  <!-- CLI Layer -->
  <rect x="20" y="45" width="780" height="62" class="box" rx="6" ry="6"/>
  <text x="410" y="65" text-anchor="middle" class="title">CLI Layer  (securevault encrypt | decrypt | inspect)</text>
  <text x="175" y="82" text-anchor="middle" class="sub">--mode gcm/cbc</text>
  <text x="175" y="96" text-anchor="middle" class="small">--input --output --key-output</text>
  <text x="410" y="82" text-anchor="middle" class="sub">--require-mode (downgrade guard)</text>
  <text x="410" y="96" text-anchor="middle" class="small">--overwrite (explicit)</text>
  <text x="645" y="82" text-anchor="middle" class="sub">inspect  (no key material)</text>
  <text x="645" y="96" text-anchor="middle" class="small">structural metadata only</text>

  <!-- Arrows CLI → FileService -->
  <line x1="410" y1="107" x2="410" y2="128" class="arrow"/>

  <!-- File Service -->
  <rect x="120" y="128" width="560" height="58" class="box" rx="6" ry="6"/>
  <text x="400" y="150" text-anchor="middle" class="title">file_service.py  (encrypt_file / decrypt_file / inspect_file)</text>
  <text x="250" y="168" text-anchor="middle" class="sub">Preflight validation, path safety, symlink guard</text>
  <text x="560" y="168" text-anchor="middle" class="sub">Fresh DEK generation, container assembly</text>

  <!-- Arrows FileService → Crypto -->
  <line x1="260" y1="186" x2="200" y2="220" class="arrow"/>
  <line x1="560" y1="186" x2="620" y2="220" class="arrow"/>

  <!-- AES-GCM -->
  <rect x="60" y="220" width="260" height="80" class="crypto" rx="6" ry="6"/>
  <text x="190" y="240" text-anchor="middle" class="title" fill="#1b5e20">AES-256-GCM (crypto/gcm.py)</text>
  <text x="190" y="258" text-anchor="middle" class="sub">Authenticated Encryption (AEAD)</text>
  <text x="190" y="274" text-anchor="middle" class="small">12-byte nonce (CSPRNG) · 128-bit tag</text>
  <text x="190" y="289" text-anchor="middle" class="small">Immutable header bound as AAD</text>

  <!-- AES-CBC -->
  <rect x="500" y="220" width="260" height="80" class="crypto" rx="6" ry="6"/>
  <text x="630" y="240" text-anchor="middle" class="title" fill="#1b5e20">AES-256-CBC (crypto/cbc.py)</text>
  <text x="630" y="258" text-anchor="middle" class="sub">Confidentiality Only · PKCS#7</text>
  <text x="630" y="274" text-anchor="middle" class="small">16-byte IV (CSPRNG) · No auth tag</text>
  <text x="630" y="289" text-anchor="middle" class="small">WARNING: no integrity protection</text>

  <!-- Container -->
  <rect x="230" y="330" width="360" height="62" class="storage" rx="6" ry="6"/>
  <text x="410" y="350" text-anchor="middle" class="title" fill="#880e4f">.svlt Container (container.py)</text>
  <text x="410" y="368" text-anchor="middle" class="small">Magic·Ver·Cipher·Flags·FileID·IV/Nonce·CiphertextLen (48B)</text>
  <text x="410" y="383" text-anchor="middle" class="small">KeyDesc(3B) + Ciphertext + [GCM Tag 16B]</text>

  <!-- Key -->
  <rect x="20" y="330" width="190" height="62" class="key" rx="6" ry="6"/>
  <text x="115" y="350" text-anchor="middle" class="title" fill="#4527a0">.svkey (key_provider.py)</text>
  <text x="115" y="368" text-anchor="middle" class="small">SVKY·Ver·FileID·CipherID·DEK(32B)</text>
  <text x="115" y="383" text-anchor="middle" class="small">54 bytes · mode+ID association</text>

  <!-- Safe I/O -->
  <rect x="230" y="420" width="360" height="60" class="security" rx="6" ry="6"/>
  <text x="410" y="440" text-anchor="middle" class="title" fill="#e65100">Safe File Publication (file_service.py)</text>
  <text x="410" y="458" text-anchor="middle" class="small">Staged temp file → os.link() (atomic, exclusive)</text>
  <text x="410" y="474" text-anchor="middle" class="small">0600 permissions · no-clobber by default · fail-closed</text>

  <!-- Arrows -->
  <line x1="190" y1="300" x2="310" y2="330" class="arrow"/>
  <line x1="630" y1="300" x2="510" y2="330" class="arrow"/>
  <line x1="115" y1="330" x2="230" y2="368" class="arrow"/>
  <line x1="410" y1="392" x2="410" y2="420" class="arrow"/>
</svg>
"""


def generate_f1_architecture() -> Path:
    out = FIGURES_DIR / "F1_architecture.svg"
    out.write_text(ARCHITECTURE_SVG, encoding="utf-8")
    print(f"  F1 written: {out}")
    return out


# ---------------------------------------------------------------------------
# F2 — Container Layout Diagram (SVG)
# ---------------------------------------------------------------------------

CONTAINER_SVG = """\
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="820" height="260" font-family="monospace,DejaVu Sans Mono,Courier New">
  <style>
    .label { font-size:10px; fill:#1a237e; font-weight:bold; text-anchor:middle; }
    .bytes { font-size:9px; fill:#333; text-anchor:middle; }
    .note  { font-size:9px; fill:#555; }
    .gcm   { fill:#e8f5e9; stroke:#2e7d32; stroke-width:1.2; }
    .cbc   { fill:#fff9c4; stroke:#f57f17; stroke-width:1.2; }
    .shared { fill:#e3f2fd; stroke:#0d47a1; stroke-width:1.2; }
    .optional { fill:#fce4ec; stroke:#880e4f; stroke-width:1.2; stroke-dasharray:4,3; }
  </style>

  <text x="410" y="22" text-anchor="middle" font-size="13" font-weight="bold" fill="#1a237e">SecureVault .svlt v1 Binary Container Layout</text>

  <!-- GCM row -->
  <text x="10" y="55" class="note" font-weight="bold">GCM:</text>
  <!-- Magic 4B -->
  <rect x="40" y="38" width="52" height="34" class="shared"/>
  <text x="66" y="55" class="label">Magic</text>
  <text x="66" y="66" class="bytes">SVLT (4B)</text>
  <!-- Ver 1B -->
  <rect x="92" y="38" width="34" height="34" class="shared"/>
  <text x="109" y="55" class="label">Ver</text>
  <text x="109" y="66" class="bytes">1B</text>
  <!-- Cipher 1B -->
  <rect x="126" y="38" width="34" height="34" class="shared"/>
  <text x="143" y="55" class="label">Cipher</text>
  <text x="143" y="66" class="bytes">1=GCM</text>
  <!-- Flags 2B -->
  <rect x="160" y="38" width="34" height="34" class="shared"/>
  <text x="177" y="55" class="label">Flags</text>
  <text x="177" y="66" class="bytes">2B</text>
  <!-- FileID 16B -->
  <rect x="194" y="38" width="72" height="34" class="shared"/>
  <text x="230" y="55" class="label">File ID</text>
  <text x="230" y="66" class="bytes">16B (UUID)</text>
  <!-- Nonce 12B+4B -->
  <rect x="266" y="38" width="72" height="34" class="gcm"/>
  <text x="302" y="55" class="label">Nonce+Pad</text>
  <text x="302" y="66" class="bytes">12B+4B pad</text>
  <!-- CiphertextLen 8B -->
  <rect x="338" y="38" width="52" height="34" class="shared"/>
  <text x="364" y="55" class="label">CT Len</text>
  <text x="364" y="66" class="bytes">8B (uint64)</text>
  <!-- KeyDesc 3B -->
  <rect x="390" y="38" width="52" height="34" class="shared"/>
  <text x="416" y="55" class="label">KeyDesc</text>
  <text x="416" y="66" class="bytes">ID+Len (3B)</text>
  <!-- Ciphertext -->
  <rect x="442" y="38" width="140" height="34" class="gcm"/>
  <text x="512" y="55" class="label">Ciphertext</text>
  <text x="512" y="66" class="bytes">CT Len bytes</text>
  <!-- GCM Tag -->
  <rect x="582" y="38" width="60" height="34" class="optional"/>
  <text x="612" y="55" class="label">GCM Tag</text>
  <text x="612" y="66" class="bytes">16B (tag)</text>
  <!-- Total note -->
  <text x="660" y="52" class="note">Total:</text>
  <text x="660" y="65" class="note">48+3+CT+16</text>

  <!-- Bracket for immutable header -->
  <line x1="40" y1="78" x2="390" y2="78" stroke="#0d47a1" stroke-width="1.2"/>
  <line x1="40" y1="75" x2="40" y2="81" stroke="#0d47a1" stroke-width="1.2"/>
  <line x1="390" y1="75" x2="390" y2="81" stroke="#0d47a1" stroke-width="1.2"/>
  <text x="215" y="92" text-anchor="middle" font-size="9" fill="#0d47a1" font-weight="bold">←— Immutable Header (48 bytes) — bound as GCM AAD —→</text>

  <!-- CBC row -->
  <text x="10" y="135" class="note" font-weight="bold">CBC:</text>
  <rect x="40" y="118" width="52" height="34" class="shared"/>
  <text x="66" y="135" class="label">Magic</text>
  <text x="66" y="146" class="bytes">SVLT (4B)</text>
  <rect x="92" y="118" width="34" height="34" class="shared"/>
  <text x="109" y="135" class="label">Ver</text>
  <text x="109" y="146" class="bytes">1B</text>
  <rect x="126" y="118" width="34" height="34" class="shared"/>
  <text x="143" y="135" class="label">Cipher</text>
  <text x="143" y="146" class="bytes">2=CBC</text>
  <rect x="160" y="118" width="34" height="34" class="shared"/>
  <text x="177" y="135" class="label">Flags</text>
  <text x="177" y="146" class="bytes">2B</text>
  <rect x="194" y="118" width="72" height="34" class="shared"/>
  <text x="230" y="135" class="label">File ID</text>
  <text x="230" y="146" class="bytes">16B (UUID)</text>
  <rect x="266" y="118" width="72" height="34" class="cbc"/>
  <text x="302" y="135" class="label">IV</text>
  <text x="302" y="146" class="bytes">16B (CSPRNG)</text>
  <rect x="338" y="118" width="52" height="34" class="shared"/>
  <text x="364" y="135" class="label">CT Len</text>
  <text x="364" y="146" class="bytes">8B (uint64)</text>
  <rect x="390" y="118" width="52" height="34" class="shared"/>
  <text x="416" y="135" class="label">KeyDesc</text>
  <text x="416" y="146" class="bytes">ID+Len (3B)</text>
  <rect x="442" y="118" width="140" height="34" class="cbc"/>
  <text x="512" y="135" class="label">Ciphertext + PKCS#7</text>
  <text x="512" y="146" class="bytes">CT Len bytes (multiple of 16)</text>
  <!-- No GCM tag in CBC -->
  <text x="612" y="135" class="note" fill="#880e4f">No Tag</text>
  <text x="612" y="148" class="note" fill="#880e4f">(no AEAD)</text>
  <text x="660" y="130" class="note">Total:</text>
  <text x="660" y="143" class="note">48+3+CT</text>

  <!-- .svkey layout -->
  <text x="10" y="200" class="note" font-weight="bold">.svkey:</text>
  <rect x="40" y="183" width="52" height="34" fill="#ede7f6" stroke="#4527a0" stroke-width="1.2"/>
  <text x="66" y="200" class="label">Magic</text>
  <text x="66" y="211" class="bytes">SVKY (4B)</text>
  <rect x="92" y="183" width="34" height="34" fill="#ede7f6" stroke="#4527a0" stroke-width="1.2"/>
  <text x="109" y="200" class="label">Ver</text>
  <text x="109" y="211" class="bytes">1B</text>
  <rect x="126" y="183" width="72" height="34" fill="#ede7f6" stroke="#4527a0" stroke-width="1.2"/>
  <text x="162" y="200" class="label">File ID</text>
  <text x="162" y="211" class="bytes">16B (UUID)</text>
  <rect x="198" y="183" width="34" height="34" fill="#ede7f6" stroke="#4527a0" stroke-width="1.2"/>
  <text x="215" y="200" class="label">Mode</text>
  <text x="215" y="211" class="bytes">1B</text>
  <rect x="232" y="183" width="90" height="34" fill="#ede7f6" stroke="#4527a0" stroke-width="1.2"/>
  <text x="277" y="200" class="label">DEK (AES-256)</text>
  <text x="277" y="211" class="bytes">32 bytes (CSPRNG)</text>
  <text x="340" y="200" class="note">= 54 bytes total</text>
  <text x="340" y="213" class="note">0600 permissions</text>

  <!-- Legend -->
  <rect x="460" y="183" width="12" height="12" fill="#e3f2fd" stroke="#0d47a1" stroke-width="1"/>
  <text x="476" y="193" class="note">Shared (GCM+CBC)</text>
  <rect x="560" y="183" width="12" height="12" fill="#e8f5e9" stroke="#2e7d32" stroke-width="1"/>
  <text x="576" y="193" class="note">GCM-specific</text>
  <rect x="640" y="183" width="12" height="12" fill="#fff9c4" stroke="#f57f17" stroke-width="1"/>
  <text x="656" y="193" class="note">CBC-specific</text>
  <rect x="460" y="200" width="12" height="12" fill="#fce4ec" stroke="#880e4f" stroke-width="1" stroke-dasharray="4,2"/>
  <text x="476" y="210" class="note">GCM auth tag only</text>
  <rect x="560" y="200" width="12" height="12" fill="#ede7f6" stroke="#4527a0" stroke-width="1"/>
  <text x="576" y="210" class="note">.svkey record</text>
</svg>
"""


def generate_f2_container_layout() -> Path:
    out = FIGURES_DIR / "F2_container_layout.svg"
    out.write_text(CONTAINER_SVG, encoding="utf-8")
    print(f"  F2 written: {out}")
    return out


# ---------------------------------------------------------------------------
# F3 — AES Performance Comparison (from real benchmark data)
# ---------------------------------------------------------------------------

def _load_summary() -> List[Dict]:
    rows = []
    with SUMMARY_CSV.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({
                "mode": row["mode"],
                "size_bytes": int(row["size_bytes"]),
                "operation": row["operation"],
                "mean_ms": float(row["mean_ms"]),
                "stdev_ms": float(row["sample_stdev_ms"]),
                "throughput": float(row["throughput_MiB_s"]),
            })
    return rows


def _load_raw() -> Dict:
    """Load all raw observations grouped by (mode, size, operation)."""
    data: Dict = {}
    with BENCHMARK_CSV.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = (row["mode"], int(row["size_bytes"]), row["operation"])
            ns = int(row["elapsed_ns"])
            data.setdefault(key, []).append(ns / 1e6)  # ms
    return data


def generate_f3_performance(raw_data: Dict, summary: List[Dict]) -> Path:
    if not HAS_MATPLOTLIB:
        out = FIGURES_DIR / "F3_performance_placeholder.txt"
        out.write_text("matplotlib not available; install it to generate F3.\n")
        return out

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle(
        "SecureVault AES-256-GCM vs AES-256-CBC Performance\n"
        "(Real observations, macOS arm64, 30 repetitions per configuration)",
        fontsize=12, fontweight="bold", y=0.98
    )

    size_labels = [SIZE_LABELS[s] for s in SIZES_ORDERED]
    x = range(len(SIZES_ORDERED))
    colors = {"gcm": "#2e7d32", "cbc": "#e65100"}
    width = 0.35

    for col, operation in enumerate(["encrypt", "decrypt"]):
        # -- Top row: mean latency bar chart with error bars --
        ax = axes[0][col]
        for i, mode in enumerate(["gcm", "cbc"]):
            means = [
                next(r["mean_ms"] for r in summary if r["mode"] == mode and r["size_bytes"] == s and r["operation"] == operation)
                for s in SIZES_ORDERED
            ]
            stdevs = [
                next(r["stdev_ms"] for r in summary if r["mode"] == mode and r["size_bytes"] == s and r["operation"] == operation)
                for s in SIZES_ORDERED
            ]
            offset = [-width/2, width/2][i]
            bars = ax.bar(
                [xi + offset for xi in x], means, width, color=colors[mode], alpha=0.85,
                label=f"AES-256-{mode.upper()}", yerr=stdevs, capsize=4, error_kw={"linewidth": 1}
            )
        ax.set_xlabel("Plaintext Size")
        ax.set_ylabel("Mean Latency (ms)")
        ax.set_title(f"Mean {operation.capitalize()} Latency ± 1σ")
        ax.set_xticks(list(x))
        ax.set_xticklabels(size_labels)
        ax.legend(fontsize=9)
        ax.grid(axis="y", alpha=0.3)
        ax.set_yscale("log")

        # -- Bottom row: box plots of raw observations --
        ax2 = axes[1][col]
        for size_idx, size in enumerate(SIZES_ORDERED):
            gcm_vals = raw_data.get(("gcm", size, operation), [])
            cbc_vals = raw_data.get(("cbc", size, operation), [])
            pos_base = size_idx * 3
            bp_gcm = ax2.boxplot(gcm_vals, positions=[pos_base + 0.6], widths=0.5,
                                  patch_artist=True, boxprops=dict(facecolor=colors["gcm"], alpha=0.7),
                                  medianprops=dict(color="white", linewidth=2),
                                  flierprops=dict(marker=".", markersize=3, alpha=0.5))
            bp_cbc = ax2.boxplot(cbc_vals, positions=[pos_base + 1.4], widths=0.5,
                                  patch_artist=True, boxprops=dict(facecolor=colors["cbc"], alpha=0.7),
                                  medianprops=dict(color="white", linewidth=2),
                                  flierprops=dict(marker=".", markersize=3, alpha=0.5))

        ax2.set_xticks([0.6 + i * 3 + 0.4 for i in range(len(SIZES_ORDERED))])
        ax2.set_xticklabels(size_labels)
        ax2.set_xlabel("Plaintext Size")
        ax2.set_ylabel("Latency (ms)")
        ax2.set_title(f"{operation.capitalize()} Latency Distribution (30 obs.)")
        ax2.set_yscale("log")
        ax2.grid(axis="y", alpha=0.3)
        gcm_patch = mpatches.Patch(color=colors["gcm"], alpha=0.85, label="AES-256-GCM")
        cbc_patch = mpatches.Patch(color=colors["cbc"], alpha=0.85, label="AES-256-CBC")
        ax2.legend(handles=[gcm_patch, cbc_patch], fontsize=9)

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    out = FIGURES_DIR / "F3_performance.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  F3 written: {out}")
    return out


# ---------------------------------------------------------------------------
# F4 — Tamper Behavior Comparison
# ---------------------------------------------------------------------------

def generate_f4_tamper_behavior() -> Path:
    if not HAS_MATPLOTLIB:
        out = FIGURES_DIR / "F4_tamper_placeholder.txt"
        out.write_text("matplotlib not available; install it to generate F4.\n")
        return out

    # Load security experiment results
    results = []
    with SECURITY_CSV.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            results.append(row)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 7))
    fig.suptitle(
        "SecureVault Tamper Detection Behavior: AES-256-GCM vs AES-256-CBC\n"
        "(Observed experimental outcomes — 6COSC033C CW1)",
        fontsize=12, fontweight="bold"
    )

    # Categorize results
    gcm_results = [r for r in results if r["mode"] == "GCM"]
    cbc_results = [r for r in results if r["mode"] == "CBC"]

    def result_color(r):
        if r["exception_type"] == "AuthenticationError":
            return "#2e7d32"
        if r["plaintext_published"] == "True" and r["plaintext_matches_original"] == "False":
            return "#e65100"
        if r["exception_type"] not in ("None", ""):
            return "#f9a825"
        return "#bdbdbd"

    def result_label(r):
        return {
            "#2e7d32": "Authentication rejected",
            "#e65100": "Corrupted plaintext returned",
            "#f9a825": r["exception_type"],
            "#bdbdbd": "Other outcome",
        }[result_color(r)]

    # GCM subplot
    ax1.set_title("AES-256-GCM: Integrity Protection", fontsize=11, fontweight="bold", color="#1b5e20")
    y_pos = range(len(gcm_results))
    bars = ax1.barh(
        y_pos,
        [1] * len(gcm_results),
        color=[result_color(r) for r in gcm_results],
        height=0.5,
        edgecolor="white"
    )
    ax1.set_yticks(list(y_pos))
    ax1.set_yticklabels([f"[{r['experiment_id']}] {r['tamper_target'].replace('_', ' ')}" for r in gcm_results], fontsize=10)
    ax1.set_xticks([])
    ax1.set_xlim(0, 1.4)
    for i, r in enumerate(gcm_results):
        ax1.text(1.05, i, result_label(r), va="center", fontsize=9, color=result_color(r))
    ax1.invert_yaxis()
    ax1.axvline(0, color="grey", linewidth=0.5)
    ax1.set_xlabel("")

    # CBC subplot
    ax2.set_title("AES-256-CBC: No Cryptographic Integrity", fontsize=11, fontweight="bold", color="#bf360c")
    y_pos2 = range(len(cbc_results))
    ax2.barh(
        y_pos2,
        [1] * len(cbc_results),
        color=[result_color(r) for r in cbc_results],
        height=0.5,
        edgecolor="white"
    )
    ax2.set_yticks(list(y_pos2))
    ax2.set_yticklabels([f"[{r['experiment_id']}] {r['tamper_target'].replace('_', ' ')}" for r in cbc_results], fontsize=10)
    ax2.set_xticks([])
    ax2.set_xlim(0, 1.4)
    for i, r in enumerate(cbc_results):
        ax2.text(1.05, i, result_label(r), va="center", fontsize=9,
                 color=result_color(r))
    ax2.invert_yaxis()

    # Legend
    detected = mpatches.Patch(color="#2e7d32", label="Authentication rejected in memory")
    corrupted = mpatches.Patch(color="#e65100", label="Corrupted plaintext returned in memory")
    exc_patch = mpatches.Patch(color="#f9a825", label="Exception raised (structural / padding)")
    fig.legend(handles=[detected, corrupted, exc_patch], loc="lower center", ncol=3, fontsize=9, bbox_to_anchor=(0.5, 0.01))

    plt.tight_layout(rect=[0, 0.06, 1, 0.95])
    out = FIGURES_DIR / "F4_tamper_behavior.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  F4 written: {out}")
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ensure_figures_dir()
    print("Generating SecureVault coursework figures...")
    print()

    print("F1 — Architecture diagram:")
    generate_f1_architecture()

    print("F2 — Container layout diagram:")
    generate_f2_container_layout()

    if HAS_MATPLOTLIB:
        print("F3 — Performance comparison (from real benchmark data):")
        try:
            raw = _load_raw()
            summary = _load_summary()
            generate_f3_performance(raw, summary)
        except FileNotFoundError as e:
            print(f"  SKIPPED: {e}")

        print("F4 — Tamper behavior comparison:")
        try:
            generate_f4_tamper_behavior()
        except FileNotFoundError as e:
            print(f"  SKIPPED: {e}")
    else:
        print("F3/F4 — Skipped (matplotlib not installed). Run: pip install matplotlib")

    print()
    print(f"All figures written to {FIGURES_DIR}/")


if __name__ == "__main__":
    main()
