# SecureVault (`nsc-securevault`)

A cryptographic file storage engine and experimental evaluation of **AES-256-GCM** (authenticated encryption with associated data) versus **AES-256-CBC** (confidentiality-only encryption with PKCS#7 padding).

Coursework project for Network Security and Cryptography (6COSC033C), Scenario 1.

---

## 1. Quick Start & Installation

### Prerequisites
- Python 3.9+ (tested on Python 3.15)
- macOS, Linux, or Windows

### Environment Setup
```bash
# 1. Create a clean virtual environment
python3 -m venv .venv

# 2. Activate the virtual environment
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install dependencies and the package
pip install cryptography pytest
pip install -e .
```

---

## 2. CLI Usage Examples

### Encrypt a file (AES-256-GCM)
```bash
python -m securevault encrypt --mode gcm --input sample.bin --output sample.svlt --key-output sample.svkey
```

### Encrypt a file (AES-256-CBC)
```bash
python -m securevault encrypt --mode cbc --input sample.bin --output sample_cbc.svlt --key-output sample_cbc.svkey
```

### Inspect container metadata without decrypting
```bash
python -m securevault inspect --input sample.svlt
```

### Decrypt a container with mode enforcement
```bash
# GCM with required mode policy
python -m securevault decrypt --input sample.svlt --output recovered.bin --key-file sample.svkey --require-mode gcm

# CBC mode
python -m securevault decrypt --input sample_cbc.svlt --output recovered_cbc.bin --key-file sample_cbc.svkey --require-mode cbc
```

---

## 3. Automated Test Suite

Run the full automated test matrix (74 passing tests):
```bash
python -m pytest -v
```

### Test Coverage Highlights
- `FUNC-01 / FUNC-02`: Byte-for-byte roundtrip on edge-case lengths (0B, 1B, 15B, 16B, 17B, 31B, 32B, 64B, 1KiB, 64KiB)
- `FUNC-03`: Arbitrary binary compatibility (PDF, JPEG, MP4, TXT)
- `KEY-01 / KEY-02`: Fresh 32-byte CSPRNG DEKs per operation, file-ID and mode mismatch rejection
- `AUTH-01`: GCM tampered ciphertext, header (AAD), nonce, and tag rejection with zero plaintext output
- `AUTH-02`: CBC lack of integrity demonstrated (bit flips produce undetected corrupted plaintext or padding errors)
- `FMT-01 / FMT-02`: Strict `.svlt` v1 header, flags, lengths, and boundary enforcement
- `MODE-01`: Prevention of mode reinterpretation / downgrade attacks
- `IO-01 / IO-02`: Safe staging, no-clobber guarantees, exclusive creation, owner-restricted permissions (0600)

---

## 4. Cryptographic Contract & Formats

| Property | AES-256-GCM | AES-256-CBC |
|---|---|---|
| **Ciphertext Integrity** | Cryptographic 128-bit tag verified before plaintext release | **None inherent** (padding valid != authentic) |
| **Header Binding** | Exact 48-byte immutable header bound as AAD | Unauthenticated |
| **DEK Lifecycle** | Fresh CSPRNG 32-byte key per encryption operation | Fresh CSPRNG 32-byte key per encryption operation |
| **IV / Nonce** | Fresh 12-byte nonce (4 zero-padded in IV slot) | Fresh 16-byte unpredictable IV |
| **Padding** | None (stream-like counter mode) | PKCS#7 (16-byte block alignment) |

- `.svlt` (Container v1): 48-byte immutable header + 3-byte key descriptor + optional key record + ciphertext + (16-byte tag if GCM).
- `.svkey` (External Dev Key): 54-byte record: `SVKY` (4B) + version (1B) + `file_id` (16B) + `cipher_id` (1B) + `DEK` (32B). Mode and file ID are checked against the container before decryption.

## 5. AES Benchmark and Statistical Analysis

The benchmark requires Python 3.10 or newer (the source uses PEP 604 union
annotations). Install the project and its test extra in a virtual environment.

Run the raw benchmark with:

```bash
python -m benchmarks.benchmark_modes
```

The default matrix has 3 sizes (1 KiB, 1 MiB, 10 MiB), 2 modes, 2 operations,
and 30 repetitions: 360 observations. The raw CSV contains one row per timed
operation and records mode, operation, size, zero-based repeat, elapsed ns,
Python/OS/CPU/backend versions, run parameters, and timing boundary.

Analyze an existing raw CSV with:

```bash
python -m benchmarks.summarize --input PATH --output-dir PATH
```

The output directory receives `results_summary.csv` (12 mode/size/operation
rows) and `mode_comparison.csv` (6 size/operation rows). Existing output files
are rejected; raw input is never changed. CSV publication stages and flushes
the file before exclusive hard-link publication, and removes the temporary
file after success or failure. Filesystems without hard-link support fail
safely instead of falling back to a potentially clobbering write.

The metric is **in-memory cryptographic API execution time**. Each timed
interval contains only the public encryption or decryption API call, including
its internal allocation, CBC padding/unpadding, and GCM authentication work.
Fixture/key/IV/nonce generation, valid decryption-input preparation, output
verification, warm-ups, and CSV I/O are outside timed intervals. Keys and
nonces are fresh per operation; encryption and decryption order alternates by
repeat. This does not measure hardware AES instruction latency or end-to-end
file encryption. Scheduler activity, memory allocation, caches, CPU frequency,
thermal state, and platform differences can affect observations.

The summarizer rejects malformed headers/rows, missing or duplicate records,
unsupported modes/sizes/operations, nonpositive timings, incomplete matrices,
noncontiguous repetition IDs, inconsistent environment metadata, and
inconsistent repetition parameters. It does not drop outliers or fill missing
trials. At least two repetitions are required for sample standard deviation.

For elapsed times in ns, the summary reports:

- `mean_ms = mean(elapsed_ns) / 1,000,000`; median, min and max are also in ms.
- `sample_stdev_ms = statistics.stdev(elapsed_ns) / 1,000,000` (denominator `n−1`).
- `throughput_MiB_s = (size_bytes / 1,048,576) / (mean(elapsed_ns) / 1,000,000,000)`.
  This is payload size divided by mean operation duration, not mean trial throughput.
- `difference_percent = 100 * (mean_GCM - mean_CBC) / mean_CBC`.
  Negative means GCM has a lower mean duration; positive means higher.

The pipeline summarizes supplied observations only. It does not generate or
claim experimental results; no final evidence run is implied by these commands.

