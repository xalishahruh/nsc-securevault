# SecureVault

**Network Security and Cryptography (6COSC033C) — CW1 Practical Project**

SecureVault is a Python file-encryption application implementing and comparing **AES-256-GCM** (authenticated encryption) and **AES-256-CBC** (confidentiality only) for secure file storage, aligned with the academic research question:

> *To what extent do AES-GCM and AES-CBC differ in their security properties, ciphertext-integrity protection, tamper-handling behavior, and encryption/decryption performance when implemented for secure file storage across varying file sizes?*

---

## Contents

1. [Requirements and Installation](#1-requirements-and-installation)  
2. [Encrypting and Decrypting Files](#2-encrypting-and-decrypting-files)  
3. [End-to-End Demonstration](#3-end-to-end-demonstration)  
4. [Security Limitations](#4-security-limitations)  
5. [Running Automated Tests](#5-running-automated-tests)  
6. [Security Experiments](#6-security-experiments)  
7. [Benchmarks](#7-benchmarks)  
8. [Statistical Analysis](#8-statistical-analysis)  
9. [Generating Figures](#9-generating-figures)  
10. [Architecture and File Formats](#10-architecture-and-file-formats)  
11. [Coursework Evidence Locations](#11-coursework-evidence-locations)

---

## 1. Requirements and Installation

**Python:** 3.10 or newer (uses PEP 604 union annotations)  
**Operating systems:** macOS, Linux (tested on macOS 26.6.2, arm64)  
**Dependencies:** `cryptography >= 41.0.0` (AES primitives via OpenSSL)

```bash
# Clone repository
git clone https://github.com/xalishahruh/nsc-securevault
cd nsc-securevault

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install application and test dependencies
pip install -e ".[test]"

# Optional: install matplotlib for figure generation
pip install matplotlib
```

**Verify installation:**
```bash
securevault --help
# or
python -m securevault --help
```

---

## 2. Encrypting and Decrypting Files

### Encrypt with AES-256-GCM

```bash
securevault encrypt \
  --mode gcm \
  --input my_document.pdf \
  --output my_document.svlt \
  --key-output my_document.svkey
```

### Encrypt with AES-256-CBC

```bash
securevault encrypt \
  --mode cbc \
  --input my_document.pdf \
  --output my_document_cbc.svlt \
  --key-output my_document_cbc.svkey
```

### Decrypt

```bash
# GCM — with optional mode enforcement
securevault decrypt \
  --input my_document.svlt \
  --output my_document_recovered.pdf \
  --key-file my_document.svkey \
  --require-mode gcm

# CBC
securevault decrypt \
  --input my_document_cbc.svlt \
  --output my_document_cbc_recovered.pdf \
  --key-file my_document_cbc.svkey \
  --require-mode cbc
```

> **CBC warning:** The CLI always prints a warning when decrypting CBC files:
> `AES-CBC provides confidentiality only; it provides NO inherent authenticity or integrity verification.`

### Inspect container metadata (no key required)

```bash
securevault inspect --input my_document.svlt
```

### Flags

| Flag | Description |
|------|-------------|
| `--overwrite` | Permit overwriting an existing output file (default: fail safely) |
| `--require-mode gcm\|cbc` | Reject containers that do not match the expected cipher mode |

---

## 3. End-to-End Demonstration

The following reproduces the complete demonstration using the included sample file.

```bash
# 0. Create sample file
python3 -c "
content = b'SecureVault Demo File\n' + bytes(range(1024 - 22))
open('demo/samples/sample.txt', 'wb').write(content)
"

# 1. Original SHA-256
shasum -a 256 demo/samples/sample.txt

# 2. GCM encryption
securevault encrypt --mode gcm \
  --input demo/samples/sample.txt \
  --output demo/gcm/sample.svlt \
  --key-output demo/gcm/sample.svkey

# 3. GCM inspect
securevault inspect --input demo/gcm/sample.svlt

# 4. GCM decrypt
securevault decrypt \
  --input demo/gcm/sample.svlt \
  --output demo/gcm/sample_recovered.txt \
  --key-file demo/gcm/sample.svkey

# 5. Exact-byte verification (hashes must match)
shasum -a 256 demo/samples/sample.txt demo/gcm/sample_recovered.txt

# 6. CBC encryption
securevault encrypt --mode cbc \
  --input demo/samples/sample.txt \
  --output demo/cbc/sample.svlt \
  --key-output demo/cbc/sample.svkey

# 7. CBC decrypt
securevault decrypt \
  --input demo/cbc/sample.svlt \
  --output demo/cbc/sample_recovered.txt \
  --key-file demo/cbc/sample.svkey

# 8. Exact-byte verification (hashes must match)
shasum -a 256 demo/samples/sample.txt demo/cbc/sample_recovered.txt

# 9. Wrong key failure
securevault decrypt \
  --input demo/gcm/sample.svlt \
  --output /tmp/wrong_key_out.bin \
  --key-file demo/cbc/sample.svkey
# Expected: Error [InvalidKeyError]: Key file ID ... does not match ...

# 10. No-clobber protection
securevault encrypt --mode gcm \
  --input demo/samples/sample.txt \
  --output demo/gcm/sample.svlt \
  --key-output demo/gcm/sample.svkey
# Expected: Error [FileExistsSecurityError]: Destination file already exists
```

**Observed outputs (Nov 2026, macOS arm64):**

| Step | Expected Result | Observed |
|------|----------------|----------|
| SHA-256 original = GCM-recovered | Identical hashes | ✓ `5c3fcab4b8760ac3...` |
| SHA-256 original = CBC-recovered | Identical hashes | ✓ `5c3fcab4b8760ac3...` |
| Wrong key | `InvalidKeyError` | ✓ Exit 2, no output file |
| Duplicate encrypt | `FileExistsSecurityError` | ✓ Exit 2, existing files preserved |

---

## 4. Security Limitations

### AES-256-GCM

- Provides authenticated encryption (AEAD): confidentiality + integrity + authenticity.
- The 48-byte immutable container header is bound as GCM authenticated associated data (AAD).
- Any modification to ciphertext, authentication tag, or header bytes raises `AuthenticationError` before any plaintext is released.
- Nonce uniqueness is maintained by generating a fresh 12-byte CSPRNG nonce per encryption.
- **Nonce reuse across different keys is harmless; nonce reuse with the same key would be catastrophic.** The current design generates a fresh 256-bit DEK per encryption, making same-key reuse structurally impossible.

### AES-256-CBC

- Provides **confidentiality only**. There is **no inherent ciphertext integrity or authenticity**.
- **PKCS#7 padding validity is NOT cryptographic authentication.** A tampered ciphertext that happens to produce valid padding will be accepted silently.
- IV modification corrupts only the first 16-byte plaintext block; all subsequent blocks decrypt correctly.
- Ciphertext modification in block *n* garbles block *n* and predictably bit-flips block *n+1*.
- Applications requiring integrity over CBC-encrypted data must add external authentication (HMAC, MAC).

### Key Management

- DEKs are 256-bit values generated by the OS CSPRNG (`os.urandom`) once per encryption.
- The `.svkey` file stores the DEK in plaintext. It must be treated as a secret — stored separately from the container, with file permissions 0600.
- Key file and container carry a shared 16-byte file ID and cipher-mode identifier. The key provider verifies both before decryption.
- **There is no password-based key derivation or key-wrapping in the current implementation.** The external key design is an engineering baseline; vault key lifecycle with Argon2id/AES-KWP is a future milestone.

### File System Safety

- All output is staged in a temporary file, flushed with `os.fsync`, and published via `os.link()` for atomic, exclusive creation.
- Existing destination files are never overwritten unless `--overwrite` is explicitly passed.
- Symlinks in source or destination paths are rejected.
- Failed GCM authentication never publishes plaintext to disk.

---

## 5. Running Automated Tests

```bash
# Full test suite (110 tests)
python -m pytest -v

# Targeted module tests
python -m pytest tests/test_gcm.py tests/test_cbc.py -v
python -m pytest tests/test_tamper.py -v
python -m pytest tests/test_safe_io.py -v
python -m pytest tests/test_functional_e2e.py -v
python -m pytest tests/test_benchmark_modes.py tests/test_benchmark_statistics.py -v
```

**Test coverage:**

| Module | Tests | Key Scenarios |
|--------|-------|---------------|
| `test_gcm.py` | 12 | GCM roundtrip, tampering, key validation |
| `test_cbc.py` | 10 | CBC roundtrip, padding, key validation |
| `test_container.py` | 14 | Header layout, boundary enforcement, malformed rejection |
| `test_tamper.py` | 10 | GCM auth failure, CBC lack-of-integrity, mode downgrade |
| `test_functional_e2e.py` | 12 | Byte-exact roundtrip across sizes and formats |
| `test_safe_io.py` | 20 | No-clobber, atomic publication, cleanup, concurrent writers |
| `test_key_provider.py` | 8 | Key association, mode mismatch, key record format |
| `test_key_recoverability.py` | 10 | Mandatory key destination, overwrite rejection |
| `test_benchmark_modes.py` | 5 | Observation count, CSV schema, parameter validation |
| `test_benchmark_statistics.py` | 9 | Statistical summary, comparison, error handling |

---

## 6. Security Experiments

Implements 10 controlled security experiments:

- **GCM-01 to GCM-05:** Ciphertext modification, tag modification, header/AAD tamper, wrong key, container truncation.
- **CBC-01 to CBC-05:** Ciphertext modification, IV modification, wrong key, container truncation, controlled non-last-block corruption.

```bash
# Run all experiments
python -m experiments.security_experiments

# Custom output path
python -m experiments.security_experiments --output my_results.csv
```

Results are written to `experiments/results/security_outcomes.csv`.  
See `experiments/SECURITY_EXPERIMENTS.md` for the full report with observed vs. expected outcomes.

**Key results:**
- GCM: 5/5 tamper cases detected — plaintext never published after any tamper.
- CBC: 0/5 cryptographic detections — corrupted plaintext accepted silently in 3/5 cases.

---

## 7. Benchmarks

Benchmarks compare AES-256-GCM and AES-256-CBC encryption and decryption across three file sizes:

| Metric | Value |
|--------|-------|
| Sizes | 1 KiB, 1 MiB, 10 MiB |
| Modes | AES-256-GCM, AES-256-CBC |
| Operations | Encrypt, Decrypt |
| Repetitions | 30 per configuration |
| Total observations | 360 |
| Timing function | `time.perf_counter_ns()` |
| Timing scope | Cryptographic API call only (excludes setup, I/O, verification) |
| Warm-up | 2 untimed cycles per configuration |
| Order | Alternated per repetition (even: enc→dec; odd: dec→enc) |
| Fixture | Deterministic (SHA-256 chain from fixed seed) |
| Keys/IVs | Fresh CSPRNG per repetition |

```bash
# Run benchmark (overwrites existing results CSV)
python -m benchmarks.benchmark_modes

# Results written to benchmarks/results/benchmark_results.csv
```

**Performance summary (actual run, macOS arm64, Nov 2026):**

| Size | Operation | GCM mean (ms) | CBC mean (ms) | GCM vs CBC |
|------|-----------|--------------|--------------|------------|
| 1 KiB | Encrypt | 0.00184 | 0.00463 | **−60.2%** |
| 1 KiB | Decrypt | 0.00184 | 0.00394 | **−53.3%** |
| 1 MiB | Encrypt | 0.179 | 0.992 | **−82.0%** |
| 1 MiB | Decrypt | 0.182 | 0.215 | **−15.5%** |
| 10 MiB | Encrypt | 2.035 | 10.254 | **−80.2%** |
| 10 MiB | Decrypt | 2.131 | 2.536 | **−16.0%** |

> GCM is 50–82% faster on encryption (hardware AES-GCM acceleration on arm64).  
> GCM is 15–53% faster on decryption.  
> Performance varies by platform, CPU frequency scaling, and thermal conditions.

---

## 8. Statistical Analysis

```bash
python -m benchmarks.summarize \
  --input benchmarks/results/benchmark_results.csv \
  --output-dir benchmarks/results/
```

Produces:
- `benchmarks/results/results_summary.csv` — mean, median, stdev, min, max, throughput per configuration
- `benchmarks/results/mode_comparison.csv` — GCM vs CBC mean difference percentage per size/operation

The summarizer rejects malformed data, missing observations, inconsistent metadata, and non-contiguous repetition indices. It never modifies raw input or generates synthetic results.

---

## 9. Generating Figures

```bash
# Install matplotlib first (requires network access)
pip install matplotlib

# Generate F1–F4
python figures/generate_figures.py
```

Produces:
- `figures/F1_architecture.svg` — SecureVault architecture diagram
- `figures/F2_container_layout.svg` — `.svlt` and `.svkey` binary format layout
- `figures/F3_performance.png` — GCM vs CBC latency comparison (from real data)
- `figures/F4_tamper_behavior.png` — Tamper detection outcome comparison

---

## 10. Architecture and File Formats

### Cryptographic Contract

| Property | AES-256-GCM | AES-256-CBC |
|---|---|---|
| Confidentiality | ✓ | ✓ |
| Integrity (Ciphertext) | ✓ 128-bit GHASH tag | ✗ None |
| Header Binding | ✓ 48-byte header as AAD | ✗ None |
| Fresh DEK | ✓ 32-byte CSPRNG per op | ✓ 32-byte CSPRNG per op |
| Nonce/IV | 12-byte CSPRNG nonce | 16-byte CSPRNG IV |
| Padding | None | PKCS#7 (block-aligned) |

### .svlt Container Format (v1)

```
Offset  Bytes  Field
0       4      Magic: 'SVLT'
4       1      Version: 1
5       1      Cipher ID: 1=GCM, 2=CBC
6       2      Flags (reserved, 0)
8       16     File ID (random UUID)
24      16     IV/Nonce slot (12-byte GCM nonce + 4 zero pad; 16-byte CBC IV)
40      8      Ciphertext length (uint64 big-endian)
-- Header end (48 bytes, used as GCM AAD) --
48      1      Key protection ID: 0=External
49      2      Key record length (uint16 big-endian)
51      var    Key record (0 bytes for external)
51+    CT      Ciphertext bytes
51+CT  16      GCM authentication tag (GCM only; absent in CBC)
```

### .svkey Format (External Key Record)

```
Offset  Bytes  Field
0       4      Magic: 'SVKY'
4       1      Version: 1
5       16     File ID (must match container file_id)
21      1      Cipher ID: 1=GCM, 2=CBC (must match container)
22      32     DEK (AES-256 data encryption key)
-- Total: 54 bytes, 0600 permissions --
```

---

## 11. Coursework Evidence Locations

| Requirement | Evidence | Location |
|-------------|----------|----------|
| AES-GCM implementation | `crypto/gcm.py` | `src/securevault/crypto/gcm.py` |
| AES-CBC implementation | `crypto/cbc.py` | `src/securevault/crypto/cbc.py` |
| File encryption/decryption | `file_service.py` | `src/securevault/file_service.py` |
| CLI | `cli.py` | `src/securevault/cli.py` |
| Container format | `container.py` | `src/securevault/container.py` |
| Key management | `key_provider.py` | `src/securevault/key_provider.py` |
| GCM tamper detection | Tests + experiments | `tests/test_tamper.py`, `experiments/` |
| CBC no-integrity | Tests + experiments | `tests/test_tamper.py`, `experiments/SECURITY_EXPERIMENTS.md` |
| Security experiment CSV | Experiment outcomes | `experiments/results/security_outcomes.csv` |
| Benchmark raw CSV | 360 real observations | `benchmarks/results/benchmark_results.csv` |
| Statistical summary | Per-config stats | `benchmarks/results/results_summary.csv` |
| GCM vs CBC comparison | Percentage difference | `benchmarks/results/mode_comparison.csv` |
| Architecture diagram | F1 | `figures/F1_architecture.svg` |
| Container layout | F2 | `figures/F2_container_layout.svg` |
| Performance figure | F3 | `figures/F3_performance.png` |
| Tamper behavior figure | F4 | `figures/F4_tamper_behavior.png` |
| Full test suite | 110 passing tests | `python -m pytest -v` |

---

## Platform Limitations

- Hard-link atomic publication (`os.link()`) may not be supported on all networked or cross-device filesystems. The system fails closed rather than falling back to non-atomic writes.
- Benchmark timing reflects in-memory cryptographic API performance, not full file I/O throughput.
- CBC-03 wrong-key PaddingError is probabilistic (~255/256 cases). Do not treat it as authentication.
- The `.svkey` DEK is stored in plaintext; physical security of the key file is the user's responsibility.
- The 256 MiB ciphertext size limit (`MAX_CIPHERTEXT_SIZE`) is a bounded-memory implementation constraint, not a cryptographic limit.
