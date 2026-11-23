# SecureVault

**Network Security and Cryptography (6COSC033C) — CW1 Practical Project**

SecureVault is an engineering-grade Python file-encryption application implementing and empirically comparing **AES-256-GCM** (authenticated encryption) and **AES-256-CBC** (confidentiality only) for secure file storage. It addresses the coursework research question:

> *To what extent do AES-GCM and AES-CBC differ in their security properties, ciphertext-integrity protection, tamper-handling behavior, and encryption/decryption performance when implemented for secure file storage across varying file sizes?*

---

## Contents

1. [Requirements and Installation](#1-requirements-and-installation)  
2. [Encrypting and Decrypting Files](#2-encrypting-and-decrypting-files)  
3. [End-to-End Demonstration](#3-end-to-end-demonstration)  
4. [Cryptographic Properties and Security Analysis](#4-cryptographic-properties-and-security-analysis)  
5. [Automated Test Suite](#5-automated-test-suite)  
6. [Controlled Security Experiments](#6-controlled-security-experiments)  
7. [Performance Benchmarking and Reproduction](#7-performance-benchmarking-and-reproduction)  
8. [Statistical Analysis and Comparison](#8-statistical-analysis-and-comparison)  
9. [Report Figures](#9-report-figures)  
10. [Container Layout and Key Formats](#10-container-layout-and-key-formats)  
11. [Coursework Criteria Evidence Mapping (MC1–MC7)](#11-coursework-criteria-evidence-mapping-mc1mc7)  
12. [Evidence Inventory and Platform Limitations](#12-evidence-inventory-and-platform-limitations)

---

## 1. Requirements and Installation

- **Python Runtime:** Python 3.10 or newer (tested on Python 3.15.2, macOS arm64)
- **Supported Platforms:** macOS, Linux
- **Cryptographic Engine:** `cryptography >= 44.0.0` (backed by OpenSSL; Argon2id must be available)

```bash
# 1. Clone repository
git clone https://github.com/xalishahruh/nsc-securevault.git
cd nsc-securevault

# 2. Create and activate a clean virtual environment
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install SecureVault with test dependencies
pip install -e ".[test]"

# 4. Optional: install matplotlib for figure regeneration
pip install matplotlib
```

Verify CLI installation:
```bash
securevault --help
# or
python -m securevault --help
```

---

## 2. Encrypting and Decrypting Files

### Encrypt with AES-256-GCM (Authenticated Encryption)
```bash
securevault encrypt \
  --mode gcm \
  --input sample.txt \
  --output sample.svlt \
  --key-output sample.svkey
```

### Encrypt with AES-256-CBC (Confidentiality Only)
```bash
securevault encrypt \
  --mode cbc \
  --input sample.txt \
  --output sample_cbc.svlt \
  --key-output sample_cbc.svkey
```

### Decrypt Encrypted Containers
```bash
# Decrypt AES-GCM with explicit mode policy enforcement
securevault decrypt \
  --input sample.svlt \
  --output sample_recovered.txt \
  --key-file sample.svkey \
  --require-mode gcm

# Decrypt AES-CBC with explicit mode policy enforcement
securevault decrypt \
  --input sample_cbc.svlt \
  --output sample_cbc_recovered.txt \
  --key-file sample_cbc.svkey \
  --require-mode cbc
```

> **CBC Security Warning:** Whenever AES-CBC is decrypted, the CLI prints an explicit warning:
> `[WARNING] Decrypted using AES-CBC. AES-CBC provides confidentiality only; it provides NO inherent authenticity or integrity verification.`

### Inspect Container Metadata (No Key Required)
```bash
securevault inspect --input sample.svlt
```
Displays non-secret header fields: magic, version, cipher mode, file UUID, IV/nonce (hex), ciphertext length, and key protection type.

### Command-Line Policy Flags
| Flag | Behavior |
|------|----------|
| `decrypt --overwrite` | Permits replacing an existing plaintext destination. The ciphertext and key cannot be output destinations. |
| `--require-mode gcm\|cbc` | Enforces caller-expected cipher mode; rejects container on mismatch to prevent cipher downgrade. |

---

## 3. End-to-End Demonstration

A complete 10-step demonstration is scripted in `scripts/run_demo.py` and can be executed with:
```bash
python scripts/run_demo.py
```

### Demonstration Steps and Expected Behaviors:
1. **Input File Selection:** 1,024-byte deterministic sample payload (`demo/samples/sample.txt`), baseline SHA-256 recorded.
2. **GCM Encryption:** Generates fresh 256-bit DEK and 12-byte nonce; outputs `.svlt` container and 54-byte `.svkey`.
3. **GCM Decryption:** Verifies 128-bit GCM authentication tag and header AAD prior to releasing plaintext.
4. **Exact-Byte Verification (GCM):** SHA-256 hash comparison confirms exact byte-for-byte recovery.
5. **CBC Encryption:** Generates fresh 256-bit DEK and unpredictable 16-byte IV; applies PKCS#7 padding.
6. **CBC Decryption:** Validates PKCS#7 unpadding and issues an explicit integrity limitation warning.
7. **Exact-Byte Verification (CBC):** SHA-256 hash comparison confirms exact byte-for-byte recovery.
8. **Wrong-Key Handling:** Mismatched key rejected (`InvalidKeyError`, exit code 2); zero plaintext written.
9. **Tampered Container Handling (GCM):** Modified authentication tag rejected (`AuthenticationError`, exit code 2); zero plaintext written.
10. **Existing-Output Preservation:** Duplicate encryption destination without `--overwrite` fails closed (`FileExistsSecurityError`, exit code 2); existing file preserved.

---

## 4. Cryptographic Properties and Security Analysis

### AES-256-GCM (Galois/Counter Mode)
- **Security Goal:** Authenticated Encryption with Associated Data (AEAD) providing confidentiality, ciphertext integrity, and origin authenticity.
- **Key & Nonce Lifecycle:** Fresh 256-bit DEK via `os.urandom(32)` per encryption operation. Fresh 96-bit CSPRNG nonce via `os.urandom(12)`.
- **Nonce Collision Analysis:** With 96-bit random nonces, birthday collision probability reaches $2^{-32}$ after approximately $2^{48}$ encryptions under the same key. SecureVault enforces a fresh random 256-bit DEK per file encryption, preventing multiple encryptions under any single key and neutralizing cross-file nonce collision risks.
- **Header Binding (AAD):** The 48-byte immutable container header (magic, version, cipher ID, flags, file UUID, nonce, ciphertext length) is cryptographically bound as GCM Authenticated Associated Data (AAD). Any modification to header metadata invalidates the 128-bit GCM authentication tag.
- **Authentication Guarantee:** Tag forgery probability is bounded by $2^{-128}$ under standard cryptographic assumptions. Decryption strictly validates the authentication tag before writing or returning plaintext.

### AES-256-CBC (Cipher Block Chaining)
- **Security Goal:** Confidentiality only against chosen-plaintext attacks (IND-CPA), conditioned on an unpredictable initialization vector (IV).
- **Integrity Limitation:** AES-CBC provides **no inherent integrity or authenticity**. Modifying a ciphertext block predictably alters plaintext bits in the subsequent block.
- **Padding Semantics:** PKCS#7 padding aligns plaintext to 16-byte block boundaries. **Valid padding does not guarantee authenticity.** A random corrupted final block has approximately a $1/256$ probability of ending in `0x01` (valid padding). When non-last ciphertext blocks are modified, the final block padding remains entirely intact, and decryption silently succeeds while returning corrupted plaintext (empirically confirmed in experiment `CBC-05`).

### Safe File Publication (Atomic No-Clobber)
- File writes stage data into owner-restricted temporary files (`0600`), flush buffers, and call `os.fsync`.
- Publication uses `os.link()` to achieve exclusive, atomic destination creation on supported filesystems. If the destination exists, `FileExistsSecurityError` is raised. The implementation never falls back to an unsafe overwriting replace when `overwrite=False`.

---

## 5. Automated Test Suite

The pytest suite covers functional operations, security boundaries, container parsing, and statistical calculations:

```bash
# Run the complete test suite
python -m pytest -v
```

### Test Suite Structure

- `tests/test_gcm.py`: AES-GCM round-trips across edge sizes, wrong-key rejection, ciphertext/tag/AAD tamper detection.
- `tests/test_cbc.py`: AES-CBC round-trips, PKCS#7 padding boundaries, corrupted IV/ciphertext behavior.
- `tests/test_container.py`: Binary `.svlt` v1 header serialization, strict field validation, truncation and malformed size rejection.
- `tests/test_tamper.py`: Negative security scenarios, GCM header/tag rejection, CBC bit-flip corruption without authentication, cipher mode downgrade prevention.
- `tests/test_functional_e2e.py`: End-to-end file encryption/decryption across diverse file formats (PDF, JPEG, MP4, TXT) and payload boundaries (0B, 1B, 15B, 16B, 17B, 31B, 32B, 64B, 1KiB, 64KiB).
- `tests/test_safe_io.py`: Exclusive staging, `os.link` atomic creation, owner permissions (`0600`), symlink rejection, concurrent writer mutual exclusion.
- `tests/test_key_provider.py`: External `.svkey` record parsing, file ID association checks, cipher mode validation.
- `tests/test_key_recoverability.py`: Mandatory key destination enforcement, rollback safety, refusal to unlink keys on container publication failure.
- `tests/test_keyring.py`: Argon2id bounds, SVKR layout and authentication, and AES-KWP file key associations.
- `tests/test_security_experiment_output.py`: Distinct authentication and structural outcomes, and preservation of existing evidence files.
- `tests/test_benchmark_modes.py`: Benchmark matrix schema, 360-observation verification, parameter validation, artifact preservation.
- `tests/test_benchmark_statistics.py`: Statistical metric verification, formula correctness, strict validation of corrupted/incomplete datasets.

---

## 6. Controlled Security Experiments

The controlled experiment runner (`experiments/security_experiments.py`) executes 10 defined tamper scenarios comparing GCM and CBC.

```bash
# Write new security experiment evidence; existing CSVs are never overwritten.
python -m experiments.security_experiments --output /tmp/securevault-security-outcomes.csv
```

### Summary of Observed Outcomes:

| Experiment ID | Mode | Target Element | Specific Modification | Expected Outcome | Observed Outcome | Plaintext returned in memory? | Authentication rejected? |
|---|---|---|---|---|---|---|---|
| **GCM-01** | GCM | Ciphertext | Flip byte at offset 51 | `AuthenticationError` | `AuthenticationError` | **No** | **Yes** |
| **GCM-02** | GCM | Auth Tag | Flip last byte of tag | `AuthenticationError` | `AuthenticationError` | **No** | **Yes** |
| **GCM-03** | GCM | Header (AAD) | Flip `file_id` byte in header | `AuthenticationError` | `AuthenticationError` | **No** | **Yes** |
| **GCM-04** | GCM | Key Material | Random 32-byte DEK | `AuthenticationError` | `AuthenticationError` | **No** | **Yes** |
| **GCM-05** | GCM | Container Length | Truncate container by 50% | `MalformedContainerError` | `MalformedContainerError` | **No** | **No** (structural rejection) |
| **CBC-01** | CBC | Ciphertext | Flip byte in block 1 | Corrupted plaintext | Corrupted plaintext accepted | **Yes** | **No** |
| **CBC-02** | CBC | IV | Flip byte in IV slot | Corrupted block 0 | Corrupted block 0 accepted | **Yes** | **No** |
| **CBC-03** | CBC | Key Material | Random 32-byte DEK | `PaddingError` | `PaddingError` (probabilistic) | **No** | **No** (unreliable) |
| **CBC-04** | CBC | Container Length | Truncate container by 50% | `MalformedContainerError` | `MalformedContainerError` | **No** | **No** (structural rejection) |
| **CBC-05** | CBC | Non-last block CT | Controlled 3-block corruption | Valid PKCS#7 padding | Corrupted plaintext accepted | **Yes** | **No** |

Filesystem publication is exercised separately by the CLI demo and file service tests. Full analysis and discussion available in `experiments/SECURITY_EXPERIMENTS.md`.

---

## 7. Performance Benchmarking and Reproduction

### Experimental Design
- **Algorithms:** AES-256-GCM vs AES-256-CBC
- **Payload Sizes:** 1 KiB (1,024 B), 1 MiB (1,048,576 B), 10 MiB (10,485,760 B)
- **Operations:** Encryption and Decryption (timed separately)
- **Repetitions:** 30 per configuration = **360 total timed observations**
- **Measurement Boundary:** Timed interval strictly isolates the cryptographic primitive call using `time.perf_counter_ns()`. Key/nonce generation, synthetic fixture generation, valid decryption input staging, output verification, and disk I/O are strictly excluded.
- **Order Balancing:** Alternates encryption-first and decryption-first order across repetitions to mitigate systematic cache ordering bias.
- **Warm-Up:** 2 untimed warm-up cycles executed prior to measurement per configuration.

### How to Run a Fresh Benchmark (Preserving Existing Evidence)
To execute a fresh benchmark without overwriting the preserved baseline evidence in `benchmarks/results/`:

```bash
# 1. Run benchmark into a fresh directory
python -m benchmarks.benchmark_modes --output /tmp/fresh_run/benchmark_results.csv --repeats 30

# 2. Run statistical summarizer on the fresh data
python -m benchmarks.summarize \
  --input /tmp/fresh_run/benchmark_results.csv \
  --output-dir /tmp/fresh_run/summary/
```

### Baseline Performance Results (macOS arm64, OpenSSL 4.0.3 Backend):

| Payload Size | Operation | AES-256-GCM Mean (ms) | AES-256-CBC Mean (ms) | GCM Throughput (MiB/s) | CBC Throughput (MiB/s) | Difference (%) |
|---|---|---|---|---|---|---|
| **1 KiB** | Encrypt | 0.00184 ± 0.00015 | 0.00463 ± 0.00028 | 530.27 | 211.02 | **−60.20%** |
| **1 KiB** | Decrypt | 0.00184 ± 0.00032 | 0.00394 ± 0.00099 | 531.08 | 247.93 | **−53.32%** |
| **1 MiB** | Encrypt | 0.17885 ± 0.01549 | 0.99187 ± 0.02440 | 5,591.32 | 1,008.20 | **−81.97%** |
| **1 MiB** | Decrypt | 0.18193 ± 0.02629 | 0.21521 ± 0.03505 | 5,496.64 | 4,646.63 | **−15.46%** |
| **10 MiB** | Encrypt | 2.03487 ± 0.15125 | 10.25413 ± 0.10028 | 4,914.32 | 975.22 | **−80.16%** |
| **10 MiB** | Decrypt | 2.13081 ± 0.40742 | 2.53635 ± 0.11805 | 4,693.05 | 3,942.67 | **−15.99%** |

*Algorithmic Discussion:* GCM operates as a stream cipher using counter mode (CTR) for encryption and GHASH for authentication. CTR allows blocks to be computed independently, enabling pipelined block processing in OpenSSL. Conversely, CBC encryption is inherently sequential: each ciphertext block depends on the preceding ciphertext block as the XOR input for the next block, precluding parallel block encryption. During decryption, CBC blocks can be decrypted independently because all ciphertext blocks are known in advance, resulting in CBC decryption being significantly faster than CBC encryption.

---

## 8. Statistical Analysis and Comparison

The statistical summarizer (`benchmarks/summarize.py`) computes:
- $\text{mean\_ms} = \frac{\text{mean}(\text{elapsed\_ns})}{10^6}$
- $\text{sample\_stdev\_ms} = \frac{s(\text{elapsed\_ns})}{10^6}$ (unbiased sample standard deviation with $n-1$ denominator)
- $\text{throughput\_MiB\_s} = \frac{\text{payload\_bytes} / 2^{20}}{\text{mean\_duration\_seconds}}$
- $\text{difference\_percent} = 100 \times \frac{\text{mean}_{\text{GCM}} - \text{mean}_{\text{CBC}}}{\text{mean}_{\text{CBC}}}$

To summarize preserved evidence into a new directory:
```bash
python -m benchmarks.summarize \
  --input benchmarks/results/benchmark_results.csv \
  --output-dir /tmp/summary_eval/
```

---

## 9. Report Figures

All figures are located in `figures/` and reproducibly generated by `figures/generate_figures.py`:

```bash
python figures/generate_figures.py
```

- **`figures/F1_architecture.svg`**: Architecture diagram showing CLI layer, file service safety boundaries, cryptographic engines (GCM/CBC), container serialization, key provider, and atomic file publication.
- **`figures/F2_container_layout.svg`**: Binary format diagram showing the 48-byte immutable header (bound as GCM AAD), key descriptor, ciphertext payload, 16-byte GCM authentication tag, and 54-byte `.svkey` structure.
- **`figures/F3_performance.png`**: Mean latency bar charts (±1σ error bars) across sizes and log-scale box plots showing raw observation distributions.
- **`figures/F4_tamper_behavior.png`**: Comparative horizontal chart contrasting GCM's tamper detection against CBC's silent acceptance of corrupted data.

---

## 10. Container Layout and Key Formats

### `.svlt` Container Layout (v1)
```
Offset  Bytes  Field Description
0       4      Magic: b'SVLT'
4       1      Version: 1
5       1      Cipher ID: 1 = GCM, 2 = CBC
6       2      Flags: uint16 big-endian (0 = reserved)
8       16     File UUID: 16 random bytes
24      16     IV / Nonce Slot: 12-byte GCM nonce + 4 zero bytes; or 16-byte CBC IV
40      8      Ciphertext Length: uint64 big-endian
-- End of 48-byte immutable header (bound as GCM AAD) --
48      1      Key Protection ID: 0 = External (.svkey)
49      2      Key Record Length: uint16 big-endian (0 for external)
51      0      Key Record Bytes (empty in external mode)
51+     var    Ciphertext bytes (exact match to header ciphertext length)
End     16     GCM Authentication Tag: 16 bytes (present only for GCM; omitted in CBC)
```

### `.svkey` External Key Record (v1)
```
Offset  Bytes  Field Description
0       4      Magic: b'SVKY'
4       1      Version: 1
5       16     File UUID (must match container File UUID)
21      1      Cipher ID: 1 = GCM, 2 = CBC (must match container)
22      32     DEK: 256-bit AES data encryption key
-- Total: 54 bytes; permissions restricted to 0600 --
```

---

## 11. Coursework Criteria Evidence Mapping (MC1–MC7)

The table below maps the 7 assessment criteria (totaling 100 marks) from the 6COSC033C specification to the codebase, automated tests, and experimental evidence:

| Marking Criterion | Weight | Assessment Scope | Implementation & Evidence Mapping | Evidence Artifacts |
|---|---|---|---|---|
| **MC1: Introduction, security problem and scope** | **8 marks** | Context, motivation, scenario, research question, objectives and scope. | `README.md` (Sections 1–4) | Research question and secure file-storage scope are stated; arbitrary binary formats are a compatibility requirement. |
| **MC2: Cryptographic research and technical understanding** | **12 marks** | Relevant cryptographic research and authoritative standards, with cited comparison of GCM and CBC. | Coursework report references; `experiments/SECURITY_EXPERIMENTS.md` | Cite original standards and relevant literature; distinguish evidence from theoretical security claims. |
| **MC3: Design choices and security justification** | **15 marks** | Threat model, key/nonce/IV policy, format and storage decisions, justified security controls. | `src/securevault/container.py`<br>`src/securevault/crypto/`<br>`src/securevault/key_provider.py`<br>`figures/F1_architecture.svg`<br>`figures/F2_container_layout.svg` | Explain threat assumptions, trusted mode policy, GCM AAD and CBC's lack of authentication. |
| **MC4: Evaluation, critical discussion and conclusion** | **15 marks** | Interpret observed results, compare modes, explain limitations and answer the research question. | Coursework report; `experiments/SECURITY_EXPERIMENTS.md`<br>`figures/F3_performance.png`<br>`figures/F4_tamper_behavior.png` | Tie conclusions to measured results and observed tamper behavior; discuss validity threats and residual risks. |
| **MC5: Structure, presentation and referencing** | **5 marks** | Required structure, academic presentation, citations, formatting and word limit. | Final coursework report and references | Apply the assignment's formatting and referencing rules; this criterion is report presentation, not software tests. |
| **MC6: Practical: correct implementation** | **25 marks** | Functional AES-256-GCM and AES-256-CBC file encryption/decryption, key handling, error handling and runnable application. | `src/securevault/`<br>`scripts/run_demo.py`<br>`tests/test_functional_e2e.py` | Demonstrate working CLI, safe key association and byte-exact recovery; distinguish implemented C05 behavior from C06 key hierarchy APIs. |
| **MC7: Practical: testing, performance/security evidence and reproducibility** | **20 marks** | Reproducible test evidence, tamper analysis, repeated encryption/decryption measurements at multiple sizes, statistics and interpretation. | `tests/`<br>`experiments/security_experiments.py`<br>`benchmarks/benchmark_modes.py`<br>`benchmarks/summarize.py`<br>`benchmarks/results/`<br>`experiments/results/` | Raw evidence supports both negative security tests and multi-size performance analysis; preserve committed CSVs and write new runs to fresh paths. |

---

## 12. Evidence Inventory and Platform Limitations

### Preserved Evidence Artifacts:
- **Raw Benchmark CSV:** `benchmarks/results/benchmark_results.csv` (360 individual timed observations with environment metadata)
- **Statistical Summary CSV:** `benchmarks/results/results_summary.csv` (12 configuration rows with mean, median, stdev, throughput)
- **Mode Comparison CSV:** `benchmarks/results/mode_comparison.csv` (6 comparative rows with GCM vs CBC percentage differences)
- **Security Outcomes CSV:** `experiments/results/security_outcomes.csv` (10 empirical tamper cases and outcomes)
- **Security Experiments Report:** `experiments/SECURITY_EXPERIMENTS.md` (Detailed methodology, analysis, and conclusions)
- **Architecture Diagram:** `figures/F1_architecture.svg`
- **Container Layout Diagram:** `figures/F2_container_layout.svg`
- **Performance Figure:** `figures/F3_performance.png`
- **Tamper Behavior Figure:** `figures/F4_tamper_behavior.png`
- **Dependency Snapshot:** `requirements-lock.txt`
- **Demonstration Script:** `scripts/run_demo.py`

### Platform Limitations:
- **Hard-Link Publication:** `os.link()` requires source and destination to reside on the same filesystem volume. If atomic hard-linking is unsupported by the filesystem (e.g. cross-device links or certain network filesystems), SecureVault fails closed with `FileServiceError` rather than risking non-exclusive replacement.
- **Timing Boundary:** Benchmark measurements capture in-memory cryptographic API duration calling the OpenSSL backend. They do not measure physical storage disk I/O or full file streaming overhead.
- **Key Storage Boundary:** Standalone commands use external `.svkey` records, which require protected storage. The managed vault uses password-protected SVKR records and wrapped file keys. The legacy audit register records local KDF measurements and pending platform validation.

## 13. Managed vault (C08)

On POSIX, initialize a new vault directory and import a file:

```bash
securevault vault init --root ./vault
securevault vault add --root ./vault --input sample.bin
securevault vault list --root ./vault
securevault vault inspect --root ./vault
securevault vault extract --root ./vault --file-id FILE_ID --output recovered.bin --require-mode gcm
```

Choose a strong passphrase. Commands prompt without echo and unlock for one command. `vault unlock` verifies credentials and the active inventory. For a process-local session in Python, call `Vault.unlock(password)` and then `Vault.lock()` when finished. Imports default to GCM. Use `--mode cbc` only when you intend to use the unauthenticated comparison mode. Extraction refuses to overwrite a destination.

Use a local filesystem that supports hard links, directory syncing, POSIX file locking, and atomic same-filesystem replacement. Use a root path with no symbolic link components and keep recovered files outside the vault. See [architecture conformance](docs/ARCHITECTURE_CONFORMANCE.md#c08-managed-vault) for the exact transaction checks and crash test scope.

### Managed key lifecycle (C09)

```bash
securevault vault change-password --root ./vault
securevault vault rotate-kek --root ./vault
securevault vault rotate-dek --root ./vault --file-id FILE_ID
```

Password change and KEK rotation preserve file payload bytes. File DEK rotation authenticates and re-encrypts the selected GCM file. Previous generations remain available on disk, so old credentials and keys may still unlock retained history. See [key lifecycle conformance](docs/ARCHITECTURE_CONFORMANCE.md#c09-key-lifecycle) for the precise guarantees and limitations.
