# SecureVault

**Local file encryption and authenticated storage in Python**

SecureVault is a command-line application for encrypting files with **AES-256-GCM** or **AES-256-CBC**. It supports ordinary standalone file encryption and an optional password-unlocked vault with protected file keys, key rotation, and encrypted backup and recovery.

The two AES modes are deliberately available through the same application so their behaviour can be examined under comparable conditions. **GCM is the preferred mode** when file integrity matters: it authenticates ciphertext and selected container metadata. **CBC is retained for comparison** and provides confidentiality without inherent authentication.

The repository includes runnable tests, controlled tamper experiments, raw timing measurements, and scripts for reproducing the recorded findings. The implementation uses the maintained [`cryptography`](https://cryptography.io/) library rather than implementing AES itself.

## Features

- **AES-256-GCM:** authenticated encryption with a 96-bit nonce, 128-bit tag, and container-header authentication using additional authenticated data (AAD).
- **AES-256-CBC:** encryption with a random 128-bit IV and PKCS#7 padding, with an explicit warning about missing ciphertext authentication.
- **File encryption:** `.svlt` containers, per-file data-encryption keys (DEKs), strict format validation, and mode checks during decryption.
- **Safer file publication:** staged writes and exclusive destination creation by default; existing output files are not silently overwritten.
- **Managed vault (optional):** password-based unlocking with Argon2id, AES-KWP-wrapped keys, authenticated manifests, manual key rotation, and encrypted backup/recovery.
- **Reproducible evaluation:** automated tests, a ten-step CLI demonstration, repeated AES-mode benchmarks, and controlled ciphertext/key/IV tamper tests.

## Requirements and installation

The recorded verification environment was **macOS 26.6.2 (arm64), Python 3.15.2, `cryptography` 50.0.2, OpenSSL 4.0.3, and pytest 9.2.0**. The package declares Python 3.10+; equivalent behaviour and dependency compatibility have not been independently verified on every supported Python version or operating system. The managed vault specifically depends on local POSIX filesystem operations.

From the project root (either a Git checkout or an extracted source archive):

```bash
# Use the verified interpreter where available.
python3.15 -m venv ../securevault-venv
source ../securevault-venv/bin/activate

# Install the recorded dependencies and the application.
python -m pip install -r requirements-lock.txt
python -m pip install --no-build-isolation --no-deps .

# Confirm the entry point is available.
python -m pip check
python -m securevault --help
```

The `securevault` console command is also installed. The commands below use `python -m securevault` so that the selected virtual environment is explicit. The actual entry point is `src/securevault/__main__.py`; the root-level `main.py` is not used.

`requirements-lock.txt` is the dependency snapshot for the recorded environment. A network connection or a local Python package mirror may be needed to install its pinned packages. **Use the non-editable install shown above** for the integrated verification runner.

## Quick start: encrypt and decrypt a file

The repository contains a 1,024-byte synthetic sample at `demo/samples/sample.txt`. It includes binary values despite the `.txt` extension. Create a separate working directory for outputs:

```bash
mkdir -p ../securevault-example
cp demo/samples/sample.txt ../securevault-example/input.bin
```

### AES-256-GCM (recommended)

```bash
python -m securevault encrypt \
  --mode gcm \
  --input ../securevault-example/input.bin \
  --output ../securevault-example/gcm.svlt \
  --key-output ../securevault-example/gcm.svkey

python -m securevault decrypt \
  --input ../securevault-example/gcm.svlt \
  --key-file ../securevault-example/gcm.svkey \
  --output ../securevault-example/gcm-recovered.bin \
  --require-mode gcm

cmp ../securevault-example/input.bin ../securevault-example/gcm-recovered.bin
```

If the data, authenticated header, tag, or encryption key does not match, GCM decryption fails before plaintext is published. `cmp` exits successfully and prints nothing when the recovered file is byte-for-byte identical.

### AES-256-CBC (comparison mode)

```bash
python -m securevault encrypt \
  --mode cbc \
  --input ../securevault-example/input.bin \
  --output ../securevault-example/cbc.svlt \
  --key-output ../securevault-example/cbc.svkey

python -m securevault decrypt \
  --input ../securevault-example/cbc.svlt \
  --key-file ../securevault-example/cbc.svkey \
  --output ../securevault-example/cbc-recovered.bin \
  --require-mode cbc

cmp ../securevault-example/input.bin ../securevault-example/cbc-recovered.bin
```

CBC decryption can succeed even when modified ciphertext yields corrupted plaintext. Valid PKCS#7 padding is **not** an integrity check; SecureVault prints a warning when CBC is used for decryption.

To inspect a container's non-secret metadata:

```bash
python -m securevault inspect --input ../securevault-example/gcm.svlt
```

`inspect` validates structural metadata but **does not verify the GCM authentication tag**. The default file-output policy rejects an existing destination. Use new paths for repeated examples. The separate `.svkey` files contain **unencrypted raw DEKs**: keeping a key beside its container is convenient for this demonstration, not a secure real-world custody arrangement.

## Managed vault

The optional managed workflow adds password-protected key custody while retaining GCM and CBC as the underlying file encryption modes. It is designed for a trusted local POSIX environment; operations use hidden interactive password prompts, not command-line password arguments.

```bash
# Use a new path on a supported local filesystem.
python -m securevault vault init --root ../securevault-managed

python -m securevault vault add \
  --root ../securevault-managed \
  --input demo/samples/sample.txt \
  --mode gcm

python -m securevault vault list --root ../securevault-managed

# Replace FILE_ID with the identifier returned by add or list.
python -m securevault vault extract \
  --root ../securevault-managed \
  --file-id FILE_ID \
  --output ../securevault-example/vault-recovered.bin \
  --require-mode gcm
```

The managed key hierarchy uses a password-derived unlock key (Argon2id), a random key-encryption key (KEK), and AES-KWP-wrapped DEKs. Its manifest is authenticated with GCM. Other available actions are `vault inspect`, `vault unlock`, `vault change-password`, `vault rotate-kek`, `vault rotate-dek`, `vault backup`, and `vault restore`; see `python -m securevault vault --help` and the relevant action's `--help`.

Only GCM files support authenticated DEK rotation. Changing the vault password or rotating keys does **not** revoke retained historical copies or previously disclosed keys. For backup, the encrypted archive and its offline recovery key must be kept separately. Implementation details and storage assumptions are documented in [`docs/ARCHITECTURE_CONFORMANCE.md`](docs/ARCHITECTURE_CONFORMANCE.md).

## Running the tests

The application includes functional, boundary, security, concurrency, key-management, and recovery tests in `tests/`.

```bash
# Automated tests
python -m pytest -q

# Ten-step live demonstration of GCM/CBC round trips and failure handling
python -m scripts.run_demo
```

The recorded C12 verification passed **315 tests in 25.31 seconds** on the environment listed above. This is a historical result, not a prediction of execution time on another system. The demo checks exact-byte recovery, GCM tamper rejection, incorrect key handling, and preservation of existing outputs.

For a complete reproduction run, including the benchmark statistics, security experiments, and figures:

```bash
python -m scripts.verify_coursework \
  --output-dir ../securevault-verification-01
```

**The output directory must be new and outside the project tree.** Choose a new directory name for subsequent runs. This runner also requires the non-editable package installation shown earlier. It verifies the retained benchmark summaries against recalculated values and compares regenerated figures with the originals. See [`docs/C12_ACCEPTANCE.md`](docs/C12_ACCEPTANCE.md) for the recorded verification environment and outcomes.

## Benchmarking AES-GCM and AES-CBC

The retained performance experiment measures encryption and decryption for **1 KiB, 1 MiB, and 10 MiB** inputs. There are **30 timed repetitions per mode, size, and operation**: 360 observations overall. Two untimed warm-up cycles precede each configuration, and encrypt/decrypt order alternates across repeats.

`time.perf_counter_ns()` times the **in-memory cryptographic mode call**, including its tag or padding work. It excludes file I/O, key and IV/nonce generation, input preparation, and output checking. The standalone benchmark does not include the serialized container header as GCM AAD. It therefore measures mode-processing behaviour rather than complete file-storage latency.

### Recorded measurements

The following values come from [`benchmarks/results/results_summary.csv`](benchmarks/results/results_summary.csv). SD is the sample standard deviation of 30 observations.

| Input size | Operation | GCM mean ± SD (ms) | CBC mean ± SD (ms) |
| --- | --- | ---: | ---: |
| 1 KiB | Encrypt | 0.00184 ± 0.00015 | 0.00463 ± 0.00028 |
| 1 KiB | Decrypt | 0.00184 ± 0.00032 | 0.00394 ± 0.00099 |
| 1 MiB | Encrypt | 0.17885 ± 0.01549 | 0.99187 ± 0.02440 |
| 1 MiB | Decrypt | 0.18193 ± 0.02629 | 0.21521 ± 0.03505 |
| 10 MiB | Encrypt | 2.03487 ± 0.15125 | 10.25413 ± 0.10028 |
| 10 MiB | Decrypt | 2.13081 ± 0.40742 | 2.53635 ± 0.11805 |

At 10 MiB, GCM's mean encryption time was **80.16% lower** and its mean decryption time **15.99% lower** than CBC in the recorded run. These results are specific to one machine and software stack. Backend implementation, scheduling, caching, and other environmental effects were not isolated.

### Reproduce the measurements

Write fresh data to new destinations so the retained results are not changed:

```bash
python -m benchmarks.benchmark_modes \
  --output ../securevault-fresh-benchmark.csv \
  --repeats 30

python -m benchmarks.summarize \
  --input ../securevault-fresh-benchmark.csv \
  --output-dir ../securevault-fresh-summary
```

The summarizer produces `results_summary.csv` and `mode_comparison.csv`. Historical raw measurements and aggregates remain in `benchmarks/results/`.

## Security experiments

[`experiments/security_experiments.py`](experiments/security_experiments.py) performs **10 controlled modifications** involving keys, ciphertext, tags, headers, IVs, and container lengths. The retained results are in [`experiments/results/security_outcomes.csv`](experiments/results/security_outcomes.csv).

| Outcome | Recorded cases | Interpretation |
| --- | ---: | --- |
| GCM `AuthenticationError` with no plaintext returned | 4 | Ciphertext, tag, authenticated header, or key failed verification |
| Container parser rejection | 2 | Truncated inputs rejected structurally, before cryptographic verification |
| CBC `PaddingError` | 1 | Wrong key caused invalid padding in this run; this is not reliable authentication |
| CBC corrupted plaintext returned | 3 | Modified IV/ciphertext was accepted without integrity verification |

Run a new set of experiments without replacing the recorded results:

```bash
python -m experiments.security_experiments \
  --output ../securevault-new-security-outcomes.csv
```

The observed CBC wrong-key padding outcome is probabilistic; a fresh run can differ. In the historical CSV, the legacy field `plaintext_published` describes an **in-memory experiment result**, not necessarily a file written to disk. File-publication safety is tested separately by the application tests and demonstration. The test methods are explained in [`experiments/SECURITY_EXPERIMENTS.md`](experiments/SECURITY_EXPERIMENTS.md).

## Design and security boundaries

**Standalone files.** Each encryption generates an independent 256-bit DEK using the operating system CSPRNG, together with a fresh 96-bit GCM nonce or unpredictable 128-bit CBC IV. The `.svlt` container has a 48-byte immutable header; GCM authenticates its serialized bytes as AAD. A separate 54-byte `.svkey` record associates the raw DEK with the file ID and mode. The key record is *not encrypted*.

**File publication.** The service stages output, syncs it, and normally publishes to a previously unused destination without overwriting an existing file. The encrypted file and separate key file are **not published as one atomic transaction**. The container parser limits ciphertext size to 256 MiB; the implementation still processes full buffers in memory.

**Trust assumptions.** Security depends on the confidentiality of key material, correct nonce/IV generation, and a trusted executing host. A copied `.svkey` plus its matching container defeats standalone confidentiality. Random key/nonce generation minimizes accidental reuse risk but cannot mathematically rule out collisions. AES-CBC does not authenticate payloads even when its key is wrapped by the managed vault.

**Limits.** Neither mode alone detects replacement by an older valid encrypted file. Historical vault generations may remain readable. Secure deletion and reliable erasure of keys from Python process memory are not guaranteed. Managed vault crash tests were performed on a local POSIX filesystem; Windows, network storage, sudden power loss, and all possible adversarial filesystem conditions are outside the verified scope.

For the implementation and threat-to-control analysis, see [`docs/ARCHITECTURE_CONFORMANCE.md`](docs/ARCHITECTURE_CONFORMANCE.md) and [`docs/C11_1_HARDENING.md`](docs/C11_1_HARDENING.md).

## Repository structure

```text
src/securevault/              Application, CLI, AES modes, containers, key and vault handling
  crypto/gcm.py               AES-256-GCM encryption and authentication
  crypto/cbc.py               AES-256-CBC with PKCS#7 padding
  file_service.py             Standalone file operations and output publication
  key_provider.py             External key records
  key_wrap.py, keyring.py      AES-KWP and Argon2id key protection
  vault.py, recovery.py       Managed-vault operations and encrypted recovery
tests/                        Automated test suite
scripts/run_demo.py           Ten-step functional demonstration
scripts/verify_coursework.py  Integrated reproducibility checks
benchmarks/                   Benchmark runner, summarizer and retained CSV measurements
experiments/                  Tamper-test runner, methodology and retained outcomes
figures/                      Architecture, container, performance and tamper figures
docs/                         Technical design, hardening and validation records
requirements-lock.txt         Tested dependency versions
pyproject.toml                Package metadata and CLI entry point
```

The preserved benchmark CSVs, experiment outcomes, and generated figures provide an inspectable record of the original evaluation. Reproduction commands intentionally create **new outputs outside the source directory** so those records remain unchanged.
