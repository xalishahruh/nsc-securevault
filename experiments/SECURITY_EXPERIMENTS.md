# SecureVault — Security Experiment Report

**Course:** Network Security and Cryptography (6COSC033C) — CW1  
**Research Question:** To what extent do AES-GCM and AES-CBC differ in their security properties, ciphertext-integrity protection, tamper-handling behavior, and encryption/decryption performance when implemented for secure file storage across varying file sizes?  
**Experiment Date:** November 2026  
**Platform:** macOS 26.6.2 · arm64 · Python 3.15.2 · cryptography 50.0.2 · OpenSSL 4.0.3

---

## 1. Experimental Design

Security experiments use 512-byte in-memory byte fixtures derived from fixed constants (not random) for reproducibility. Each test modifies one specific structural or cryptographic element of a fresh container and records whether plaintext is published and what error (if any) is raised.

**Commands to reproduce:**
```bash
python -m experiments.security_experiments --output /tmp/securevault-security-outcomes.csv
```

CSV publication is atomic and refuses to replace an existing destination. Choose a new output path for each run; the committed `experiments/results/security_outcomes.csv` remains preserved.

---

## 2. GCM Experiments: Authenticated Encryption

> AES-256-GCM uses GHASH-based MAC computation over both the ciphertext and authenticated associated data (AAD). The 48-byte immutable container header is passed as AAD. The 128-bit authentication tag is verified before any plaintext is released.

| ID | Tamper Target | Expected | Observed | Plaintext Published |
|----|--------------|----------|----------|---------------------|
| GCM-01 | Ciphertext (1 byte) | AuthenticationError | **AuthenticationError** | **NO** |
| GCM-02 | GCM authentication tag (1 byte) | AuthenticationError | **AuthenticationError** | **NO** |
| GCM-03 | Immutable header / AAD (file_id byte) | AuthenticationError | **AuthenticationError** | **NO** |
| GCM-04 | Key material (wrong 32-byte DEK) | AuthenticationError | **AuthenticationError** | **NO** |
| GCM-05 | Container truncation | MalformedContainerError | **MalformedContainerError** | **NO** |

**GCM Result: 5/5 tamper cases detected. Plaintext never published after any tamper.**

### Key findings — GCM:
- **Ciphertext modification:** Any single-byte change produces a GHASH mismatch, raising `AuthenticationError` before any plaintext output.
- **Tag modification:** The GHASH tag covers the entire ciphertext; any change is immediately detected.
- **Header/AAD tamper:** The immutable header bytes are cryptographically bound to the ciphertext as GCM AAD. Any header modification — including structure fields like `file_id` — invalidates the authentication tag.
- **Wrong key:** A fresh 256-bit key produces a completely different GHASH; authentication fails unconditionally.
- **Truncation:** The container parser enforces exact structural sizes before cryptographic verification.

---

## 3. CBC Experiments: Confidentiality Only

> AES-256-CBC provides confidentiality but **no inherent integrity or authentication**. Successful decryption and valid PKCS#7 padding are **not** evidence that ciphertext has not been modified.

| ID | Tamper Target | Expected | Observed | Plaintext Published | Tamper Detected |
|----|--------------|----------|----------|---------------------|-----------------|
| CBC-01 | Ciphertext (1 byte, non-last block) | Corrupted plaintext | **Corrupted plaintext accepted** | **YES** | **NO** |
| CBC-02 | IV (1 byte) | Silently corrupted first block | **Silently corrupted first block** | **YES** | **NO** |
| CBC-03 | Key material (wrong 32-byte DEK) | PaddingError or corrupted output | **PaddingError raised** | NO | probabilistic |
| CBC-04 | Container truncation | MalformedContainerError | **MalformedContainerError** | NO | structural only |
| CBC-05 | Ciphertext (non-last block, controlled) | Corrupted plaintext, valid padding | **Corrupted plaintext accepted** | **YES** | **NO** |

**CBC Result: 1/5 cases detected (structural). Cryptographic integrity: 0/5.**

### Key findings — CBC:

**CBC-01 / CBC-05 (Ciphertext modification):**
In CBC mode, modifying a byte in ciphertext block *n* garbles the entire plaintext block *n* (pseudo-random bytes) but XOR-flips the corresponding bit in plaintext block *n+1* exactly. If the last block is unaffected, PKCS#7 padding remains valid and decryption succeeds silently — returning corrupted data without any error.

**CBC-02 (IV tamper):**
The IV XOR-feeds into the decryption of the first ciphertext block only. Flipping one IV bit flips exactly one bit in the corresponding position of the first plaintext block. All subsequent blocks are decrypted correctly. The corruption affects only 1 of 1024 bytes in the experiment (confirmed: 1 different byte). No error is raised.

**CBC-03 (Wrong key):**
A wrong 256-bit AES key produces garbled ciphertext in every block. The last block typically produces invalid PKCS#7 padding, raising `PaddingError`. **This is not authentication** — it is a probabilistic side effect of random-looking decryption output. Approximately 1 in 256 wrong-key attempts may produce a valid padding byte by chance.

**CBC-04 (Truncation):**
Structural parser detects length violation before any cryptographic operation. This is format-layer validation, not cryptographic integrity.

**CBC-05 (Controlled corruption — definitive demonstration):**
Using a 3-block plaintext and targeting the first ciphertext block, the experiment confirms that:
- The tampered block decrypts to pseudo-random garbage.
- The adjacent block receives a predictable bit-flip.
- The last block is untouched — PKCS#7 padding remains valid.
- **Result: corrupted plaintext returned with exit code 0 and no error.**

---

## 4. Summary and Security Conclusions

```
GCM: 5/5 tamper cases detected   — no plaintext ever published after any tamper
CBC: 0/5 cryptographic detections — plaintext published in 3/5 cases despite modification
```

| Property | AES-256-GCM | AES-256-CBC |
|---|---|---|
| Confidentiality | ✓ | ✓ |
| Ciphertext Integrity | ✓ Cryptographic 128-bit GHASH | ✗ None |
| Header Binding | ✓ Immutable header as AAD | ✗ None |
| Wrong Key Detection | ✓ Authentication failure | ~ Probabilistic padding error |
| IV/Nonce Tamper | ✓ Detected via GHASH | ✗ Silent first-block corruption |
| Tamper Before Plaintext Release | ✓ Always | ✗ Never (cryptographically) |

**Critical finding:** The statement "valid PKCS#7 padding proves authenticity" is **false**. CBC-05 demonstrates empirically that ciphertext can be modified in a way that preserves valid padding and returns corrupted plaintext without any error.

---

## 5. Reproduction Commands

```bash
# Install and configure (from repository root)
python -m venv .venv && .venv/bin/pip install -e .

# Run all security experiments without replacing committed evidence
python -m experiments.security_experiments --output /tmp/securevault-security-outcomes.csv

# Run with custom output path
python -m experiments.security_experiments --output my_results.csv

# View raw outputs
cat experiments/results/security_outcomes.csv
```

---

## 6. Important Limitations

- Experiments use in-memory containers; they do not test file-system atomicity.
- CBC-03 wrong-key detection is probabilistic; PaddingError is likely but not guaranteed.
- Structural truncation detection (GCM-05, CBC-04) uses the parser's size validation, not cryptographic verification.
- Experiments test a 512-byte fixture; GCM authentication behavior is identical regardless of plaintext size.
- The CBC-05 controlled-corruption success depends on targeting a non-last ciphertext block; last-block modification is more likely to produce invalid PKCS#7 and a PaddingError.
