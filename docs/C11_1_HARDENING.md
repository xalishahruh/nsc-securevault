# C11.1 final security hardening

Baseline `8c44e1e444e4f9562a468dd9d19a1e8b02105ff8`. Review inputs included the C01–C06 legacy register (L01–L14), the C07–C10 architecture and review records, the C11 requirements matrix, the 23 November Notion compliance index, the original CW1 descriptor, and the frozen local format references. Notion still labels C10/C11 pending in that snapshot. This register uses the tested Git checkpoints for implementation status and the descriptor for coursework requirements.

## Findings register

| Finding and severity | Disposition | Control and evidence | Residual risk or boundary |
|---|---|---|---|
| H01 — Interrupted standalone write could leave a staged key/plaintext file and fail to explicitly close its descriptor. Medium confidentiality and reliability impact. | **FIXED** | Context-managed file, cleanup after catchable interruption or I/O failure, and Git exclusions for both standalone and managed output staging. `test_c111_interrupted_staging_closes_and_removes_temporary_file`; `git check-ignore` on both prefixes. | Abrupt process death and unlink failure can leave owner-only files. Operators must review abandoned work after a failed run. |
| H02 — Turning warnings into errors could report a successful standalone publication as failed after its destination was already visible. Medium reliability impact. | **FIXED** | Preserve the actual outcome after logging the cleanup warning. `test_c111_warning_as_error_preserves_published_success`. | A failed cleanup can still leave a staging alias. Published data remains intact. |
| H03 — Malformed SVLT and SVKY magic was echoed in CLI diagnostics. Medium confidentiality impact. | **FIXED** | Fixed-text diagnostics without input bytes. `test_c111_cli_rejects_bad_magic_without_echoing_input_bytes`. | File paths and permitted nonsecret metadata remain visible in diagnostics. |
| H04 — Length-compliant predictable passphrases were accepted. Medium offline-guessing exposure. | **MITIGATED** | Local whole-value checks reject a small set of obvious guesses after trimming and case folding for comparison only, plus single-character repetition. Tests exercise init, change and restore. Existing unlock and KEK rotation retain exact password bytes. | This is a small list plus a repetition check. There is no breach corpus or guarantee of adequate entropy. Argon2id raises the cost of offline guesses. |
| H05 — Recovery copied entire archive buffers unnecessarily before AEAD processing. Medium resource pressure. | **FIXED** | Use the library's [combined AES-GCM ciphertext/tag buffer](https://cryptography.io/en/44.0.0/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM) and a view on restore. Exact-cap restore/rejection tests, an independently generated C11 archive, and a full-size round trip verify unchanged framing and authentication. | Whole-buffer processing remains bounded and can still use several times the 256 MiB payload ceiling. Memory-constrained targets remain unverified. |
| Legacy L01–L02/L04/L07, C07 and C08-01 — overwrite/data loss, bounds, key association, demo safety, and authenticated generation commits. Previously high/critical where applicable. | **FIXED** | Prior fixes remain in ancestry. Re-ran standalone, manifest, vault and recovery tests. Commit verification authenticates every referenced GCM payload before CURRENT replacement. | Standalone output assumes trusted parent directories. Managed storage assumes cooperating writers in a trusted process. |
| Legacy L05–L06/L08, MC3/MC7 — experiment labels, unsupported security claims, and reproducibility. High for assessment accuracy. | **FIXED** | Current runner separates authentication, parser rejection and CBC padding outcomes. README names the reviewed branch and distinguishes GCM authentication from CBC unpadding. Historical summary CSVs recompute byte for byte. | Fresh timings depend on the host and library. Report interpretation and clean-package reproduction remain separate acceptance gates. |
| CBC, history and revocation — inherent or explicitly out of threat scope. | **ACCEPTED LIMITATION** | Tests demonstrate CBC corruption returning plaintext and a complete older generation reopening. Password change preserves the KEK, and retained keyrings and snapshots preserve their respective historical access. | CBC vault ciphertext remains unauthenticated. Valid generations can be replayed. Rotation cannot revoke copied keys or archives. Python does not promise secret erasure. |
| Crash cleanup, staging and retry — residual medium operational risk. | **MITIGATED** | C08–C11 subprocess tests exercise staging, published dependencies, CURRENT replacement, recovery promotion and subsequent successful retry. Invalid or absent CURRENT never selects staging. | Process death can leave inactive artifacts, unused recovery keys or a standalone orphaned key. Cleanup is manual after confirming which generation and outputs are active. |
| Windows, network filesystems, sudden power loss, and independent extracted-ZIP acceptance (L10/L11). | **UNVERIFIED** | Verified on local macOS POSIX storage with no-follow paths, directory descriptors, hard links, advisory writer locks, same-filesystem replacement and directory sync calls. | No claim about Windows ACLs, network filesystem semantics, power-loss durability or clean lab-machine installation. |

## Exact key and IV/nonce lifecycle

- Standalone encryption and managed import draw an independent 256-bit DEK and either a 96-bit GCM nonce or an unpredictable 128-bit CBC IV from the OS CSPRNG for every encryption. Neither high-level workflow accepts a caller-supplied encryption key or IV/nonce. Standalone CLI and managed-import tests sample multiple encryptions and inspect the actual records.
- GCM DEK rotation first verifies the prior tag, then draws a fresh DEK and nonce for a new encryption. KEK rotation changes wrapping records and preserves immutable headers, payloads and tags. Password change likewise does not invoke payload encryption.
- SVMF draws its own independently generated 256-bit data key and 96-bit nonce per sealing. Each recovery archive uses its own 256-bit recovery key and independent 96-bit nonce. Restore copies the authenticated SVLT bytes without payload re-encryption, even when restoring the same archive twice. It seals a fresh SVMF and wraps the recovered KEK with a new password and salt.
- The same key and nonce matter together for GCM. For independent uniform draws, the probability that a specific pair of encryptions with fresh 256-bit keys and 96-bit nonces repeats both is 2⁻³⁵². This is a pairwise estimate conditional on the CSPRNG, not a guarantee, a tag forgery bound, or an estimate of the impact of key compromise. CBC requires an unpredictable IV and has no payload authentication.

## MC3, MC6 and MC7 acceptance cross-check

| Descriptor gate | Evidence and remaining work |
|---|---|
| MC3: modes, CSPRNG and reuse prevention, justified design and threat response | Lifecycle above, CLI and managed key/IV tests, GCM AAD and tag rejection tests, and documented protection boundaries. Explain the threat-to-control reasoning in the assessed report. |
| MC6: trusted library, two working modes, mode-specific processing, normal desktop environment | cryptography/OpenSSL AES-256; actual GCM authentication before file output; CBC PKCS#7 and block boundary tests; exact recovery via standalone CLI and full managed lifecycle. Independent clean desktop installation is still open. |
| MC7: three sizes, repeated encrypt and decrypt, aggregates/throughput, negative test and reproducible evidence | 360 observations, 12 summaries, six mode comparisons, preserved history, fresh tamper run, pinned dependencies and instructions. The final ZIP and report must tie results to the exact assessed commit and verified environment. |

This checkpoint stops before C12. Final package verification and academic report acceptance remain open.

## Boundary and compatibility measurements

On macOS arm64, an isolated synthetic GCM vault produced an SVRA file of exactly 268,435,500 bytes (256 MiB authenticated payload plus 44 bytes of framing). Restore and subsequent extraction recovered 268,434,754 bytes, and SHA-256 matched the original payload. Backup took 0.87s and restore 1.05s on that run. Process peak RSS across import, backup, restore and extract was 1,606.1 MiB. This is a whole-run peak and does not isolate backup or restore allocations. Automated tests also reject a physically oversized sparse archive before authentication and reject a payload one byte over a scaled limit.

A separate process loaded code exported at the exact C11 baseline, wrote an SVRA backup, and C11.1 restored that archive and recovered the original GCM payload byte for byte. No historical artifacts were changed.

## Verification record

Platform: macOS 26.6.2 arm64, Python 3.15.2, cryptography 50.0.2, OpenSSL backend 4.0.3, pytest 9.2.0. All commands used the repository virtual environment.

- Baseline `python -m pytest -q`: 301 passed in 44.60s.
- `python -m compileall -q src benchmarks experiments tests figures scripts`: exit 0.
- `python -m pytest -q -k c111`: 14 passed, 301 deselected in 3.22s.
- `python -m pytest -q tests/test_safe_io.py tests/test_container.py tests/test_key_provider.py tests/test_keyring.py tests/test_manifest.py tests/test_tamper.py tests/test_vault.py tests/test_recovery.py`: 229 passed in 39.07s.
- Final `python -m pytest -q`: 315 passed in 41.03s.
- `python -m benchmarks.benchmark_modes --output "$RUN/fresh.csv" --repeats 30`: 360 new observations in 1.79s. `benchmarks.summarize` generated 12 summaries and six comparisons. Both historical summaries recomputed byte for byte.
- `python -m experiments.security_experiments --output "$RUN/security.csv"`: four GCM authentication rejections, two parser rejections, one observed CBC padding error and three CBC corrupted plaintext returns. `python -O scripts/run_demo.py` completed all ten steps. Evidence outputs were isolated under `/tmp/securevault-c111.PpZAMH` and the historical CSVs and figures remained unchanged.

No new critical or high-severity security defect was confirmed in the reviewed scope. Remaining actionable work for acceptance is independent clean-room reproduction, final packaging, and report-to-evidence verification.
