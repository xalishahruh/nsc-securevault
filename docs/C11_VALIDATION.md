# C11 security validation

Baseline C10 commit `2613f53c40c41ad41532cb34e318a36665fc8fb5`. Scope includes the assessed standalone AES comparison and the supplementary managed vault. The original CW1 descriptor and 23 November Notion compliance assessment were cross-checked. The descriptor assigns 25 marks to MC6, 20 to MC7, and 55 across MC1–MC5.

## Requirements and evidence

| Requirement | Executed evidence | Boundary |
|---|---|---|
| MC3/MC6: CSPRNG AES-256, mode parameters, systematic IV/nonce reuse prevention | `test_c11_each_standalone_cli_encryption_generates_a_new_key_and_iv` samples four fresh CLI processes per mode and checks the stored keys, IV/nonce lengths, block-aligned CBC expansion, file/key associations and exact recovery. `encrypt_file` and the managed encryption path generate a DEK and IV/nonce internally for every encryption. | No encrypt option accepts a reused DEK or IV/nonce. Random sampling illustrates the design and cannot prove collision impossibility. |
| MC6/MC7: both AES modes, wrong-key rejection, malformed data and tamper handling | `test_functional_e2e.py`, `test_container.py`, `test_gcm.py`, `test_cbc.py`, `test_tamper.py`, `test_safe_io.py`; real CLI demo rerun. | GCM verifies before output publication. CBC PKCS#7 adds padding and can detect invalid padding. Valid padding carries no integrity assurance. |
| MC3/MC6: trusted managed storage and no partial generation activation | `test_manifest.py` and `test_vault.py` cover malformed authenticated manifests, wrong keys, substituted objects and wrapped keys, symlinks, hard links, traversal, writer contention and CURRENT-last publication. | Tests use cooperating writers and isolated local POSIX storage. |
| DEK rotation at transaction boundaries | `test_c11_dek_rotation_process_exit_keeps_complete_generation` stops an independent process after staging the manifest and object, after publishing the object, keyring and manifest, before CURRENT replacement, immediately after replacement, and after the root directory sync. Each case checks the active object ID, reads both recovered files and performs a subsequent rotation. | Process exits on the tested system establish old-or-new behavior at these boundaries. Power-loss durability and other filesystems remain unverified. |
| Lifecycle and recovery | `test_c11_complete_lifecycle_and_operations_after_restore` initializes, adds both modes, changes password, rotates KEK and GCM DEK, backs up, restores without the old password, recovers exact bytes, then adds, rotates and extracts a new file. `test_recovery.py` covers wrong keys, malformed/truncated/oversized archives, missing dependencies, substitution, aliased keys, stale staging and interrupted recovery. | CBC payloads remain unauthenticated in vault storage. Restore activates only a fully verified destination. |
| Rollback and historical keys | `test_c11_rollback_of_complete_historical_generation_is_possible` confirms that a genuinely retained older generation can be reopened with its historical password. Existing negative pointer tests cover absent or malformed generations. | Historical retention helps recovery and does not revoke previous passwords or keys. There is no trusted monotonic state. |
| Managed password creation and compatibility | `test_c11_password_policy_applies_only_when_setting_password`, `test_c11_legacy_short_password_can_unlock_rotate_kek_and_upgrade`, and recovery policy tests. | Init, change and restore require 15 Unicode characters, a non-whitespace character, and a maximum of 1,024 UTF-8 bytes. Existing unlock and KEK rotation still accept the stored password bytes. |
| MC7: repeated timings, statistics and tamper evidence | Fresh run of 360 observations, three sizes, two modes, two directions and 30 repeats. Historical summary/comparison recomputed byte for byte. Fresh security experiments distinguish authentication, structural and padding outcomes. | Timing includes mode API work like padding, tag processing and internal allocation. It excludes disk and vault transaction costs. Preserve the historical CSVs and figures. |

## Findings and disposition

| Finding | Severity | Fix or disposition | Residual risk |
|---|---|---|---|
| One-byte or whitespace-only passwords could be set in managed workflows. | Medium | Enforce the new-password policy at initialization, password change and recovery restore. The length floor takes guidance from [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html#passwords). That guidance is for centrally verified passwords and serves here as a design reference. No composition rules or normalization changes. | Length alone cannot establish entropy. There is no compromised-password screening. Argon2id increases guessing cost, but stolen keyrings still permit offline guesses. Historic short credentials remain readable so operators can migrate. Python does not guarantee secret erasure. |
| Full DEK-rotation crash coverage and integrated recovery evidence were missing. | Medium | Added the eight process-exit cases and full lifecycle test. | Abandoned private work can remain after abrupt exit. Sudden power loss and Windows/network filesystems have not been accepted. |
| README nonce estimate, general tag bound and API timing description were misleading. | High for coursework accuracy | Corrected the claims and added real CLI evidence for the fresh-key design. Clarified the benchmark boundary without modifying collected observations. | Measurements apply to this recorded platform and library. Fresh samples cannot establish a mathematical uniqueness guarantee or universal performance ranking. |
| Default GitHub clone selected a branch without the benchmark and recovery work. | High for MC6/MC7 reproducibility | README selects the C11 branch and uses the pinned dependency snapshot. | C12 must pin the final SHA and complete an independent clean install from the extracted submission package. |

## Verification and C12 gate

Local environment: macOS 26.6.2 arm64, Python 3.15.2, cryptography 50.0.2, OpenSSL backend 4.0.3, pytest 9.2.0. Commands used the repository virtual environment.

- Baseline `python -m pytest -q`: 280 passed in 32.65s.
- `python -m compileall -q src benchmarks experiments tests figures scripts`: exit 0.
- `python -m pytest -q -k c11`: 21 passed, 280 deselected in 9.08s.
- `python -m pytest -q tests/test_container.py tests/test_tamper.py tests/test_manifest.py tests/test_safe_io.py tests/test_vault.py tests/test_recovery.py tests/test_key_recoverability.py`: 172 passed in 38.78s.
- `python -m pytest -q`: 301 passed in 39.27s.
- `python -m benchmarks.benchmark_modes --output "$RUN/fresh.csv" --repeats 30`: 360 observations in 2.37s. `benchmarks.summarize` produced 12 fresh summaries and six comparisons. Running it on the committed raw CSV reproduced both historical output CSVs byte for byte.
- `python -m experiments.security_experiments --output "$RUN/security.csv"`: four GCM authentication rejections, two parser rejections, one CBC padding error and three CBC cases with corrupted plaintext returned.
- `python scripts/run_demo.py`: all 10 steps verified. The evidence runs used `/tmp/securevault-c11.VORRHo` for `$RUN` and left committed artifacts untouched.

C11 supplies evidence for the practical controls. Final independent clean-room installation, submission packaging, result-to-report traceability and academic report review remain C12 work. Use the exact final commit and include source, dependencies, instructions and supporting results in the descriptor's single ZIP. Keep the local knowledge base and all vault/key material outside the submission.
