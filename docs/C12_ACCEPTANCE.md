# C12 technical acceptance

The assessed implementation is the C11.1 tree at `230eeb22fb1b4423ae3e92224b82dc4a258f020a`. C12 freezes the application, tests, binary formats and historical evidence. The candidate's `acceptance/source.json` identifies the exact packaging commit and baseline. This is a technical candidate and the academic report is absent.

## Reproduce from the candidate

Extract `NSC.CW1.IDnumber.zip` into a new directory, enter the extracted root, and use Python 3.15.2 on the verified local macOS arm64 environment. The virtual environment and verification output belong outside the extracted tree.

```sh
shasum -a 256 -c PACKAGE_MANIFEST.sha256
python3.15 -m venv ../cw1-venv
p=../cw1-venv/bin/python
"$p" -m pip --isolated install -r requirements-lock.txt
"$p" -m pip --isolated install --no-build-isolation --no-deps .
"$p" -m scripts.verify_coursework --output-dir ../cw1-verification
```

The pinned dependencies are installed from `requirements-lock.txt`. The package is installed into the fresh environment's site-packages. The harness requires that installed location and deliberately writes fresh results outside the extracted source. Installing the pins requires access to their package index or an equivalent wheel mirror.

The harness runs `pip check`, `compileall`, standalone binary CLI checks, `python -O scripts/run_demo.py`, `python -m pytest -q`, the 30-repeat benchmark and summarizer, the historical summary recomputation, the ten security experiments and all four figure generators. It validates the benchmark matrix and calculations independently, including sample standard deviation and throughput. It compares SVG bytes and decoded PNG pixels. Read `acceptance/first-verification.log` and `acceptance/first-run/environment.json` for the captured run. Fresh timing observations and summaries are in that run folder. Historical data and figures remain at their original paths and retain their provenance.

The first extraction's separate, non-editable install passed `pip check` and compilation. On macOS 26.6.2 arm64, Python 3.15.2, cryptography 50.0.2 (OpenSSL backend 4.0.3), and pytest 9.2.0, it passed **315 tests in 25.31s**. The CLI recovered 7,939 binary bytes exactly in each mode. A wrong GCM key with valid association fields and a corrupted GCM tag each stopped publication. An IV alteration on CBC produced the expected corrupted plaintext. The ten-step CLI demonstration also completed.

The fresh benchmark produced 360 observations in 1.54s. All 12 summary rows and six mode comparisons were recomputed, and both historical aggregate CSVs matched byte for byte. The experiment runner reproduced four GCM authentication failures, two parser rejections, one observed CBC padding failure and three corrupted CBC plaintext returns. F1/F2 matched as SVG bytes and F3/F4 matched at the pixel level. Historical outputs were preserved.

## CW1 requirements to evidence matrix

Audited against the original 6COSC033C CW1 descriptor and the 23 November Notion compliance index. The descriptor governs assessed requirements. The five advanced vault checkpoints are supplementary to the AES comparison.

| Criterion | Evidence available in this candidate | Academic work or verification remaining |
|---|---|---|
| MC1 (8) — introduction, problem and scope | `README.md` describes local file storage and states the GCM/CBC research question. `docs/ARCHITECTURE_CONFORMANCE.md` and `figures/F1_architecture.svg` describe implemented boundaries. | Write the report introduction, assets, goals, scenario and threat assumptions. |
| MC2 (12) — cryptographic research | `src/securevault/crypto/gcm.py` and `cbc.py` implement the cited mechanisms. `tests/test_gcm.py`, `tests/test_cbc.py` and `experiments/SECURITY_EXPERIMENTS.md` provide technical material. | Complete original research and verified citations. Distinguish GCM authentication, CBC confidentiality, padding and misuse risks. |
| MC3 (15) — design and security justification | `docs/C11_1_HARDENING.md` records the OS CSPRNG, independent 256-bit key per encryption, 96-bit GCM nonce, 128-bit CBC IV and limits of probabilistic reuse prevention. `test_c11_each_standalone_cli_encryption_generates_a_new_key_and_iv` and `test_c111_managed_import_draws_independent_key_and_iv` exercise real generations. F1 and F2 explain the workflow and container. | Justify choices in the report and link threats, controls, tests and residual risks. |
| MC4 (15) — evaluation and discussion | `benchmarks/results/results_summary.csv`, `mode_comparison.csv`, F3, `experiments/results/security_outcomes.csv`, F4 and `acceptance/first-verification.log` support comparison. | Explain magnitudes, variance, applicability and confounders. The benchmark measures mode APIs, including processing inside them, outside disk I/O. Distinguish authentication failures, format rejection and accepted CBC corruption. |
| MC5 (5) — presentation and referencing | `REPORT_PLACEHOLDER.md` identifies the missing final report. The verified figures and supporting CSVs are included. | Replace placeholder with the seven-section report. Check the descriptor's word limit, typography, identifiers and Westminster-Harvard references. |
| MC6 (25) — practical implementation | `scripts.verify_coursework` exercises exact-byte recovery for arbitrary binary data in both modes, a same-association wrong GCM key, a modified GCM tag and CBC IV tamper. `tests/test_functional_e2e.py`, `test_gcm.py`, `test_cbc.py`, `test_tamper.py` and `test_safe_io.py` cover mode correctness, PKCS#7, authentication and publication. See `acceptance/first-verification.log`. | Include the exact source and concise essential extracts in the final submission. |
| MC7 (20) — testing, measurement and reproducibility | `requirements-lock.txt`, `README.md`, harness, raw and summarized CSVs and test/experiment logs. The harness verifies 360 observations across three input sizes, two modes and both directions, 12 summaries and six comparisons. It regenerates F1–F4 and rechecks the security outcomes. | Run the above after replacing the report placeholder and rebuilding the final ZIP. Preserve original observations and cite the correct evidence version. |

## Outstanding findings

| Severity | Finding and disposition |
|---|---|
| High — submission | The final academic report and student ID are absent. Replace the placeholder, confirm the submission format and academic-integrity acknowledgment, and use the actual student ID in the archive name. Recompute the manifest and verify the final ZIP. |
| Medium — portability | Reproduction here is on one macOS arm64 host. Validate on the intended lab environment if it differs. Managed storage requires local POSIX semantics. Windows, network filesystems and power-loss durability remain unverified. |
| Accepted practical limitations | CBC payloads remain unauthenticated. Valid older generations can be replayed. Retained keys and archives do not imply revocation. Python does not guarantee memory erasure. Archive handling is bounded and can still use substantial RAM. |
| Evidence interpretation | Systematic fresh generation mitigates nonce/IV reuse risk under the CSPRNG assumption. The timing scope is in memory and results are host-specific. Technical acceptance does not assign a coursework mark. |

The package manifest covers every payload file except the manifest itself. The outer SHA-256 and final extraction receipt accompany the candidate. The report placeholder and private-development exclusions are intentional review boundaries.
