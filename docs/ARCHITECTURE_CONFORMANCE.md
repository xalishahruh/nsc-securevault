# SecureVault Architecture Conformance

## C06 key hierarchy

**Baseline:** C05 `59bee081cbd8797455c98954fd8ed5b61af5af49`

**Architecture:** 12 November 2026 Security Architecture & Threat Model, Sections 9–11; matching full repository copy: `SecureVault_Antigravity_Implementation_Task.md`.

**Conformance scope:** Password-protected KEK and AES-KWP key hierarchy only.

## Implemented

- Password bytes are fed to the maintained `cryptography` Argon2id implementation with a fresh 16-byte OS CSPRNG salt and 32-byte result. Default profile: 65536 KiB memory, 3 iterations, 4 lanes.
- KDF records are bounded before KDF work: memory 8192–262144 KiB, iterations 1–10, lanes 1–8. Invalid version/algorithm identifiers, flags, reserved bytes, size, and bounds are rejected.
- Each new keyring gets independent random 16-byte vault and KEK generation IDs and an independent random 32-byte KEK. The plaintext KEK is returned only to the immediate caller; this checkpoint does not persist it.
- SVKR v1 is encoded exactly as a 68-byte big-endian header plus a 72-byte AES-KWP payload (140 bytes total). Its 64-byte plaintext is `vault_id[16] || kek_generation_id[16] || KEK[32]`. Both IDs must agree with the parsed header and may also be checked against trusted caller values.
- A file DEK record contains `file_id[16] || cipher_id[1] || DEK[32]` and wraps to 64 bytes. Unwrap validates AES-KWP integrity and requires trusted caller expectations for both association fields.
- Incorrect passwords and corrupted KWP payloads fail without returning key material. Password and key bytes are not printed or logged by these APIs.

## Cryptographic API choices

`cryptography` provides `Argon2id` (`cryptography.hazmat.primitives.kdf.argon2`, available since 44.0.0) and the padded AES key-wrap functions `aes_key_wrap_with_padding` / `aes_key_unwrap_with_padding` (AES-KWP, RFC 5649). Project metadata now requires `cryptography>=44.0.0`; `requirements-lock.txt` pins 50.0.2. No hand-written cryptographic primitive or fallback KDF is used. A runtime lacking Argon2id support fails explicitly.

Python and its immutable `bytes` objects do not provide reliable secret zeroization. Password-derived keys, KEKs and DEKs may remain in process memory until reclaimed; garbage collection is not secure erasure. The caller must keep key lifetimes short and protect the process and host.

### Password policy limitation and cost measurement gate

The current API only rejects empty passwords and inputs over 1024 UTF-8 bytes. It does not enforce a minimum passphrase length or strength, apply composition rules, or normalize Unicode. Unlock must receive the same UTF-8 byte sequence used at creation. Before any password-based vault initialization is exposed, measure the initial 65536 KiB / 3-iteration / 4-lane Argon2id profile on the local target hardware, recording elapsed time, peak memory, Python, `cryptography`, and OpenSSL versions. Review usability on constrained supported machines without changing the accepted KDF bounds or silently falling back to another algorithm.

## Threat assumptions and residual risks

The design protects a stored keyring from an attacker who can read or modify storage but cannot obtain the password or compromise the authorized endpoint. A copied keyring supports offline password guessing; Argon2id and a strong passphrase raise its cost but do not prevent it. Bounded attacker-controlled KDF values limit resource abuse, although valid high-cost values can still consume up to 256 MiB and 10 passes. KWP protects payload integrity and binds both IDs; it does not authenticate external vault state or file ciphertext. CBC remains confidentiality-only, even when its DEK is correctly wrapped.

The immutable header is not a separate MAC. Changing unsupported identifiers is rejected; changing accepted salt/cost metadata generally prevents the wrapped payload from authenticating and can cause denial of service. Rollback, deletion, compromised passwords/endpoints, memory disclosure, and secure erasure are not addressed. No guarantee is made that Python erases secret memory.

No raw KEK or DEK is written to disk by C06 code. The creation API does expose the fresh KEK to its caller in memory, as needed for future vault operations; persistence policy and lifecycle enforcement belong to later checkpoints.

## Validation

Run from the repository root with its environment activated:

```bash
python -m compileall -q src benchmarks experiments tests
python -m pytest -q
```

The focused C06 checks are in `tests/test_keyring.py` and cover Argon2id output/profile, independent salts and KEKs, exact SVKR layout/size, password unlock, incorrect password, modified wrapped data/identifiers, malformed records and unsupported/bounded parameters, DEK KWP size/round-trip and wrong association. The complete suite checks C05 compatibility. Results are recorded with the C06 handoff; this document does not claim a test result by itself.

### Integration pending at the C06 checkpoint

The following remain unimplemented and must be designed and verified in their assigned later checkpoints: authenticated encrypted manifest; trusted mode and key-protection policy; vault directory/state model and CURRENT pointer; transactional object/keyring/manifest publication and crash recovery; user-facing password prompting and short-lived unlock session; password change; manual KEK rotation and generation migration; independently protected encrypted recovery backup; managed-vault CLI; storage permissions and platform-specific operational validation. Do not claim rotation, recovery, rollback protection, or authenticated manifest support from C06.

## C07 authenticated manifest

`securevault.manifest` implements the SVMF v1 envelope from Notion §10 with the approved C07 schema completion rules. The 64-byte header and 40-byte wrapped manifest key form the exact 104-byte GCM AAD. The remaining bytes are the ciphertext and 16-byte tag. The codec enforces the 16 MiB and 10,000-entry limits before unwrapping the key or decrypting.

- `seal_manifest(document, kek)` validates the five-field document, sorts the file array by file ID, and encodes compact, recursively key-sorted UTF-8 JSON. Each call uses a fresh manifest data key and nonce.
- `open_manifest(data, kek, ...)` requires the KEK and vault/KEK generation IDs from verified SVKR context, plus the expected manifest generation ID from the caller. After GCM verification, it rejects duplicate keys and IDs, invalid schema or types, noncanonical bytes and inconsistent IDs or counts. It returns immutable metadata.
- Use the authenticated entry's `object_path` to resolve `objects/{object_id}.svlt`. `Manifest.unwrap_file_dek` checks the selected object ID, verified KEK generation, parsed file ID, expected cipher and wrapped-key protection before passing trusted IDs to the existing DEK unwrap routine. These checks protect the association. CBC ciphertext still lacks authentication.

MAN-01 through MAN-04 are in `tests/test_manifest.py`. Tests include independent AES-GCM envelopes containing invalid metadata and a real SVKR unlock-to-manifest round trip. The C08 integration must bind the supplied object ID to the opened file and enforce path confinement, symlink rejection and generation transactions. SVMF alone cannot detect replay of an older valid generation.

Local validation used Python 3.15.2 through the repository virtual environment. `python -m compileall -q src benchmarks experiments tests figures scripts` exited 0. Running `python -m pytest -q tests/test_manifest.py` with `-k man01`, `-k man02`, `-k man03`, and `-k man04` passed 4, 13, 28, and 2 tests respectively. The full `python -m pytest -q` run passed 213 tests in 6.27 seconds.

## C08 managed vault

The supported C08 storage backend is POSIX. The CLI uses a hidden interactive password prompt for each command. `Vault.unlock` verifies the selected SVKR against the password, opens the corresponding SVMF and checks the object inventory. The session keeps the verified keyring, KEK and root inode in process memory. `Vault.lock()` clears the logical session for subsequent operations. The CLI closes its session before exiting.

- **Authority.** The active generation comes from the exact 39-byte CURRENT v1 record. Each operation reopens and authenticates the selected SVMF against the unlocked vault ID, expected generation and verified SVKR KEK generation. Managed operations accept file IDs and paths. They obtain their authorization from the disk manifest opened internally, with no caller-supplied Manifest input.
- **Object identity.** An authenticated object ID selects exactly `objects/{object_id}.svlt`. Opening and parsing those bytes precedes file ID, cipher, protection and KEK generation checks. AES-KWP verifies the wrapped DEK against the trusted file ID and cipher. Extract verifies GCM before creating any output and supports a trusted expected mode. CBC warns on extraction and retains its original lack of payload authentication. Unlock, list and inspect verify inventory structure and associations. The final inventory pass before CURRENT activation also verifies every referenced GCM tag and discards the plaintext.
- **Paths.** The vault walks path components through directory descriptors without following links, validates owner and permissions, and rejects aliased vault files. Internal directory descriptors must be on the vault filesystem. Extract publishes privately staged plaintext with an exclusive hard link, outside the vault, into a directory owned by the caller and protected from other users' writes.
- **Transactions.** Writers hold an exclusive `flock` on the same vault lock file and reload CURRENT after acquiring it. New files are staged exclusively with private permissions. The writer rereads and verifies the staged manifest and object, syncs files and destination directories, publishes immutable dependencies with no replacement, checks the published inventory and compares CURRENT with the expected prior generation. It then replaces CURRENT atomically and syncs the vault root. The previous generation and keyring stay available.
- **Generation mapping.** `keyrings/{generation-id}.keys` is selected by the manifest generation ID. C08 appends copy the verified SVKR bytes into that new name. The stable KEK generation ID inside SVKR and the manifest is separate from the changing CURRENT generation ID.
- **Restart.** Only CURRENT selects a generation. Inactive staging and unreferenced dependencies may remain after interruption and never automatically activate. An invalid pointer fails closed. A failed first initialization can leave a private directory without a valid CURRENT. Preserve it for inspection and initialize a new directory.

The process-exit tests exercise staging interruption, immediately before CURRENT replacement and immediately after replacement. They reopen the vault and verify exact recovered bytes. The concurrent test starts three independent writer processes with sessions opened on the same starting generation and checks that all their entries survive. These results apply to process crashes on the tested local filesystem. Power-loss durability, network filesystems and Windows remain unverified.

On macOS arm64 with Python 3.15.2, `python -m compileall -q src benchmarks experiments tests figures scripts` exited 0. `python -m pytest -q tests/test_vault.py` passed 28 tests in 13.55 seconds, and `python -m pytest -q` passed 241 tests in 22.22 seconds. Both pytest runs used the repository virtual environment and ran concurrently.

A separate terminal smoke test ran `vault init`, `add`, `list` and `extract --require-mode gcm` in subprocesses with real hidden prompts. The recovered payload matched byte for byte and the terminal output did not contain the supplied test password.

C08 assumes cooperating writers and a trusted active OS process. A host attacker with the same effective user can interfere with the namespace, the advisory lock and process memory. A valid older committed generation can still be replayed. The implementation keeps older generations and abandoned artifacts without automatic garbage collection. Files are processed in memory with a 256 MiB ciphertext cap and can require several times the file size in RAM. C09 and C10 own key lifecycle and backup/recovery.

### C08-01 inventory authentication correction

Every generation commit authenticates GCM payloads under the writer lock before changing CURRENT, including reused objects from older generations. The pass reads every live container and allocates plaintext for one GCM file at a time. Work grows with total live bytes and increases write latency. A local smoke measurement on macOS arm64 (three 1 MiB GCM objects, 10 warm-cache passes, excluding Argon2id and publication) measured a 0.852 ms median for structural checks and 1.882 ms with GCM verification. This is a diagnostic measurement and is separate from the historical coursework evidence.

POSIX local filesystem support, unverified power-loss and network-filesystem behavior, and valid-generation rollback remain the same. CBC payloads receive structure and key association checks only.

The corruption regression modifies an existing GCM ciphertext byte, runs a real append and checks that the 39 CURRENT bytes remain identical. At the correction checkpoint, `python -m pytest -q tests/test_vault.py` passed 29 tests in 7.89 seconds and the full suite passed 242 tests in 13.23 seconds.

## C09 key lifecycle

Each lifecycle operation acquires the existing writer lock, authenticates CURRENT and its SVMF using the unlocked SVKR context, and commits through the shared CURRENT-last transaction. Before activation the writer checks every candidate object's structure and key association and authenticates every referenced GCM payload. Temporary plaintext exists only in memory during authentication and re-encryption.

| Operation | New generation |
|---|---|
| Password change | Preserves the vault ID, KEK generation, KEK and all object references. Uses a new Argon2id salt and verifies password unlock of the newly wrapped keyring before activation. |
| KEK rotation | Verifies the current password, creates a fresh random KEK and KEK generation ID, and verifies the new password wrapper. For each live object, verifies the old key binding and any GCM tag, then creates a new immutable object with only the 64-byte KWP record changed. The file ID, first 48 header bytes, payload ciphertext and GCM tag are preserved. A new SVMF uses a fresh manifest data key. |
| File DEK rotation | Authenticates the selected GCM object, encrypts the recovered bytes with a fresh DEK and nonce, and verifies exact recovery from the staged object. The file ID stays stable and only its object reference changes. CBC file DEK rotation is rejected because there is no original payload authentication to verify. |

Password change and KEK rotation close the initiating session. Other unlocked sessions detect the changed keyring and must unlock again. Old committed manifests, keyrings and objects remain on disk. A password change changes which password opens the active generation. A retained old keyring and its old password can still recover the same KEK, and older complete generations can still be replayed. Rotation does not revoke previously obtained keys or eliminate historic copies. CBC objects support KEK rewrapping, with integrity checks limited to structure and wrapped key associations.

The process-exit tests cover before and after CURRENT replacement for password change and KEK rotation, and a partial KEK update after the first new object is published. Restart verifies the selected credentials and exact recovered bytes. This is evidence for process interruption on the tested local POSIX filesystem. Power-loss durability, network filesystems, and Windows remain unverified. C10 encrypted backup and recovery remains pending.

On macOS arm64 with Python 3.15.2, `python -m compileall -q src benchmarks experiments tests figures scripts` exited 0. The focused suite (`python -m pytest -q tests/test_vault.py tests/test_keyring.py`) passed 90 tests in 14.83 seconds. The complete suite (`python -m pytest -q`) passed 254 tests in 20.24 seconds.

## C10 encrypted backup and recovery

Notion §9 specifies encrypted and authenticated recovery with a separately generated offline key. C10 defines the missing archive framing and publication rules. The existing AES, SVLT, SVKR, SVMF and CURRENT formats are unchanged.

- **SVRA v1.** A 28-byte exact AAD prefix contains ASCII `SVRA`, version 1, cipher ID 1, two zero flag bytes, a fresh 12-byte nonce and an unsigned 64-bit big-endian ciphertext length. The ciphertext and a 16-byte GCM tag follow. The encrypted payload is capped at 256 MiB and has no trailing bytes.
- **Snapshot.** Under the vault writer lock, backup verifies the selected SVMF and copies each referenced SVLT in canonical file ID order after checking its key association and any GCM tag. The encrypted payload contains the 32-byte KEK, three 16-byte vault, snapshot and KEK generation IDs, a 4-byte SVMF length and its bytes, followed by SVLT records with 8-byte lengths. All lengths are unsigned big-endian. The source and its history stay intact. The archive captures only the selected generation, with no old password wrapper or historical keyring.
- **Separate offline key.** Each backup generates a 32-byte CSPRNG key and uses it for its archive. The owner-only key file is written in a different directory before the archive. Both outputs refuse to overwrite. An interruption between publications can leave an unused key. The operator must keep the key offline and separate from the archive. Recovery secrets are absent from the archive, vault and application output.
- **Restore.** The archive authenticates before the application creates a staged vault. The reader also verifies the enclosed SVMF, record count, object bindings and GCM payloads. Restore rewraps the recovered KEK with a fresh SVKR salt and new password, verifies unlock, then builds a generation with CURRENT last inside a private sibling directory. It reserves a new final directory exclusively and promotes the fully verified stage with a same-filesystem rename. The original vault password is not needed.
- **Interruption.** Ordinary publication errors clean up the unused reservation and staging directory. An abrupt process exit may leave a private sibling stage or an empty reserved destination. Neither is activated automatically. Retry using a new destination. A process exit after promotion leaves a complete recoverable vault. The process tests do not establish power-loss durability. Windows and network filesystems remain unverified.
- **Residual risk.** The snapshot can be restored later with the matching key, so valid old state can be replayed. Historic keys, keyrings and backups do not imply revocation. The archive GCM tag authenticates captured CBC bytes within the archive, while a restored standalone CBC object has no payload authentication. Bounded whole-buffer processing can require several times the snapshot size in memory.

C11 follow-ups remain full process crash-boundary coverage for file DEK rotation and review of managed password-strength enforcement. Historical key retention remains a documented recovery tradeoff.

On macOS arm64 with Python 3.15.2, compilation (`python -m compileall -q src benchmarks experiments tests figures scripts`) exited 0. The focused REC-01–04 suite (`python -m pytest -q tests/test_recovery.py`) passed 26 tests in 10.68 seconds. The full suite passed 280 tests in 34.48 seconds, including all 254 C09 baseline tests. The process tests covered exit before staged CURRENT activation, at final promotion, and after final promotion, plus a separate writer blocked on the snapshot lock.
