# C06 Architecture Conformance

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

## Pending C07–C12 integration

The following remain unimplemented and must be designed and verified in their assigned later checkpoints: authenticated encrypted manifest; trusted mode and key-protection policy; vault directory/state model and CURRENT pointer; transactional object/keyring/manifest publication and crash recovery; user-facing password prompting and short-lived unlock session; password change; manual KEK rotation and generation migration; independently protected encrypted recovery backup; managed-vault CLI; storage permissions and platform-specific operational validation. Do not claim rotation, recovery, rollback protection, or authenticated manifest support from C06.
