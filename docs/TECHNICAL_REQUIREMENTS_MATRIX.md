# SecureVault C06 Technical Requirements Matrix

**Scope:** Protected key hierarchy only. C06 adds key management primitives without changing the C05 AES-GCM versus AES-CBC research scope or integrating a managed vault into the CLI.

| Requirement | C06 implementation | Evidence |
| --- | --- | --- |
| Password to unlock key | Argon2id, 16-byte random salt, 32-byte output; default profile is 65536 KiB, 3 iterations, 4 lanes | `src/securevault/kdf.py`; `tests/test_keyring.py` |
| Bound untrusted KDF settings | Memory 8192–262144 KiB, iterations 1–10, parallelism 1–8, checked before KDF invocation | `KDFParameters.validate`; out-of-range tests |
| Random vault KEK | Independent OS CSPRNG 32-byte KEK per newly created keyring | `create_keyring`; random key and salt test |
| Protected keyring | Strict SVKR v1: 68-byte header and 72-byte KWP payload, exactly 140 bytes | `src/securevault/keyring.py`; binary layout test |
| KEK binding | KWP plaintext is `vault_id[16] || kek_generation_id[16] || KEK[32]`; compare IDs after unwrap and optionally against trusted expected IDs | `unlock_keyring`; mismatch/tamper tests |
| File DEK protection | KWP plaintext is `file_id[16] || cipher_id[1] || DEK[32]`; wrapped length is 64 bytes | `src/securevault/key_wrap.py`; round-trip and wrong-association tests |
| Existing file encryption | C05 GCM, CBC, `.svlt` v1, `.svkey`, CLI, benchmark and evidence remain outside this change | Existing full test suite and existing artifacts |
| Managed vault operations | Not implemented in C06 | Reserved for subsequent checkpoints |

## Frozen keyring format

SVKR v1 follows the final Section 11.B table in the 12 November 2026 Security Architecture & Threat Model and the matching repository specification in `SecureVault_Antigravity_Implementation_Task.md` (SVKR section). The record fields are:

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 4 | `SVKR` |
| 4 | 1 | Version 1 |
| 5 | 1 | Argon2id ID 1 |
| 6 | 1 | AES-KWP ID 1 |
| 7 | 1 | Zero flags |
| 8 | 16 | Vault ID |
| 24 | 16 | KEK generation ID |
| 40 | 16 | KDF salt |
| 56 | 4 | Argon2id memory cost, unsigned big-endian KiB |
| 60 | 4 | Argon2id iteration count, unsigned big-endian |
| 64 | 2 | Argon2id parallelism, unsigned big-endian |
| 66 | 2 | Reserved zero bytes |
| 68 | 72 | AES-KWP wrapped 64-byte KEK payload |

The header is strictly parsed, but KDF metadata is not a separate authenticated object. Modifying it can cause unlock failure or a bounded denial of service; accepted costs are checked before KDF allocation. IDs are bound inside the KWP payload.

## API and dependency

- `cryptography.hazmat.primitives.kdf.argon2.Argon2id`: `salt`, `length=32`, `iterations`, `lanes`, and `memory_cost`; the API was introduced in `cryptography` 44.0.0.
- `cryptography.hazmat.primitives.keywrap.aes_key_wrap_with_padding` and `aes_key_unwrap_with_padding`: AES-KWP (RFC 5649) operations. Authentication/unwrap failures are mapped to non-secret typed errors.
- Project minimum is `cryptography>=44.0.0`; the repository lock records `cryptography==50.0.2`. Argon2id availability depends on the linked OpenSSL build; unsupported environments fail without an alternate KDF.
- Passwords are accepted by the library API as UTF-8 `str` or `bytes`, limited to 1–1024 bytes, and are never passed through a command-line option by this checkpoint.
- `create_keyring()` returns the serialized-record object and its newly generated KEK for immediate caller use. `unlock_keyring()` returns a KEK only after exact parsing, successful KWP unwrap, and embedded-ID verification.
- `wrap_dek()` and `unwrap_dek()` are low-level calls requiring the caller to supply trusted expected file and cipher IDs. The encrypted file header alone is not a trusted policy source.

## Scope exclusions

This checkpoint does not implement an authenticated manifest, vault state, password change, KEK rotation, recovery backup, transaction protocol, keyring persistence, session lock/unlock UI, or CLI integration. It does not change `.svlt` v1 or `.svkey` behavior.
