"""C06 tests for Argon2id, SVKR v1 and AES-KWP DEK associations."""

import struct

import pytest

from securevault.errors import InvalidKeyError, KeyringError
from securevault.kdf import (
    DEFAULT_KDF_PARAMETERS,
    KDFParameters,
    derive_unlock_key,
)
from securevault.key_wrap import unwrap_dek, wrap_dek
from securevault.keyring import (
    HEADER_SIZE,
    KEYRING_SIZE,
    WRAPPED_PAYLOAD_SIZE,
    Keyring,
    create_keyring,
    unlock_keyring,
)

FAST_KDF = KDFParameters(memory_cost=8192, iterations=1, parallelism=1)


def test_argon2id_profile_and_output_size():
    assert DEFAULT_KDF_PARAMETERS == KDFParameters(65536, 3, 4)
    assert len(derive_unlock_key("test passphrase", b"s" * 16)) == 32


def test_keyring_creation_has_independent_salts_and_random_keks():
    first, first_kek = create_keyring("test passphrase", FAST_KDF)
    second, second_kek = create_keyring("test passphrase", FAST_KDF)
    assert first.salt != second.salt
    assert first_kek != second_kek
    assert first.vault_id != second.vault_id


def test_svkr_layout_exact_size_and_password_unlock():
    record, kek = create_keyring("test passphrase", FAST_KDF)
    encoded = record.serialize()
    assert len(encoded) == KEYRING_SIZE == 140
    assert encoded[:8] == b"SVKR\x01\x01\x01\0"
    assert encoded[8:24] == record.vault_id
    assert encoded[24:40] == record.kek_generation_id
    assert encoded[40:56] == record.salt
    assert struct.unpack(">IIH", encoded[56:66]) == (8192, 1, 1)
    assert encoded[66:68] == b"\0\0"
    assert len(encoded[HEADER_SIZE:]) == WRAPPED_PAYLOAD_SIZE == 72
    assert Keyring.parse(encoded) == record
    assert unlock_keyring(
        encoded,
        "test passphrase",
        expected_vault_id=record.vault_id,
        expected_kek_generation_id=record.kek_generation_id,
    ) == kek


def test_wrong_password_corruption_and_associated_ids_fail_closed():
    record, _ = create_keyring("test passphrase", FAST_KDF)
    encoded = record.serialize()
    with pytest.raises(KeyringError, match="Unable to unlock"):
        unlock_keyring(encoded, "wrong password")
    damaged = bytearray(encoded)
    damaged[-1] ^= 1
    with pytest.raises(KeyringError, match="Unable to unlock"):
        unlock_keyring(bytes(damaged), "test passphrase")
    with pytest.raises(KeyringError, match="vault ID"):
        unlock_keyring(encoded, "test passphrase", expected_vault_id=b"x" * 16)
    with pytest.raises(KeyringError, match="generation ID"):
        unlock_keyring(encoded, "test passphrase", expected_kek_generation_id=b"x" * 16)


@pytest.mark.parametrize("data", [b"", b"SVKR", b"x" * 139, b"x" * 141])
def test_truncated_and_oversized_keyrings_are_rejected(data):
    with pytest.raises(KeyringError):
        Keyring.parse(data)


@pytest.mark.parametrize(
    ("offset", "value"),
    [(4, 2), (5, 2), (6, 2), (7, 1), (66, 1), (56, 0xFF)],
)
def test_unsupported_ids_flags_reserved_and_kdf_bounds_are_rejected(offset, value):
    record, _ = create_keyring("test passphrase", FAST_KDF)
    damaged = bytearray(record.serialize())
    damaged[offset] = value
    with pytest.raises(KeyringError):
        Keyring.parse(bytes(damaged))


@pytest.mark.parametrize(
    "params",
    [
        KDFParameters(8191, 1, 1),
        KDFParameters(262145, 1, 1),
        KDFParameters(8192, 0, 1),
        KDFParameters(8192, 11, 1),
        KDFParameters(8192, 1, 0),
        KDFParameters(8192, 1, 9),
    ],
)
def test_kdf_parameter_bounds_rejected_before_derivation(params):
    with pytest.raises(KeyringError):
        derive_unlock_key("test passphrase", b"s" * 16, params)


@pytest.mark.parametrize("field", ["memory_cost", "iterations", "parallelism"])
@pytest.mark.parametrize("value", [True, 8192.0, "8192", None])
def test_kdf_parameter_fields_require_exact_integer_types(field, value):
    values = {"memory_cost": 8192, "iterations": 1, "parallelism": 1}
    values[field] = value
    with pytest.raises(KeyringError, match="must be integers"):
        KDFParameters(**values).validate()


def test_keyring_header_id_tampering_fails_after_unwrap():
    record, _ = create_keyring("test passphrase", FAST_KDF)
    damaged = bytearray(record.serialize())
    damaged[8] ^= 1
    with pytest.raises(KeyringError, match="Unable to unlock"):
        unlock_keyring(bytes(damaged), "test passphrase")


@pytest.mark.parametrize(
    ("offset", "replacement"),
    [(56, struct.pack(">I", 8193)), (60, struct.pack(">I", 2)), (64, struct.pack(">H", 2))],
)
def test_accepted_range_kdf_header_tampering_does_not_unlock(offset, replacement):
    record, _ = create_keyring("test passphrase", FAST_KDF)
    damaged = bytearray(record.serialize())
    damaged[offset:offset + len(replacement)] = replacement
    # These values are individually within policy bounds, but changing KDF
    # metadata must not make the existing wrapped key authenticate.
    assert Keyring.parse(bytes(damaged)).parameters != FAST_KDF
    with pytest.raises(KeyringError, match="Unable to unlock"):
        unlock_keyring(bytes(damaged), "test passphrase")


@pytest.mark.parametrize("data", [None, bytearray(b"x" * KEYRING_SIZE), "SVKR"])
def test_keyring_parser_rejects_non_bytes_inputs(data):
    with pytest.raises(KeyringError):
        Keyring.parse(data)


@pytest.mark.parametrize("salt", [None, bytearray(b"s" * 16), "s" * 16])
def test_kdf_rejects_non_bytes_salt(salt):
    with pytest.raises(KeyringError, match="salt"):
        derive_unlock_key("test passphrase", salt, FAST_KDF)


@pytest.mark.parametrize("password", [None, 42, [b"not a password"]])
def test_kdf_rejects_unsupported_password_types(password):
    with pytest.raises(TypeError, match="Password must be str or bytes"):
        derive_unlock_key(password, b"s" * 16, FAST_KDF)


def test_dek_aes_kwp_roundtrip_and_trusted_association_checks():
    kek, dek, file_id = b"k" * 32, b"d" * 32, b"f" * 16
    wrapped = wrap_dek(kek, file_id, 1, dek)
    assert len(wrapped) == 64
    assert unwrap_dek(kek, wrapped, file_id, 1) == dek
    with pytest.raises(InvalidKeyError, match="trusted file"):
        unwrap_dek(kek, wrapped, b"x" * 16, 1)
    with pytest.raises(InvalidKeyError, match="trusted file"):
        unwrap_dek(kek, wrapped, file_id, 2)
    with pytest.raises(InvalidKeyError, match="authentication failed"):
        unwrap_dek(kek, bytes([wrapped[0] ^ 1]) + wrapped[1:], file_id, 1)


def test_dek_wrapping_rejects_malformed_sizes_and_ids():
    with pytest.raises(InvalidKeyError):
        wrap_dek(b"k" * 32, b"f" * 16, 1, b"d" * 31)
    with pytest.raises(InvalidKeyError):
        unwrap_dek(b"k" * 32, b"w" * 63, b"f" * 16, 1)
