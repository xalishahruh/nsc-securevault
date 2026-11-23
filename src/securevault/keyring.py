"""SVKR v1 password-protected vault KEK records."""

import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap_with_padding,
    aes_key_wrap_with_padding,
)

from securevault.errors import KeyringError
from securevault.kdf import (
    DEFAULT_KDF_PARAMETERS,
    KDFParameters,
    SALT_SIZE,
    derive_unlock_key,
)
from securevault.key_wrap import KEK_SIZE

MAGIC_KEYRING = b"SVKR"
KEYRING_VERSION = 1
ARGON2ID_ID = 1
AES_KWP_ID = 1
HEADER_SIZE = 68
WRAPPED_PAYLOAD_SIZE = 72
KEYRING_SIZE = HEADER_SIZE + WRAPPED_PAYLOAD_SIZE
_HEADER = struct.Struct(">4sBBBB16s16s16sIIH2s")


@dataclass(frozen=True)
class Keyring:
    """Parsed SVKR metadata and authenticated wrapped payload; contains no raw KEK."""

    vault_id: bytes
    kek_generation_id: bytes
    salt: bytes
    parameters: KDFParameters
    wrapped_payload: bytes

    def serialize(self) -> bytes:
        _validate_ids(self.vault_id, self.kek_generation_id)
        if len(self.salt) != SALT_SIZE:
            raise KeyringError(f"Keyring salt must be exactly {SALT_SIZE} bytes.")
        self.parameters.validate()
        if len(self.wrapped_payload) != WRAPPED_PAYLOAD_SIZE:
            raise KeyringError(f"Wrapped KEK payload must be exactly {WRAPPED_PAYLOAD_SIZE} bytes.")
        header = _HEADER.pack(
            MAGIC_KEYRING,
            KEYRING_VERSION,
            ARGON2ID_ID,
            AES_KWP_ID,
            0,
            self.vault_id,
            self.kek_generation_id,
            self.salt,
            self.parameters.memory_cost,
            self.parameters.iterations,
            self.parameters.parallelism,
            b"\0\0",
        )
        assert len(header) == HEADER_SIZE
        return header + self.wrapped_payload

    @classmethod
    def parse(cls, data: bytes) -> "Keyring":
        if not isinstance(data, bytes) or len(data) != KEYRING_SIZE:
            raise KeyringError(f"SVKR v1 keyring must be exactly {KEYRING_SIZE} bytes.")
        (
            magic, version, kdf_id, wrap_id, flags, vault_id, generation_id,
            salt, memory_cost, iterations, parallelism, reserved,
        ) = _HEADER.unpack(data[:HEADER_SIZE])
        if magic != MAGIC_KEYRING or version != KEYRING_VERSION:
            raise KeyringError("Unsupported or malformed keyring magic/version.")
        if kdf_id != ARGON2ID_ID or wrap_id != AES_KWP_ID:
            raise KeyringError("Unsupported keyring KDF or wrapping algorithm.")
        if flags != 0 or reserved != b"\0\0":
            raise KeyringError("Keyring flags and reserved bytes must be zero.")
        parameters = KDFParameters(memory_cost, iterations, parallelism)
        parameters.validate()
        _validate_ids(vault_id, generation_id)
        return cls(vault_id, generation_id, salt, parameters, data[HEADER_SIZE:])


def _validate_ids(vault_id: bytes, kek_generation_id: bytes) -> None:
    if not isinstance(vault_id, bytes) or len(vault_id) != 16:
        raise KeyringError("vault_id must be exactly 16 bytes.")
    if not isinstance(kek_generation_id, bytes) or len(kek_generation_id) != 16:
        raise KeyringError("KEK generation ID must be exactly 16 bytes.")


def create_keyring(
    password: str | bytes,
    parameters: KDFParameters = DEFAULT_KDF_PARAMETERS,
) -> tuple[Keyring, bytes]:
    """Create a keyring and return its new KEK for immediate caller use."""
    vault_id = os.urandom(16)
    generation_id = os.urandom(16)
    kek = os.urandom(KEK_SIZE)
    return protect_keyring(password, kek, vault_id, generation_id, parameters), kek


def protect_keyring(
    password: str | bytes, kek: bytes, vault_id: bytes, kek_generation_id: bytes,
    parameters: KDFParameters = DEFAULT_KDF_PARAMETERS,
) -> Keyring:
    """Wrap a 32-byte KEK with a fresh salt and the specified SVKR associations."""
    _validate_ids(vault_id, kek_generation_id)
    if not isinstance(kek, bytes) or len(kek) != KEK_SIZE:
        raise KeyringError("Vault KEK must be exactly 32 bytes.")
    salt = os.urandom(SALT_SIZE)
    unlock_key = derive_unlock_key(password, salt, parameters)
    wrapped = aes_key_wrap_with_padding(unlock_key, vault_id + kek_generation_id + kek)
    assert len(wrapped) == WRAPPED_PAYLOAD_SIZE
    return Keyring(vault_id, kek_generation_id, salt, parameters, wrapped)


def unlock_keyring(
    data: bytes,
    password: str | bytes,
    *,
    expected_vault_id: bytes | None = None,
    expected_kek_generation_id: bytes | None = None,
) -> bytes:
    """Return the KEK only after strict parsing, authenticated unwrap and ID checks."""
    keyring = Keyring.parse(data)
    if expected_vault_id is not None and expected_vault_id != keyring.vault_id:
        raise KeyringError("Keyring vault ID does not match the trusted expected ID.")
    if (
        expected_kek_generation_id is not None
        and expected_kek_generation_id != keyring.kek_generation_id
    ):
        raise KeyringError("Keyring generation ID does not match the trusted expected ID.")
    unlock_key = derive_unlock_key(password, keyring.salt, keyring.parameters)
    try:
        plaintext = aes_key_unwrap_with_padding(unlock_key, keyring.wrapped_payload)
    except (InvalidUnwrap, ValueError) as exc:
        raise KeyringError("Unable to unlock keyring (incorrect password or corrupted record).") from exc
    expected_prefix = keyring.vault_id + keyring.kek_generation_id
    if len(plaintext) != 64 or plaintext[:32] != expected_prefix:
        raise KeyringError("Unable to unlock keyring (incorrect password or corrupted record).")
    return plaintext[32:]
