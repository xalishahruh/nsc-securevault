"""AES-KWP helpers for vault KEKs and per-file DEK records."""

from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap_with_padding,
    aes_key_wrap_with_padding,
)

from securevault.errors import InvalidKeyError

KEK_SIZE = 32
DEK_SIZE = 32
FILE_ID_SIZE = 16
DEK_RECORD_SIZE = 49
WRAPPED_DEK_SIZE = 64
SUPPORTED_CIPHER_IDS = (1, 2)


def _validate_kek(kek: bytes) -> None:
    if not isinstance(kek, bytes) or len(kek) != KEK_SIZE:
        raise InvalidKeyError(f"AES-KWP key must be exactly {KEK_SIZE} bytes.")


def _validate_association(file_id: bytes, cipher_id: int) -> None:
    if not isinstance(file_id, bytes) or len(file_id) != FILE_ID_SIZE:
        raise InvalidKeyError(f"file_id must be exactly {FILE_ID_SIZE} bytes.")
    if type(cipher_id) is not int or cipher_id not in SUPPORTED_CIPHER_IDS:
        raise InvalidKeyError("cipher_id must be 1 (GCM) or 2 (CBC).")


def wrap_dek(kek: bytes, file_id: bytes, cipher_id: int, dek: bytes) -> bytes:
    """Wrap a DEK and its trusted file/mode association as a 64-byte record."""
    _validate_kek(kek)
    _validate_association(file_id, cipher_id)
    if not isinstance(dek, bytes) or len(dek) != DEK_SIZE:
        raise InvalidKeyError(f"DEK must be exactly {DEK_SIZE} bytes.")
    plaintext = file_id + bytes((cipher_id,)) + dek
    assert len(plaintext) == DEK_RECORD_SIZE
    wrapped = aes_key_wrap_with_padding(kek, plaintext)
    assert len(wrapped) == WRAPPED_DEK_SIZE
    return wrapped


def unwrap_dek(
    kek: bytes,
    wrapped: bytes,
    expected_file_id: bytes,
    expected_cipher_id: int,
) -> bytes:
    """Unwrap a DEK only when KWP integrity and caller-trusted IDs both match."""
    _validate_kek(kek)
    _validate_association(expected_file_id, expected_cipher_id)
    if not isinstance(wrapped, bytes) or len(wrapped) != WRAPPED_DEK_SIZE:
        raise InvalidKeyError(f"Wrapped DEK record must be exactly {WRAPPED_DEK_SIZE} bytes.")
    try:
        plaintext = aes_key_unwrap_with_padding(kek, wrapped)
    except (InvalidUnwrap, ValueError) as exc:
        raise InvalidKeyError("Wrapped DEK authentication failed.") from exc
    if len(plaintext) != DEK_RECORD_SIZE:
        raise InvalidKeyError("Unwrapped DEK record has an invalid length.")
    file_id, cipher_id, dek = plaintext[:16], plaintext[16], plaintext[17:]
    if file_id != expected_file_id or cipher_id != expected_cipher_id:
        raise InvalidKeyError("Wrapped DEK does not match the trusted file and cipher association.")
    return dek
