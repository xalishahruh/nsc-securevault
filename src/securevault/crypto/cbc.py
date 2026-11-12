"""AES-256-CBC confidentiality-only encryption implementation with PKCS#7 padding."""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from securevault.errors import PaddingError, InvalidKeyError

CBC_KEY_SIZE = 32    # 256-bit key
CBC_IV_SIZE = 16     # 128-bit AES block size / IV
CBC_BLOCK_SIZE = 16  # 16 bytes (128 bits)


def generate_cbc_dek() -> bytes:
    """Generate a fresh cryptographically secure 32-byte (256-bit) DEK."""
    return os.urandom(CBC_KEY_SIZE)


def generate_cbc_iv() -> bytes:
    """Generate a fresh cryptographically secure 16-byte IV."""
    return os.urandom(CBC_IV_SIZE)


def encrypt_cbc(dek: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext using AES-256-CBC with PKCS#7 padding.

    NOTE: AES-CBC provides confidentiality only; it provides NO inherent
    ciphertext integrity or authenticity guarantees.

    Args:
        dek: 32-byte AES-256 data encryption key.
        iv: 16-byte initialization vector.
        plaintext: Raw data bytes to encrypt.

    Returns:
        Ciphertext bytes whose length is a multiple of 16.
    """
    if len(dek) != CBC_KEY_SIZE:
        raise InvalidKeyError(f"AES-256-CBC key must be exactly {CBC_KEY_SIZE} bytes; got {len(dek)}.")
    if len(iv) != CBC_IV_SIZE:
        raise ValueError(f"AES-CBC IV must be exactly {CBC_IV_SIZE} bytes; got {len(iv)}.")

    padder = padding.PKCS7(CBC_BLOCK_SIZE * 8).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(dek), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext


def decrypt_cbc(dek: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext using AES-256-CBC and unpad PKCS#7.

    WARNING: AES-CBC provides no authenticity verification. Successful
    decryption and valid PKCS#7 padding do NOT guarantee that ciphertext
    has not been tampered with. If tampered, this function will either raise
    PaddingError or return corrupted plaintext.

    Args:
        dek: 32-byte AES-256 data encryption key.
        iv: 16-byte initialization vector.
        ciphertext: Encrypted payload bytes (must be non-empty and multiple of 16).

    Returns:
        Decrypted plaintext bytes.

    Raises:
        PaddingError: If PKCS#7 padding is invalid.
        InvalidKeyError: If key length is not 32 bytes.
        ValueError: If ciphertext length is invalid.
    """
    if len(dek) != CBC_KEY_SIZE:
        raise InvalidKeyError(f"AES-256-CBC key must be exactly {CBC_KEY_SIZE} bytes; got {len(dek)}.")
    if len(iv) != CBC_IV_SIZE:
        raise ValueError(f"AES-CBC IV must be exactly {CBC_IV_SIZE} bytes; got {len(iv)}.")
    if not ciphertext or len(ciphertext) % CBC_BLOCK_SIZE != 0:
        raise ValueError(
            f"AES-CBC ciphertext must be non-empty and a multiple of {CBC_BLOCK_SIZE} bytes; got {len(ciphertext)}."
        )

    cipher = Cipher(algorithms.AES(dek), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(CBC_BLOCK_SIZE * 8).unpadder()
    try:
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext
    except ValueError as err:
        raise PaddingError(
            "CBC PKCS#7 padding validation failed (corrupted ciphertext or incorrect key)."
        ) from err

