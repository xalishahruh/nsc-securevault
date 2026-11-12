"""AES-256-GCM authenticated encryption implementation."""

import os
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from securevault.errors import AuthenticationError, InvalidKeyError

GCM_KEY_SIZE = 32   # 256-bit key
GCM_NONCE_SIZE = 12 # 96-bit standard GCM nonce
GCM_TAG_SIZE = 16   # 128-bit authentication tag


def generate_gcm_dek() -> bytes:
    """Generate a fresh cryptographically secure 32-byte (256-bit) DEK."""
    return os.urandom(GCM_KEY_SIZE)


def generate_gcm_nonce() -> bytes:
    """Generate a fresh cryptographically secure 12-byte nonce."""
    return os.urandom(GCM_NONCE_SIZE)


def encrypt_gcm(
    dek: bytes,
    nonce: bytes,
    plaintext: bytes,
    associated_data: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM.

    Args:
        dek: 32-byte AES-256 data encryption key.
        nonce: 12-byte unique initialization vector.
        plaintext: Raw data bytes to encrypt.
        associated_data: Optional authenticated associated data (AAD).

    Returns:
        Tuple of (ciphertext, tag), where tag is 16 bytes and ciphertext length
        equals plaintext length.
    """
    if len(dek) != GCM_KEY_SIZE:
        raise InvalidKeyError(f"AES-256-GCM key must be exactly {GCM_KEY_SIZE} bytes; got {len(dek)}.")
    if len(nonce) != GCM_NONCE_SIZE:
        raise ValueError(f"AES-GCM nonce must be exactly {GCM_NONCE_SIZE} bytes; got {len(nonce)}.")

    aesgcm = AESGCM(dek)
    # cryptography AESGCM.encrypt appends 16-byte tag to the ciphertext
    combined = aesgcm.encrypt(nonce, plaintext, associated_data)
    ciphertext = combined[:-GCM_TAG_SIZE]
    tag = combined[-GCM_TAG_SIZE:]
    return ciphertext, tag


def decrypt_gcm(
    dek: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Decrypt and authenticate ciphertext using AES-256-GCM.

    Args:
        dek: 32-byte AES-256 data encryption key.
        nonce: 12-byte initialization vector.
        ciphertext: Encrypted payload bytes.
        tag: 16-byte authentication tag.
        associated_data: Optional authenticated associated data (AAD).

    Returns:
        Decrypted plaintext bytes.

    Raises:
        AuthenticationError: If tag verification fails or data was tampered with.
        InvalidKeyError: If key length is not 32 bytes.
    """
    if len(dek) != GCM_KEY_SIZE:
        raise InvalidKeyError(f"AES-256-GCM key must be exactly {GCM_KEY_SIZE} bytes; got {len(dek)}.")
    if len(nonce) != GCM_NONCE_SIZE:
        raise ValueError(f"AES-GCM nonce must be exactly {GCM_NONCE_SIZE} bytes; got {len(nonce)}.")
    if len(tag) != GCM_TAG_SIZE:
        raise ValueError(f"AES-GCM tag must be exactly {GCM_TAG_SIZE} bytes; got {len(tag)}.")

    aesgcm = AESGCM(dek)
    combined = ciphertext + tag
    try:
        plaintext = aesgcm.decrypt(nonce, combined, associated_data)
        return plaintext
    except InvalidTag as err:
        raise AuthenticationError(
            "GCM authentication failed: ciphertext, tag, or header modified, or wrong key used."
        ) from err

