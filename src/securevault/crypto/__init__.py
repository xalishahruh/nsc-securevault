"""Cryptographic primitives for SecureVault."""

from securevault.crypto.gcm import (
    encrypt_gcm,
    decrypt_gcm,
    generate_gcm_dek,
    generate_gcm_nonce,
    GCM_KEY_SIZE,
    GCM_NONCE_SIZE,
    GCM_TAG_SIZE,
)

KEY_SIZE = 32

__all__ = [
    "KEY_SIZE",
    "GCM_KEY_SIZE",
    "GCM_NONCE_SIZE",
    "GCM_TAG_SIZE",
    "encrypt_gcm",
    "decrypt_gcm",
    "generate_gcm_dek",
    "generate_gcm_nonce",
]
