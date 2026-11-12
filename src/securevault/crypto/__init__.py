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
from securevault.crypto.cbc import (
    encrypt_cbc,
    decrypt_cbc,
    generate_cbc_dek,
    generate_cbc_iv,
    CBC_KEY_SIZE,
    CBC_IV_SIZE,
    CBC_BLOCK_SIZE,
)

KEY_SIZE = 32

__all__ = [
    "KEY_SIZE",
    "GCM_KEY_SIZE",
    "GCM_NONCE_SIZE",
    "GCM_TAG_SIZE",
    "CBC_KEY_SIZE",
    "CBC_IV_SIZE",
    "CBC_BLOCK_SIZE",
    "encrypt_gcm",
    "decrypt_gcm",
    "generate_gcm_dek",
    "generate_gcm_nonce",
    "encrypt_cbc",
    "decrypt_cbc",
    "generate_cbc_dek",
    "generate_cbc_iv",
]
