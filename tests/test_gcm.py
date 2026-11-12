"""Unit tests for AES-256-GCM authenticated encryption."""

import os
import pytest
from securevault.crypto.gcm import (
    generate_gcm_dek,
    generate_gcm_nonce,
    encrypt_gcm,
    decrypt_gcm,
    GCM_KEY_SIZE,
    GCM_NONCE_SIZE,
    GCM_TAG_SIZE,
)
from securevault.errors import AuthenticationError, InvalidKeyError


def test_gcm_key_and_nonce_generation():
    """Verify CSPRNG key and nonce lengths and freshness."""
    k1 = generate_gcm_dek()
    k2 = generate_gcm_dek()
    n1 = generate_gcm_nonce()
    n2 = generate_gcm_nonce()

    assert len(k1) == GCM_KEY_SIZE == 32
    assert len(k2) == GCM_KEY_SIZE == 32
    assert len(n1) == GCM_NONCE_SIZE == 12
    assert len(n2) == GCM_NONCE_SIZE == 12
    assert k1 != k2
    assert n1 != n2


@pytest.mark.parametrize("payload_size", [0, 1, 15, 16, 17, 1024, 65536])
def test_gcm_roundtrip(payload_size):
    """FUNC-01/02: Verify byte-for-byte roundtrip for various payload sizes."""
    dek = generate_gcm_dek()
    nonce = generate_gcm_nonce()
    plaintext = os.urandom(payload_size)
    aad = b"immutable-header-data"

    ciphertext, tag = encrypt_gcm(dek, nonce, plaintext, associated_data=aad)
    assert len(ciphertext) == payload_size
    assert len(tag) == GCM_TAG_SIZE

    recovered = decrypt_gcm(dek, nonce, ciphertext, tag, associated_data=aad)
    assert recovered == plaintext


def test_gcm_wrong_key_fails():
    """KEY-02: Decryption with wrong key must raise AuthenticationError."""
    dek1 = generate_gcm_dek()
    dek2 = generate_gcm_dek()
    nonce = generate_gcm_nonce()
    plaintext = b"top secret data"

    ciphertext, tag = encrypt_gcm(dek1, nonce, plaintext)

    with pytest.raises(AuthenticationError):
        decrypt_gcm(dek2, nonce, ciphertext, tag)


def test_gcm_tampered_ciphertext_fails():
    """AUTH-01: Tampering even a single bit in ciphertext must cause authentication failure."""
    dek = generate_gcm_dek()
    nonce = generate_gcm_nonce()
    plaintext = b"critical message"

    ciphertext, tag = encrypt_gcm(dek, nonce, plaintext)
    tampered_ct = bytearray(ciphertext)
    tampered_ct[0] ^= 0x01

    with pytest.raises(AuthenticationError):
        decrypt_gcm(dek, nonce, bytes(tampered_ct), tag)


def test_gcm_tampered_tag_fails():
    """AUTH-01: Tampering even a single bit in authentication tag must cause authentication failure."""
    dek = generate_gcm_dek()
    nonce = generate_gcm_nonce()
    plaintext = b"critical message"

    ciphertext, tag = encrypt_gcm(dek, nonce, plaintext)
    tampered_tag = bytearray(tag)
    tampered_tag[-1] ^= 0x80

    with pytest.raises(AuthenticationError):
        decrypt_gcm(dek, nonce, ciphertext, bytes(tampered_tag))


def test_gcm_tampered_aad_fails():
    """AUTH-01: Modifying associated data must fail authentication."""
    dek = generate_gcm_dek()
    nonce = generate_gcm_nonce()
    plaintext = b"critical message"
    aad = b"header-v1"

    ciphertext, tag = encrypt_gcm(dek, nonce, plaintext, associated_data=aad)

    with pytest.raises(AuthenticationError):
        decrypt_gcm(dek, nonce, ciphertext, tag, associated_data=b"header-v2")


def test_gcm_invalid_key_length():
    """Reject keys that are not exactly 32 bytes."""
    nonce = generate_gcm_nonce()
    with pytest.raises(InvalidKeyError):
        encrypt_gcm(b"short-key", nonce, b"data")
    with pytest.raises(InvalidKeyError):
        decrypt_gcm(b"short-key", nonce, b"data", b"0" * 16)

