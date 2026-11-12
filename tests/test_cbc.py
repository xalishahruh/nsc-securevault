"""Unit tests for AES-256-CBC encryption with PKCS#7 padding."""

import os
import pytest
from securevault.crypto.cbc import (
    generate_cbc_dek,
    generate_cbc_iv,
    encrypt_cbc,
    decrypt_cbc,
    CBC_KEY_SIZE,
    CBC_IV_SIZE,
    CBC_BLOCK_SIZE,
)
from securevault.errors import PaddingError, InvalidKeyError


def test_cbc_key_and_iv_generation():
    """Verify CSPRNG key and IV lengths and freshness."""
    k1 = generate_cbc_dek()
    k2 = generate_cbc_dek()
    iv1 = generate_cbc_iv()
    iv2 = generate_cbc_iv()

    assert len(k1) == CBC_KEY_SIZE == 32
    assert len(k2) == CBC_KEY_SIZE == 32
    assert len(iv1) == CBC_IV_SIZE == 16
    assert len(iv2) == CBC_IV_SIZE == 16
    assert k1 != k2
    assert iv1 != iv2


@pytest.mark.parametrize("payload_size", [0, 1, 15, 16, 17, 31, 32, 1024, 65536])
def test_cbc_roundtrip_and_pkcs7_padding(payload_size):
    """FUNC-01/02: Verify PKCS#7 padding formula and byte-for-byte roundtrip."""
    dek = generate_cbc_dek()
    iv = generate_cbc_iv()
    plaintext = os.urandom(payload_size)

    ciphertext = encrypt_cbc(dek, iv, plaintext)

    # Theoretical size formula: C = 16 * (floor(P / 16) + 1)
    expected_ct_len = 16 * (payload_size // 16 + 1)
    assert len(ciphertext) == expected_ct_len
    assert len(ciphertext) % CBC_BLOCK_SIZE == 0

    recovered = decrypt_cbc(dek, iv, ciphertext)
    assert recovered == plaintext


def test_cbc_tampered_iv_yields_corrupted_plaintext():
    """AUTH-02: Tampering IV in CBC flips bits in the first plaintext block without integrity alert!

    This explicitly documents CBC's lack of authenticity.
    """
    dek = generate_cbc_dek()
    iv = generate_cbc_iv()
    plaintext = b"A" * 32  # 2 blocks

    ciphertext = encrypt_cbc(dek, iv, plaintext)

    # Flip 1 bit in IV
    tampered_iv = bytearray(iv)
    tampered_iv[0] ^= 0x01

    # Decryption succeeds without raising an error, but the first block of plaintext is corrupted!
    recovered = decrypt_cbc(dek, bytes(tampered_iv), ciphertext)
    assert recovered != plaintext
    # Specifically: recovered[0] has the flipped bit
    assert recovered[0] == plaintext[0] ^ 0x01
    # Second block remains unaffected in CBC when IV is flipped
    assert recovered[16:] == plaintext[16:]


def test_cbc_tampered_ciphertext_may_fail_padding_or_corrupt():
    """AUTH-02: Tampering CBC ciphertext either causes PaddingError or corrupted plaintext."""
    dek = generate_cbc_dek()
    iv = generate_cbc_iv()
    plaintext = b"B" * 64

    ciphertext = encrypt_cbc(dek, iv, plaintext)

    # Tamper the middle block
    tampered_ct = bytearray(ciphertext)
    tampered_ct[16] ^= 0xFF

    # Decrypting may either raise PaddingError (if padding corrupted) or yield corrupt plaintext
    try:
        recovered = decrypt_cbc(dek, iv, bytes(tampered_ct))
        assert recovered != plaintext
    except PaddingError:
        pass  # Also an expected outcome for corrupted padding block


def test_cbc_invalid_key_length():
    """Reject keys that are not exactly 32 bytes."""
    iv = generate_cbc_iv()
    with pytest.raises(InvalidKeyError):
        encrypt_cbc(b"short-key", iv, b"data")
    with pytest.raises(InvalidKeyError):
        decrypt_cbc(b"short-key", iv, b"data" * 4)

