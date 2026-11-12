"""Tests for .svlt container serialization, parsing, and format validation."""

import os
import struct
import pytest
from securevault.container import (
    ContainerHeader,
    serialize_container,
    parse_container,
    CIPHER_GCM,
    CIPHER_CBC,
    KEY_PROT_EXTERNAL,
    KEY_PROT_KWP,
    HEADER_SIZE,
    MAGIC_CONTAINER,
    CONTAINER_VERSION,
)
from securevault.errors import (
    InvalidHeaderError,
    MalformedContainerError,
)


def test_container_theoretical_sizes():
    """Verify exact theoretical container size calculations against specification Table in Section 5."""
    # Theoretical sizes for external-key mode:
    # Header: 48, Key Desc: 3 (1+2), Key record: 0
    # GCM: total = 48 + 3 + P + 16 = 67 + P
    # CBC: total = 48 + 3 + (16 * (P // 16 + 1))
    test_cases = [
        (0, 67, 67),
        (1, 68, 67),
        (16, 83, 83),
        (1024, 1091, 1091),
        (1048576, 1048643, 1048643),
    ]

    for p_len, expected_gcm_total, expected_cbc_total in test_cases:
        # GCM
        hdr_gcm = ContainerHeader(
            version=1,
            cipher_id=CIPHER_GCM,
            flags=0,
            file_id=os.urandom(16),
            iv_or_nonce=os.urandom(12),
            ciphertext_length=p_len,
        )
        ct_gcm = b"X" * p_len
        tag = b"T" * 16
        gcm_container = serialize_container(hdr_gcm, ct_gcm, key_protection_id=KEY_PROT_EXTERNAL, gcm_tag=tag)
        assert len(gcm_container) == expected_gcm_total

        # CBC
        cbc_ct_len = 16 * (p_len // 16 + 1)
        hdr_cbc = ContainerHeader(
            version=1,
            cipher_id=CIPHER_CBC,
            flags=0,
            file_id=os.urandom(16),
            iv_or_nonce=os.urandom(16),
            ciphertext_length=cbc_ct_len,
        )
        ct_cbc = b"Y" * cbc_ct_len
        cbc_container = serialize_container(hdr_cbc, ct_cbc, key_protection_id=KEY_PROT_EXTERNAL)
        assert len(cbc_container) == expected_cbc_total


def test_container_roundtrip():
    """Serialize and parse valid containers for GCM and CBC."""
    file_id = os.urandom(16)
    nonce = os.urandom(12)
    ct = b"sample-encrypted-payload"
    tag = os.urandom(16)

    hdr = ContainerHeader(
        version=1,
        cipher_id=CIPHER_GCM,
        flags=0,
        file_id=file_id,
        iv_or_nonce=nonce,
        ciphertext_length=len(ct),
    )
    raw = serialize_container(hdr, ct, key_protection_id=KEY_PROT_EXTERNAL, gcm_tag=tag)
    parsed = parse_container(raw)

    assert parsed.header.version == 1
    assert parsed.header.cipher_id == CIPHER_GCM
    assert parsed.header.file_id == file_id
    assert parsed.header.iv_or_nonce == nonce
    assert parsed.header.ciphertext_length == len(ct)
    assert parsed.ciphertext == ct
    assert parsed.gcm_tag == tag
    assert len(parsed.immutable_header_bytes) == HEADER_SIZE


@pytest.mark.parametrize(
    "corrupt_field,mutator,expected_exc",
    [
        ("magic", lambda b: b"BAD!" + b[4:], InvalidHeaderError),
        ("version", lambda b: b[:4] + b"\x02" + b[5:], InvalidHeaderError),
        ("cipher_id", lambda b: b[:5] + b"\x99" + b[6:], InvalidHeaderError),
        ("flags", lambda b: b[:6] + b"\x00\x01" + b[8:], InvalidHeaderError),
        ("gcm_iv_padding", lambda b: b[:36] + b"\x01\x00\x00\x00" + b[40:], InvalidHeaderError),
        ("key_protection_id", lambda b: b[:48] + b"\x05" + b[49:], MalformedContainerError),
        ("extra_bytes", lambda b: b + b"trailing", MalformedContainerError),
        ("truncated", lambda b: b[:-5], MalformedContainerError),
    ],
)
def test_fmt_01_invalid_header_rejections(corrupt_field, mutator, expected_exc):
    """FMT-01: Strict parser rejection of corrupt headers, flags, padding, and boundaries."""
    hdr = ContainerHeader(
        version=1,
        cipher_id=CIPHER_GCM,
        flags=0,
        file_id=os.urandom(16),
        iv_or_nonce=os.urandom(12),
        ciphertext_length=16,
    )
    valid_bytes = serialize_container(hdr, b"A" * 16, key_protection_id=KEY_PROT_EXTERNAL, gcm_tag=b"T" * 16)

    corrupted = mutator(valid_bytes)
    with pytest.raises(expected_exc):
        parse_container(corrupted)


def test_fmt_02_oversized_declared_length_rejected():
    """FMT-02: Overlarge declared length in header rejected before memory allocation."""
    # Craft a header declaring 1 GiB ciphertext length but file is only 100 bytes
    huge_length = 1024 * 1024 * 1024  # 1 GiB > 256 MiB limit
    crafted_header = struct.pack(
        ">4sBBH16s16sQ",
        MAGIC_CONTAINER,
        CONTAINER_VERSION,
        CIPHER_GCM,
        0,  # flags
        os.urandom(16),
        os.urandom(12) + b"\x00\x00\x00\x00",
        huge_length,
    )
    fake_body = b"\x00\x00\x00" + b"some bytes"
    with pytest.raises(MalformedContainerError):
        parse_container(crafted_header + fake_body)


def test_cbc_container_requires_divisible_by_16():
    """FMT-01: CBC ciphertext length must be non-zero and divisible by 16."""
    hdr = ContainerHeader(
        version=1,
        cipher_id=CIPHER_CBC,
        flags=0,
        file_id=os.urandom(16),
        iv_or_nonce=os.urandom(16),
        ciphertext_length=15,  # Invalid: not divisible by 16
    )
    raw = serialize_container(hdr, b"X" * 15, key_protection_id=KEY_PROT_EXTERNAL)
    with pytest.raises(MalformedContainerError):
        parse_container(raw)

