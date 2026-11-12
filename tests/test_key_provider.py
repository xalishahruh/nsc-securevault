"""Tests for external key record serialization, validation, and key provider behavior."""

import os
import pytest
from securevault.key_provider import (
    ExternalKeyRecord,
    ExternalKeyProvider,
    MAGIC_KEY,
    KEY_RECORD_SIZE,
)
from securevault.errors import InvalidKeyError, ModeMismatchError


def test_key_record_serialization_and_parsing():
    """Verify 54-byte external key record serialization and byte parsing."""
    file_id = os.urandom(16)
    dek = os.urandom(32)
    record = ExternalKeyRecord(version=1, file_id=file_id, cipher_id=1, dek=dek)

    serialized = record.serialize()
    assert len(serialized) == KEY_RECORD_SIZE == 54
    assert serialized[:4] == MAGIC_KEY

    parsed = ExternalKeyRecord.parse(serialized)
    assert parsed.version == 1
    assert parsed.file_id == file_id
    assert parsed.cipher_id == 1
    assert parsed.dek == dek


def test_key_02_file_id_mismatch_rejected():
    """KEY-02: Key record with mismatched file ID must be rejected."""
    record = ExternalKeyRecord(
        version=1,
        file_id=os.urandom(16),
        cipher_id=1,
        dek=os.urandom(32),
    )
    different_file_id = os.urandom(16)

    with pytest.raises(InvalidKeyError, match="does not match container file ID"):
        record.validate_association(different_file_id, expected_cipher_id=1)


def test_key_02_mode_mismatch_rejected():
    """KEY-02: Key record configured for GCM cannot be used for CBC and vice versa."""
    record = ExternalKeyRecord(
        version=1,
        file_id=os.urandom(16),
        cipher_id=1,  # GCM
        dek=os.urandom(32),
    )

    with pytest.raises(ModeMismatchError, match="does not match container cipher mode"):
        record.validate_association(record.file_id, expected_cipher_id=2)  # CBC


def test_invalid_key_bytes_rejected():
    """Malformed key bytes must be rejected."""
    with pytest.raises(InvalidKeyError):
        ExternalKeyRecord.parse(b"short")

    with pytest.raises(InvalidKeyError):
        ExternalKeyRecord.parse(b"BADM" + b"\x00" * 50)

