"""SVMF v1 acceptance tests, grouped by MAN-01 through MAN-04."""

import json
import os
from copy import deepcopy
from pathlib import PurePosixPath

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap_with_padding, aes_key_wrap_with_padding

from securevault.container import ContainerHeader, parse_container, serialize_container
from securevault.crypto.cbc import encrypt_cbc
from securevault.crypto.gcm import encrypt_gcm
from securevault.errors import AuthenticationError, InvalidKeyError, ManifestError
from securevault.kdf import KDFParameters
from securevault.key_wrap import wrap_dek
from securevault.keyring import create_keyring, unlock_keyring
from securevault.manifest import open_manifest, seal_manifest

KEK = b"K" * 32
VAULT, GENERATION, KEK_ID = (bytes([i]) * 16 for i in (1, 2, 3))
FILE, OBJECT = (bytes([i]) * 16 for i in (4, 5))
EXPECTED = dict(expected_vault_id=VAULT, expected_generation_id=GENERATION, expected_kek_generation_id=KEK_ID)
EMPTY_PLAINTEXT = (
    b'{"files":[],"generation_id":"02020202020202020202020202020202",'
    b'"kek_generation_id":"03030303030303030303030303030303","schema":1,'
    b'"vault_id":"01010101010101010101010101010101"}'
)


def record(file_id=FILE, object_id=OBJECT, cipher=1):
    return dict(file_id=file_id.hex(), object_id=object_id.hex(), cipher_id=cipher,
                key_protection_id=1, kek_generation_id=KEK_ID.hex())


def metadata(*files):
    return dict(schema=1, vault_id=VAULT.hex(), generation_id=GENERATION.hex(),
                kek_generation_id=KEK_ID.hex(), files=list(files))


def encode(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def envelope(plaintext, count=0):
    """Assemble and authenticate test input independently of the manifest implementation."""
    key, nonce = os.urandom(32), os.urandom(12)
    prefix = (
        b"SVMF\x01\x01\x00\x00" + VAULT + GENERATION + nonce
        + len(plaintext).to_bytes(8, "big") + count.to_bytes(4, "big")
        + aes_key_wrap_with_padding(KEK, key)
    )
    return prefix + AESGCM(key).encrypt(nonce, plaintext, prefix)


def unpack_plaintext(blob):
    key = aes_key_unwrap_with_padding(KEK, blob[64:104])
    return key, AESGCM(key).decrypt(blob[40:52], blob[104:], blob[:104])


def test_man01_empty_exact_layout_and_canonical_bytes():
    data = seal_manifest(metadata(), KEK)
    assert data[:8] == b"SVMF\x01\x01\x00\x00"
    assert data[8:24] == VAULT and data[24:40] == GENERATION
    assert int.from_bytes(data[52:60], "big") == len(EMPTY_PLAINTEXT)
    assert data[60:64] == bytes(4)
    assert len(data) == 120 + len(EMPTY_PLAINTEXT)
    key, plaintext = unpack_plaintext(data)
    assert len(key) == 32 and plaintext == EMPTY_PLAINTEXT
    manifest = open_manifest(data, KEK, **EXPECTED)
    assert (manifest.vault_id, manifest.generation_id, manifest.kek_generation_id, manifest.files) == (
        VAULT, GENERATION, KEK_ID, (),
    )


def test_man01_multifile_sorting_and_fresh_key_and_nonce():
    second = record(b"z" * 16, b"o" * 16, 2)
    first = record()
    data = seal_manifest(metadata(second, first), KEK)
    another = seal_manifest(metadata(first, second), KEK)
    assert int.from_bytes(data[60:64], "big") == 2
    key, canonical = unpack_plaintext(data)
    another_key, another_canonical = unpack_plaintext(another)
    assert canonical == another_canonical == encode(metadata(first, second))
    assert key != another_key and data[40:52] != another[40:52]
    entries = open_manifest(data, KEK, **EXPECTED).files
    assert [(entry.file_id, entry.cipher_id) for entry in entries] == [(FILE, 1), (b"z" * 16, 2)]
    assert entries[0].object_path == PurePosixPath("objects") / f"{OBJECT.hex()}.svlt"


def test_man01_with_verified_svkr():
    keyring, kek = create_keyring("test password", KDFParameters(8192, 1, 1))
    document = dict(metadata(), vault_id=keyring.vault_id.hex(), kek_generation_id=keyring.kek_generation_id.hex())
    from_disk = unlock_keyring(keyring.serialize(), "test password", expected_vault_id=keyring.vault_id)
    assert open_manifest(
        seal_manifest(document, kek), from_disk,
        expected_vault_id=keyring.vault_id, expected_generation_id=GENERATION,
        expected_kek_generation_id=keyring.kek_generation_id,
    ).files == ()


def test_man01_exact_entry_limit():
    records = [record(i.to_bytes(16, "big"), i.to_bytes(16, "big")) for i in range(10_000)]
    data = seal_manifest(metadata(*records), KEK)
    assert len(open_manifest(data, KEK, **EXPECTED).files) == 10_000


@pytest.mark.parametrize("offset,error", [
    (0, ManifestError), (4, ManifestError), (5, ManifestError), (6, ManifestError),
    (8, ManifestError), (24, ManifestError), (40, AuthenticationError),
    (63, AuthenticationError), (64, AuthenticationError), (104, AuthenticationError),
    (-1, AuthenticationError),
])
def test_man02_tampering(offset, error):
    data = bytearray(envelope(EMPTY_PLAINTEXT))
    data[offset] ^= 1
    with pytest.raises(error):
        open_manifest(bytes(data), KEK, **EXPECTED)


def test_man02_wrong_kek_and_expected_ids():
    data = envelope(EMPTY_PLAINTEXT)
    with pytest.raises(AuthenticationError):
        open_manifest(data, b"X" * 32, **EXPECTED)
    for field in ("expected_vault_id", "expected_generation_id"):
        with pytest.raises(ManifestError):
            open_manifest(data, KEK, **(EXPECTED | {field: b"X" * 16}))


def test_man02_valid_wrap_of_wrong_length_is_rejected():
    data = envelope(EMPTY_PLAINTEXT)
    wrapped = aes_key_wrap_with_padding(KEK, b"k" * 31)
    assert len(wrapped) == 40
    with pytest.raises(AuthenticationError, match="key length"):
        open_manifest(data[:64] + wrapped + data[104:], KEK, **EXPECTED)


@pytest.mark.parametrize("plaintext", [
    EMPTY_PLAINTEXT.replace(b'"schema":1', b'"schema":1,"schema":1'),
    EMPTY_PLAINTEXT.replace(b'"schema":1,', b''),
    EMPTY_PLAINTEXT.replace(b'"schema":1', b'"schema":1,"extra":1'),
    EMPTY_PLAINTEXT.replace(b'"schema":1', b'"schema":true'),
    EMPTY_PLAINTEXT.replace(b'"schema":1', b'"schema":1.0'),
    EMPTY_PLAINTEXT.replace(b'"schema":1', b'"schema":NaN'),
    EMPTY_PLAINTEXT.replace(b'"schema":1', b'"schema":-1'),
    EMPTY_PLAINTEXT.replace(b'"files":[]', b'"files":null'),
    EMPTY_PLAINTEXT.replace(b'"files":[]', b'"files":' + b'[' * 5000 + b']' * 5000),
    EMPTY_PLAINTEXT.replace(VAULT.hex().encode(), b'A' * 32),
    EMPTY_PLAINTEXT.replace(VAULT.hex().encode(), b'../invalid'),
    EMPTY_PLAINTEXT.replace(VAULT.hex().encode(), b'\xff'),
    EMPTY_PLAINTEXT.replace(b'0101', b'\\u003001'),
    EMPTY_PLAINTEXT + b'\n',
    b'\xef\xbb\xbf' + EMPTY_PLAINTEXT,
    b' ' + EMPTY_PLAINTEXT,
    json.dumps(metadata(), separators=(",", ":")).encode(),
])
def test_man03_authenticated_invalid_json(plaintext):
    with pytest.raises(ManifestError):
        open_manifest(envelope(plaintext), KEK, **EXPECTED)


@pytest.mark.parametrize("field,value", [
    ("cipher_id", True), ("cipher_id", 0), ("cipher_id", "1"),
    ("key_protection_id", True), ("key_protection_id", 0),
    ("object_id", "../invalid"), ("file_id", "a" * 31),
    ("kek_generation_id", "a" * 32), ("extra", 1),
])
def test_man03_invalid_file_record(field, value):
    records = metadata(record() | {field: value})
    with pytest.raises(ManifestError):
        open_manifest(envelope(encode(records), 1), KEK, **EXPECTED)
    with pytest.raises(ManifestError):
        seal_manifest(records, KEK)


def test_man03_duplicate_ids_missing_fields_and_unsorted_files():
    other = record(b"z" * 16, b"o" * 16)
    missing = deepcopy(other)
    del missing["object_id"]
    for records in [
        [record(), other | {"file_id": FILE.hex()}],
        [record(), other | {"object_id": OBJECT.hex()}],
        [missing],
        [other, record()],
    ]:
        with pytest.raises(ManifestError):
            open_manifest(envelope(encode(metadata(*records)), len(records)), KEK, **EXPECTED)


def test_man03_envelope_lengths_count_and_authenticated_header_disagreement():
    data = envelope(EMPTY_PLAINTEXT)
    for invalid in (
        data[:-1], data + b"\x00",
        data[:52] + (16 * 1024 * 1024 + 1).to_bytes(8, "big") + data[60:],
        data[:60] + (10_001).to_bytes(4, "big") + data[64:],
        envelope(EMPTY_PLAINTEXT, 1),
        envelope(encode(dict(metadata(), vault_id="f" * 32))),
        envelope(encode(dict(metadata(), generation_id="f" * 32))),
        envelope(encode(metadata(*[
            record(i.to_bytes(16, "big"), i.to_bytes(16, "big")) for i in range(10_001)
        ]))),
    ):
        with pytest.raises(ManifestError):
            open_manifest(invalid, KEK, **EXPECTED)


def test_man04_kek_generation_disagreement():
    with pytest.raises(ManifestError):
        open_manifest(envelope(EMPTY_PLAINTEXT), KEK, **(EXPECTED | {"expected_kek_generation_id": b"x" * 16}))


def test_man04_object_policy_and_wrapped_dek_association():
    manifest = open_manifest(seal_manifest(metadata(record()), KEK), KEK, **EXPECTED)
    dek = os.urandom(32)

    def object_data(file_id=FILE, cipher=1, protection=1, wrapped_id=FILE, wrapped_cipher=1):
        nonce = os.urandom(12 if cipher == 1 else 16)
        header = ContainerHeader(1, cipher, 0, file_id, nonce, 16)
        if cipher == 1:
            ciphertext, tag = encrypt_gcm(dek, nonce, bytes(16), header.serialize())
        else:
            ciphertext, tag = encrypt_cbc(dek, nonce, b"cbc fixture"), None
        wrapped = wrap_dek(KEK, wrapped_id, wrapped_cipher, dek) if protection else b""
        return parse_container(serialize_container(header, ciphertext, protection, wrapped, tag))

    assert manifest.unwrap_file_dek(FILE, OBJECT, object_data(), KEK, kek_generation_id=KEK_ID) == dek
    for container in (object_data(file_id=b"x" * 16), object_data(cipher=2), object_data(protection=0)):
        with pytest.raises(ManifestError):
            manifest.unwrap_file_dek(FILE, OBJECT, container, KEK, kek_generation_id=KEK_ID)
    for container in (object_data(wrapped_id=b"x" * 16), object_data(wrapped_cipher=2)):
        with pytest.raises(InvalidKeyError):
            manifest.unwrap_file_dek(FILE, OBJECT, container, KEK, kek_generation_id=KEK_ID)
    with pytest.raises(ManifestError):
        manifest.unwrap_file_dek(FILE, b"x" * 16, object_data(), KEK, kek_generation_id=KEK_ID)
    with pytest.raises(ManifestError):
        manifest.unwrap_file_dek(FILE, OBJECT, object_data(), KEK, kek_generation_id=b"x" * 16)
    cbc = open_manifest(seal_manifest(metadata(record(cipher=2)), KEK), KEK, **EXPECTED)
    assert cbc.unwrap_file_dek(
        FILE, OBJECT, object_data(cipher=2, wrapped_cipher=2), KEK, kek_generation_id=KEK_ID,
    ) == dek
