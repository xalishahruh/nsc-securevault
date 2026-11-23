"""SVMF v1 authenticated manifests and managed file association policy."""

import json
import re
import struct
from bisect import bisect_left
from dataclasses import dataclass
from pathlib import PurePosixPath

from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap_with_padding,
    aes_key_wrap_with_padding,
)

from securevault.container import CIPHER_CBC, CIPHER_GCM, KEY_PROT_KWP, ParsedContainer
from securevault.crypto.gcm import (
    GCM_KEY_SIZE, GCM_TAG_SIZE, decrypt_gcm, encrypt_gcm, generate_gcm_dek, generate_gcm_nonce,
)
from securevault.errors import AuthenticationError, ManifestError
from securevault.key_wrap import KEK_SIZE, unwrap_dek

_HEADER = struct.Struct(">4sBBH16s16s12sQI")
_FORMAT = (b"SVMF", 1, CIPHER_GCM, 0)
AAD_SIZE = _HEADER.size + 40
MAX_METADATA_SIZE = 16 * 1024 * 1024
MAX_ENTRIES = 10_000
_TOP_FIELDS = {"schema", "vault_id", "generation_id", "kek_generation_id", "files"}
_FILE_FIELDS = {"file_id", "object_id", "cipher_id", "key_protection_id", "kek_generation_id"}
_HEX_ID = re.compile("[0-9a-f]{32}")
_JSON_STRUCTURE = re.compile(rb'["{}\[\]]')


@dataclass(frozen=True, repr=False, slots=True)
class ManifestFile:
    file_id: bytes
    object_id: bytes
    cipher_id: int

    @property
    def object_path(self) -> PurePosixPath:
        """Relative vault path. Filesystem confinement is the caller's responsibility."""
        return PurePosixPath("objects", self.object_id.hex() + ".svlt")


@dataclass(frozen=True, repr=False, slots=True)
class Manifest:
    """Decoded metadata. Use open_manifest to obtain it from storage."""

    vault_id: bytes
    generation_id: bytes
    kek_generation_id: bytes
    files: tuple[ManifestFile, ...]

    def file(self, file_id: bytes) -> ManifestFile:
        _require_bytes(file_id, 16)
        index = bisect_left(self.files, file_id, key=lambda entry: entry.file_id)
        if index == len(self.files) or self.files[index].file_id != file_id:
            raise ManifestError("File is absent from the manifest.")
        return self.files[index]

    def unwrap_file_dek(
        self, file_id: bytes, object_id: bytes, container: ParsedContainer, kek: bytes,
        *, kek_generation_id: bytes,
    ) -> bytes:
        """Check the selected object and unwrap under the verified SVKR generation."""
        _require_bytes(object_id, 16)
        _require_bytes(kek_generation_id, 16)
        entry = self.file(file_id)
        if (
            object_id != entry.object_id
            or kek_generation_id != self.kek_generation_id
            or container.header.file_id != entry.file_id
            or container.header.cipher_id != entry.cipher_id
            or container.key_protection_id != KEY_PROT_KWP
        ):
            raise ManifestError("Object does not match the authenticated file policy.")
        return unwrap_dek(kek, container.key_record, entry.file_id, entry.cipher_id)


def _require_bytes(value: bytes, size: int) -> None:
    if type(value) is not bytes or len(value) != size:
        raise ManifestError(f"Expected exactly {size} bytes.")


def _hex_id(value: object) -> bytes:
    if type(value) is not str or _HEX_ID.fullmatch(value) is None:
        raise ManifestError("Invalid manifest identifier.")
    return bytes.fromhex(value)


def _validate(document: dict) -> Manifest:
    if type(document) is not dict or document.keys() != _TOP_FIELDS:
        raise ManifestError("Invalid manifest fields.")
    if type(document["schema"]) is not int or document["schema"] != 1:
        raise ManifestError("Unsupported manifest schema.")
    vault_id = _hex_id(document["vault_id"])
    generation_id = _hex_id(document["generation_id"])
    kek_generation_id = _hex_id(document["kek_generation_id"])
    files = document["files"]
    if type(files) is not list or len(files) > MAX_ENTRIES:
        raise ManifestError("Invalid manifest file list.")
    entries = []
    file_ids = set()
    object_ids = set()
    for record in files:
        if type(record) is not dict or record.keys() != _FILE_FIELDS:
            raise ManifestError("Invalid manifest file fields.")
        file_id = _hex_id(record["file_id"])
        object_id = _hex_id(record["object_id"])
        if file_id in file_ids or object_id in object_ids:
            raise ManifestError("Duplicate manifest file or object identifier.")
        file_ids.add(file_id)
        object_ids.add(object_id)
        cipher, protection = record["cipher_id"], record["key_protection_id"]
        if type(cipher) is not int or cipher not in (CIPHER_GCM, CIPHER_CBC):
            raise ManifestError("Unsupported manifest file cipher.")
        if type(protection) is not int or protection != KEY_PROT_KWP:
            raise ManifestError("Unsupported manifest key protection.")
        if _hex_id(record["kek_generation_id"]) != kek_generation_id:
            raise ManifestError("File KEK generation does not match the manifest.")
        entries.append(ManifestFile(file_id, object_id, cipher))
    return Manifest(vault_id, generation_id, kek_generation_id, tuple(sorted(entries, key=lambda entry: entry.file_id)))


def _canonical(document: dict) -> bytes:
    ordered = {**document, "files": sorted(document["files"], key=lambda record: record["file_id"])}
    return json.dumps(
        ordered, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _unique_object(pairs: list[tuple]) -> dict:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ManifestError("Duplicate manifest JSON key.")
    return result


def _reject_number(_: str) -> int:
    raise ManifestError("Invalid manifest JSON number.")


def _integer(token: str) -> int:
    if token not in ("1", "2"):
        return _reject_number(token)
    return int(token)


def _decode(plaintext: bytes) -> Manifest:
    # Canonical identifiers and field names never use escapes. Bound nesting before json.loads.
    if b"\\" in plaintext:
        raise ManifestError("Manifest JSON must not use escapes.")
    # Four top-level commas, four per file record, and separators between records.
    if plaintext.count(b",") > 4 + 5 * MAX_ENTRIES - 1:
        raise ManifestError("Manifest JSON has too many fields or entries.")
    depth = 0
    quoted = False
    for token in _JSON_STRUCTURE.finditer(plaintext):
        char = token[0]
        if char == b'"':
            quoted = not quoted
        elif not quoted:
            depth += 1 if char in (b"{", b"[") else -1
            if not 0 <= depth <= 3:
                raise ManifestError("Invalid manifest JSON depth.")
    try:
        document = json.loads(
            plaintext.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_int=_integer, parse_float=_reject_number, parse_constant=_reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ManifestError("Invalid manifest JSON.") from None
    manifest = _validate(document)
    if _canonical(document) != plaintext:
        raise ManifestError("Manifest JSON is not canonical.")
    return manifest


def seal_manifest(document: dict, kek: bytes) -> bytes:
    """Validate metadata and encrypt its canonical representation under the vault KEK."""
    _require_bytes(kek, KEK_SIZE)
    manifest = _validate(document)
    plaintext = _canonical(document)
    if len(plaintext) > MAX_METADATA_SIZE:
        raise ManifestError("Manifest metadata exceeds the size limit.")
    key, nonce = generate_gcm_dek(), generate_gcm_nonce()
    header = _HEADER.pack(
        *_FORMAT, manifest.vault_id, manifest.generation_id, nonce, len(plaintext), len(manifest.files),
    )
    prefix = header + aes_key_wrap_with_padding(kek, key)
    ciphertext, tag = encrypt_gcm(key, nonce, plaintext, associated_data=prefix)
    return prefix + ciphertext + tag


def open_manifest(
    data: bytes, kek: bytes, *, expected_vault_id: bytes, expected_generation_id: bytes,
    expected_kek_generation_id: bytes,
) -> Manifest:
    """Open SVMF with a verified SVKR KEK/IDs and a caller-selected generation ID."""
    _require_bytes(kek, KEK_SIZE)
    for identifier in (expected_vault_id, expected_generation_id, expected_kek_generation_id):
        _require_bytes(identifier, 16)
    if type(data) is not bytes or len(data) < AAD_SIZE + GCM_TAG_SIZE:
        raise ManifestError("Invalid manifest envelope.")
    magic, version, cipher, flags, vault_id, generation_id, nonce, size, count = _HEADER.unpack_from(data)
    if (magic, version, cipher, flags) != _FORMAT:
        raise ManifestError("Unsupported manifest envelope.")
    if size > MAX_METADATA_SIZE or count > MAX_ENTRIES or len(data) != AAD_SIZE + size + GCM_TAG_SIZE:
        raise ManifestError("Invalid manifest size or entry count.")
    if (vault_id, generation_id) != (expected_vault_id, expected_generation_id):
        raise ManifestError("Manifest does not match the expected vault or generation.")
    try:
        key = aes_key_unwrap_with_padding(kek, data[_HEADER.size:AAD_SIZE])
    except InvalidUnwrap:
        raise AuthenticationError("Manifest key authentication failed.") from None
    if len(key) != GCM_KEY_SIZE:
        raise AuthenticationError("Invalid wrapped manifest key length.")
    plaintext = decrypt_gcm(
        key, nonce, data[AAD_SIZE:-GCM_TAG_SIZE], data[-GCM_TAG_SIZE:], associated_data=data[:AAD_SIZE],
    )
    manifest = _decode(plaintext)
    if (
        (manifest.vault_id, manifest.generation_id, manifest.kek_generation_id)
        != (vault_id, generation_id, expected_kek_generation_id)
        or len(manifest.files) != count
    ):
        raise ManifestError("Authenticated manifest identifiers or count disagree.")
    return manifest
