"""Managed vault sessions and CURRENT-last generation transactions."""

import os
import re
from contextlib import contextmanager
from pathlib import Path

from securevault.container import (
    CIPHER_CBC, CIPHER_GCM, KEY_PROT_KWP, MAX_CIPHERTEXT_SIZE,
    ContainerHeader, ParsedContainer, parse_container, serialize_container,
)
from securevault.crypto.cbc import decrypt_cbc, encrypt_cbc, generate_cbc_iv
from securevault.crypto.gcm import GCM_TAG_SIZE, decrypt_gcm, encrypt_gcm, generate_gcm_dek, generate_gcm_nonce
from securevault.errors import ModeMismatchError, VaultError
from securevault.file_service import MAX_CONTAINER_SIZE
from securevault.key_wrap import wrap_dek
from securevault.keyring import KEYRING_SIZE, Keyring, create_keyring, unlock_keyring
from securevault.manifest import AAD_SIZE, MAX_ENTRIES, MAX_METADATA_SIZE, Manifest, open_manifest, seal_manifest
from securevault.vault_storage import (
    Storage, directory, identity, open_storage, path_directory, publish, read, write_new,
)

_CURRENT = re.compile(rb"SVCR1\n([0-9a-f]{32})\n")
_CURRENT_SIZE = 39
_MANIFEST_LIMIT = AAD_SIZE + MAX_METADATA_SIZE + GCM_TAG_SIZE
_MODES = {"gcm": CIPHER_GCM, "cbc": CIPHER_CBC}


def _current(store: Storage) -> bytes:
    match = _CURRENT.fullmatch(read(store.root, "CURRENT", _CURRENT_SIZE))
    if match is None:
        raise VaultError("Invalid CURRENT pointer.")
    return bytes.fromhex(match[1].decode("ascii"))


def _load_manifest(store: Storage, generation: bytes, ring: Keyring, kek: bytes) -> Manifest:
    with directory(store.generations, generation.hex()) as folder:
        return _open_manifest(read(folder, "manifest.svmf", _MANIFEST_LIMIT), generation, ring, kek)


def _open_manifest(data: bytes, generation: bytes, ring: Keyring, kek: bytes) -> Manifest:
    return open_manifest(
        data, kek, expected_vault_id=ring.vault_id,
        expected_generation_id=generation, expected_kek_generation_id=ring.kek_generation_id,
    )


def _record(file_id: bytes, object_id: bytes, cipher: int, ring: Keyring) -> dict:
    return {
        "file_id": file_id.hex(), "object_id": object_id.hex(), "cipher_id": cipher,
        "key_protection_id": KEY_PROT_KWP, "kek_generation_id": ring.kek_generation_id.hex(),
    }


def _decode_object(
    manifest: Manifest, file_id: bytes, object_id: bytes, raw: bytes, ring: Keyring, kek: bytes,
) -> tuple[ParsedContainer, bytes]:
    container = parse_container(raw)
    dek = manifest.unwrap_file_dek(file_id, object_id, container, kek, kek_generation_id=ring.kek_generation_id)
    return container, dek


def _verify_inventory(store: Storage, manifest: Manifest, ring: Keyring, kek: bytes) -> None:
    for entry in manifest.files:
        raw = read(store.objects, entry.object_path.name, MAX_CONTAINER_SIZE)
        _decode_object(manifest, entry.file_id, entry.object_id, raw, ring, kek)


def _decrypt_object(container: ParsedContainer, dek: bytes, cipher: int) -> bytes:
    if cipher == CIPHER_GCM:
        return decrypt_gcm(
            dek, container.header.iv_or_nonce, container.ciphertext,
            container.gcm_tag, associated_data=container.immutable_header_bytes,
        )
    return decrypt_cbc(dek, container.header.iv_or_nonce, container.ciphertext)


def _encrypt_object(data: bytes, file_id: bytes, cipher: int, kek: bytes) -> bytes:
    dek = generate_gcm_dek()
    if cipher == CIPHER_GCM:
        nonce = generate_gcm_nonce()
        header = ContainerHeader(1, cipher, 0, file_id, nonce, len(data))
        ciphertext, tag = encrypt_gcm(dek, nonce, data, associated_data=header.serialize())
    else:
        iv = generate_cbc_iv()
        ciphertext = encrypt_cbc(dek, iv, data)
        header = ContainerHeader(1, cipher, 0, file_id, iv, len(ciphertext))
        tag = None
    return serialize_container(header, ciphertext, KEY_PROT_KWP, wrap_dek(kek, file_id, cipher, dek), tag)


def _activate(store: Storage, stage: int) -> None:
    os.replace("CURRENT", "CURRENT", src_dir_fd=stage, dst_dir_fd=store.root)
    os.fsync(store.root)


def _commit(
    store: Storage, lock: int, previous: bytes | None, ring: Keyring, kek: bytes,
    records: list[dict], *, new_object: tuple[bytes, bytes, bytes, bytes] | None = None,
) -> None:
    generation = os.urandom(16)
    name = generation.hex()
    document = {
        "schema": 1, "vault_id": ring.vault_id.hex(), "generation_id": name,
        "kek_generation_id": ring.kek_generation_id.hex(), "files": records,
    }
    ring_data = ring.serialize()
    pointer = b"SVCR1\n" + name.encode("ascii") + b"\n"
    with store.stage(name) as stage:
        write_new(stage, "keyring", ring_data)
        write_new(stage, "manifest.svmf", seal_manifest(document, kek))
        write_new(stage, "CURRENT", pointer)
        verified = _open_manifest(read(stage, "manifest.svmf", _MANIFEST_LIMIT), generation, ring, kek)
        if read(stage, "keyring", KEYRING_SIZE) != ring_data:
            raise VaultError("Staged keyring failed verification.")
        if new_object is not None:
            file_id, object_id, encoded, plaintext = new_object
            write_new(stage, "object", encoded)
            raw = read(stage, "object", MAX_CONTAINER_SIZE)
            parsed, dek = _decode_object(verified, file_id, object_id, raw, ring, kek)
            if _decrypt_object(parsed, dek, verified.file(file_id).cipher_id) != plaintext:
                raise VaultError("Staged object failed verification.")
            publish(stage, "object", store.objects, verified.file(file_id).object_path.name)
        publish(stage, "keyring", store.keyrings, name + ".keys")
        os.mkdir(name, 0o700, dir_fd=store.generations)
        with directory(store.generations, name) as target:
            publish(stage, "manifest.svmf", target, "manifest.svmf")
        os.fsync(store.generations)
        published = _load_manifest(store, generation, ring, kek)
        if published != verified or read(store.keyrings, name + ".keys", KEYRING_SIZE) != ring_data:
            raise VaultError("Published generation failed verification.")
        _verify_inventory(store, published, ring, kek)
        if new_object is not None and read(
            store.objects, published.file(file_id).object_path.name, MAX_CONTAINER_SIZE,
        ) != encoded:
            raise VaultError("Published object failed verification.")
        store.check_layout()
        store.check_writer(lock)
        if previous is None:
            try:
                read(store.root, "CURRENT", _CURRENT_SIZE)
            except FileNotFoundError:
                pass
            else:
                raise VaultError("The vault already has an active generation.")
        elif _current(store) != previous:
            raise VaultError("Active generation changed during the update.")
        if read(stage, "CURRENT", _CURRENT_SIZE) != pointer:
            raise VaultError("Staged pointer failed verification.")
        os.fsync(stage)
        _activate(store, stage)


class Vault:
    """Process-local session. Operations read and verify metadata from disk."""

    __slots__ = ("_root", "_session")

    def __init__(self, root: Path):
        self._root = Path(root).absolute()
        self._session = None

    @classmethod
    def initialize(cls, root: Path, password: str | bytes) -> None:
        root = Path(root).absolute()
        if root.name in ("", "..") or ".." in root.parts:
            raise VaultError("Unsafe vault root.")
        ring, kek = create_keyring(password)
        verified_kek = unlock_keyring(
            ring.serialize(), password, expected_vault_id=ring.vault_id,
            expected_kek_generation_id=ring.kek_generation_id,
        )
        if verified_kek != kek:
            raise VaultError("Initial keyring failed verification.")
        with open_storage(root, create=True) as store, store.writer() as lock:
            _commit(store, lock, None, ring, kek, [])

    def unlock(self, password: str | bytes) -> None:
        self.lock()
        with open_storage(self._root) as store:
            generation = _current(store)
            keyring_data = read(store.keyrings, generation.hex() + ".keys", KEYRING_SIZE)
            ring = Keyring.parse(keyring_data)
            kek = unlock_keyring(keyring_data, password)
            manifest = _load_manifest(store, generation, ring, kek)
            _verify_inventory(store, manifest, ring, kek)
            self._session = (identity(store.root), ring, kek, keyring_data)

    def lock(self) -> None:
        self._session = None

    @contextmanager
    def _open(self):
        if self._session is None:
            raise VaultError("Vault is locked.")
        root_id, ring, kek, keyring_data = self._session
        with open_storage(self._root) as store:
            if identity(store.root) != root_id:
                raise VaultError("The unlocked vault directory was replaced.")
            yield store, ring, kek, keyring_data

    @staticmethod
    def _active(store: Storage, ring: Keyring, kek: bytes, keyring_data: bytes) -> Manifest:
        generation = _current(store)
        if read(store.keyrings, generation.hex() + ".keys", KEYRING_SIZE) != keyring_data:
            raise VaultError("The active keyring changed. Unlock the vault again.")
        return _load_manifest(store, generation, ring, kek)

    def list_files(self) -> tuple[tuple[str, str], ...]:
        with self._open() as (store, ring, kek, keyring_data):
            manifest = self._active(store, ring, kek, keyring_data)
            _verify_inventory(store, manifest, ring, kek)
            return tuple((entry.file_id.hex(), "gcm" if entry.cipher_id == CIPHER_GCM else "cbc")
                         for entry in manifest.files)

    def inspect(self) -> dict:
        with self._open() as (store, ring, kek, keyring_data):
            manifest = self._active(store, ring, kek, keyring_data)
            _verify_inventory(store, manifest, ring, kek)
            return {"vault_id": ring.vault_id.hex(), "generation_id": manifest.generation_id.hex(),
                    "file_count": len(manifest.files)}

    def add(self, source: Path, *, mode: str = "gcm") -> str:
        if mode not in _MODES:
            raise ModeMismatchError("Unsupported cipher mode.")
        cipher = _MODES[mode]
        source = Path(source)
        if source.name in ("", ".."):
            raise VaultError("Unsafe input name.")
        with self._open() as (store, ring, kek, keyring_data):
            with path_directory(source.parent, outside=identity(store.root)) as parent:
                plaintext = read(parent, source.name, MAX_CIPHERTEXT_SIZE - (cipher == CIPHER_CBC), private=False)
            file_id, object_id = os.urandom(16), os.urandom(16)
            encoded = _encrypt_object(plaintext, file_id, cipher, kek)
            with store.writer() as lock:
                current = self._active(store, ring, kek, keyring_data)
                if len(current.files) >= MAX_ENTRIES:
                    raise VaultError("Vault entry limit reached.")
                records = [_record(entry.file_id, entry.object_id, entry.cipher_id, ring) for entry in current.files]
                records.append(_record(file_id, object_id, cipher, ring))
                _commit(store, lock, current.generation_id, ring, kek, records,
                        new_object=(file_id, object_id, encoded, plaintext))
            return file_id.hex()

    def extract(self, file_id: str, output: Path, *, require_mode: str | None = None) -> str:
        if type(file_id) is not str or re.fullmatch("[0-9a-f]{32}", file_id) is None:
            raise VaultError("Invalid file identifier.")
        if require_mode is not None and require_mode not in _MODES:
            raise ModeMismatchError("Unsupported cipher policy.")
        output = Path(output)
        if output.name in ("", ".."):
            raise VaultError("Unsafe output name.")
        with self._open() as (store, ring, kek, keyring_data):
            manifest = self._active(store, ring, kek, keyring_data)
            entry = manifest.file(bytes.fromhex(file_id))
            if require_mode is not None and _MODES[require_mode] != entry.cipher_id:
                raise ModeMismatchError("File does not satisfy the required cipher policy.")
            raw = read(store.objects, entry.object_path.name, MAX_CONTAINER_SIZE)
            container, dek = _decode_object(manifest, entry.file_id, entry.object_id, raw, ring, kek)
            plaintext = _decrypt_object(container, dek, entry.cipher_id)
            with path_directory(output.parent, outside=identity(store.root)) as parent:
                info = os.fstat(parent)
                if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    raise VaultError("Output directory must be owned by the current user and not writable by others.")
                temporary = ".securevault-" + os.urandom(16).hex()
                write_new(parent, temporary, plaintext)
                try:
                    publish(parent, temporary, parent, output.name)
                finally:
                    try:
                        os.unlink(temporary, dir_fd=parent)
                    except FileNotFoundError:
                        pass
            return "gcm" if entry.cipher_id == CIPHER_GCM else "cbc"
