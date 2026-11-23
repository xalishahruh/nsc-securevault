"""SVRA v1 authenticated backups of active managed vault generations."""

import os
import stat
import struct
from contextlib import contextmanager
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from securevault.container import CIPHER_GCM, parse_container
from securevault.crypto.gcm import GCM_TAG_SIZE, generate_gcm_dek, generate_gcm_nonce
from securevault.errors import AuthenticationError, VaultError
from securevault.file_service import MAX_CONTAINER_SIZE
from securevault.kdf import validate_new_password
from securevault.key_wrap import KEK_SIZE
from securevault.keyring import protect_keyring, unlock_keyring
from securevault.manifest import Manifest, ManifestFile, open_manifest
from securevault.vault import (
    Vault, _MANIFEST_LIMIT, _commit, _current, _decrypt_object, _open_manifest, _records,
)
from securevault.vault_storage import directory, identity, initialize_layout, path_directory, publish, read, write_new

MAX_PAYLOAD_SIZE = 256 * 1024 * 1024
_HEADER = struct.Struct(">4sBBH12sQ")
_FORMAT = (b"SVRA", 1, CIPHER_GCM, 0)
_META = struct.Struct(">32s16s16s16sI")
_LENGTH = struct.Struct(">Q")
_MAX_ARCHIVE_SIZE = _HEADER.size + MAX_PAYLOAD_SIZE + GCM_TAG_SIZE


@contextmanager
def _storage_errors():
    try:
        yield
    except OSError as exc:
        raise VaultError(f"Recovery storage operation failed (OS error {exc.errno}).") from None


def _name(path: Path) -> str:
    if path.name in ("", "..") or ".." in path.parts:
        raise VaultError("Unsafe recovery path.")
    return path.name


def _writable_parent(parent: int) -> None:
    info = os.fstat(parent)
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise VaultError("Recovery output directory must be owned by the current user and protected from other writers.")


def _require_absent(parent: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise VaultError("Recovery destination already exists.")


def _publish_file(parent: int, name: str, data: bytes) -> None:
    temporary = ".svrecovery-" + os.urandom(16).hex()
    write_new(parent, temporary, data)
    try:
        publish(parent, temporary, parent, name)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass


def _verify_object(manifest: Manifest, entry: ManifestFile, raw: bytes, kek: bytes) -> None:
    container = parse_container(raw)
    dek = manifest.unwrap_file_dek(
        entry.file_id, entry.object_id, container, kek, kek_generation_id=manifest.kek_generation_id,
    )
    if entry.cipher_id == CIPHER_GCM:
        _decrypt_object(container, dek, entry.cipher_id)


def backup(vault: Vault, archive: Path, recovery_key: Path) -> None:
    """Publish an encrypted active snapshot and its independent offline key."""
    archive, recovery_key = Path(archive), Path(recovery_key)
    name, key_name = _name(archive), _name(recovery_key)
    if archive.suffix != ".svra" or recovery_key.suffix != ".svrecovery":
        raise VaultError("Use .svra for the archive and .svrecovery for the offline key.")
    with _storage_errors(), vault._open() as (store, ring, kek, ring_data):
        outside = identity(store.root)
        with (path_directory(archive.parent, outside=outside) as destination,
              path_directory(recovery_key.parent, outside=outside) as offline):
            _writable_parent(destination)
            _writable_parent(offline)
            if identity(destination) == identity(offline):
                raise VaultError("Keep the recovery key in a separate directory from the backup.")
            _require_absent(destination, name)
            _require_absent(offline, key_name)
            with store.writer() as lock:
                manifest = vault._active(store, ring, kek, ring_data)
                generation = manifest.generation_id
                with directory(store.generations, generation.hex()) as folder:
                    metadata = read(folder, "manifest.svmf", _MANIFEST_LIMIT)
                if _open_manifest(metadata, generation, ring, kek) != manifest:
                    raise VaultError("The backup manifest changed.")
                payload = bytearray(_META.pack(
                    kek, ring.vault_id, generation, ring.kek_generation_id, len(metadata),
                ))
                payload.extend(metadata)
                for entry in manifest.files:
                    remaining = MAX_PAYLOAD_SIZE - len(payload) - _LENGTH.size
                    if remaining <= 0:
                        raise VaultError("Backup exceeds the archive size limit.")
                    raw = read(store.objects, entry.object_path.name, min(remaining, MAX_CONTAINER_SIZE))
                    _verify_object(manifest, entry, raw, kek)
                    payload.extend(_LENGTH.pack(len(raw)))
                    payload.extend(raw)
                    del raw
                store.check_layout()
                store.check_writer(lock)
                if _current(store) != generation:
                    raise VaultError("Active generation changed during backup.")
            if len(payload) > MAX_PAYLOAD_SIZE:
                raise VaultError("Backup exceeds the archive size limit.")
            key, nonce = generate_gcm_dek(), generate_gcm_nonce()
            prefix = _HEADER.pack(*_FORMAT, nonce, len(payload))
            sealed = AESGCM(key).encrypt(nonce, payload, prefix)
            del payload
            _publish_file(offline, key_name, key)
            _publish_file(destination, name, prefix + sealed)


def _decrypt_archive(data: bytes, key: bytes) -> bytes:
    if len(key) != KEK_SIZE or len(data) < _HEADER.size + GCM_TAG_SIZE:
        raise VaultError("Invalid recovery key or archive size.")
    magic, version, cipher, flags, nonce, size = _HEADER.unpack_from(data)
    if (magic, version, cipher, flags) != _FORMAT:
        raise VaultError("Unsupported recovery archive format.")
    if size > MAX_PAYLOAD_SIZE or len(data) != _HEADER.size + size + GCM_TAG_SIZE:
        raise VaultError("Invalid recovery archive length.")
    try:
        return AESGCM(key).decrypt(nonce, memoryview(data)[_HEADER.size:], data[:_HEADER.size])
    except InvalidTag:
        raise AuthenticationError("Recovery archive authentication failed.") from None


def _verify_snapshot(payload: bytes) -> tuple[Manifest, bytes, list[tuple[int, int]]]:
    if len(payload) < _META.size:
        raise VaultError("Incomplete recovery metadata.")
    kek, vault_id, generation, kek_id, size = _META.unpack_from(payload)
    end = _META.size + size
    if size > _MANIFEST_LIMIT or end > len(payload):
        raise VaultError("Invalid recovery manifest length.")
    manifest = open_manifest(
        payload[_META.size:end], kek, expected_vault_id=vault_id, expected_generation_id=generation,
        expected_kek_generation_id=kek_id,
    )
    objects = []
    for entry in manifest.files:
        if end + _LENGTH.size > len(payload):
            raise VaultError("Missing recovery object.")
        (size,) = _LENGTH.unpack_from(payload, end)
        offset = end + _LENGTH.size
        end = offset + size
        if size == 0 or size > MAX_CONTAINER_SIZE or end > len(payload):
            raise VaultError("Invalid recovery object length.")
        _verify_object(manifest, entry, payload[offset:end], kek)
        objects.append((offset, end))
    if end != len(payload):
        raise VaultError("Unexpected trailing recovery data.")
    return manifest, kek, objects


def _remove_tree(parent: int, name: str) -> None:
    """Remove only the private staging directory created by this operation."""
    with directory(parent, name) as fd:
        for child in os.listdir(fd):
            if stat.S_ISDIR(os.stat(child, dir_fd=fd, follow_symlinks=False).st_mode):
                _remove_tree(fd, child)
            else:
                os.unlink(child, dir_fd=fd)
    os.rmdir(name, dir_fd=parent)


def _publish_restore(parent: int, stage: str, target: str) -> None:
    # mkdir reserves the name without clobbering even an empty existing destination.
    os.mkdir(target, 0o700, dir_fd=parent)
    try:
        os.rename(stage, target, src_dir_fd=parent, dst_dir_fd=parent)
    except BaseException:
        os.rmdir(target, dir_fd=parent)
        raise
    os.fsync(parent)


def restore(archive: Path, recovery_key: Path, destination: Path, new_password: str | bytes) -> None:
    """Validate an entire archive, then publish a new password-protected vault."""
    archive, recovery_key, destination = Path(archive), Path(recovery_key), Path(destination)
    target = _name(destination)
    validate_new_password(new_password)
    with _storage_errors(), path_directory(destination.parent) as parent:
        _writable_parent(parent)
        _require_absent(parent, target)
        with path_directory(recovery_key.parent) as offline:
            key = read(offline, _name(recovery_key), KEK_SIZE)
        with path_directory(archive.parent) as source:
            data = read(source, _name(archive), _MAX_ARCHIVE_SIZE, private=False)
        payload = _decrypt_archive(data, key)
        del data, key
        manifest, kek, offsets = _verify_snapshot(payload)
        ring = protect_keyring(new_password, kek, manifest.vault_id, manifest.kek_generation_id)
        if unlock_keyring(ring.serialize(), new_password) != kek:
            raise VaultError("Recovered keyring failed verification.")

        stage = ".svrestore-" + os.urandom(16).hex()
        os.mkdir(stage, 0o700, dir_fd=parent)
        try:
            with initialize_layout(parent, stage) as store, store.writer() as lock:
                objects = (
                    (entry.file_id, entry.object_id, payload[start:end], None)
                    for entry, (start, end) in zip(manifest.files, offsets)
                )
                _commit(store, lock, None, ring, kek, _records(manifest, ring), new_objects=objects)
            _publish_restore(parent, stage, target)
        finally:
            try:
                _remove_tree(parent, stage)
            except FileNotFoundError:
                pass
