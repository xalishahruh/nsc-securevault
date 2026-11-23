"""REC-01–04 with real encrypted vault data and process interruption."""

import errno
import os
import stat
import subprocess
import sys
import time

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from securevault.cli import main
from securevault.errors import AuthenticationError, KeyringError, ManifestError, VaultError
from securevault.recovery import backup, restore
from securevault.vault import Vault

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Managed vault storage requires POSIX")
OLD = "synthetic source password"
NEW = "synthetic recovered password"
GCM = bytes(range(256)) * 8
CBC = b"another synthetic fixture"


@pytest.fixture
def source(tmp_path):
    base = tmp_path.resolve()
    root = base / "source"
    Vault.initialize(root, OLD)
    vault = Vault(root)
    vault.unlock(OLD)
    source_file = base / "input"
    source_file.write_bytes(GCM)
    gcm = vault.add(source_file)
    source_file.write_bytes(CBC)
    cbc = vault.add(source_file, mode="cbc")
    offline = base / "offline"
    offline.mkdir(mode=0o700)
    return base, vault, {gcm: (GCM, "gcm"), cbc: (CBC, "cbc")}, offline


@pytest.fixture
def snapshot(source):
    base, vault, files, offline = source
    archive, key = base / "backup.svra", offline / "snapshot.svrecovery"
    backup(vault, archive, key)
    return base, files, archive, key


def _assert_restored(root, files, password=NEW):
    vault = Vault(root)
    vault.unlock(password)
    assert dict(vault.list_files()) == {ident: mode for ident, (_, mode) in files.items()}
    for ident, (data, mode) in files.items():
        target = root.parent / ("out-" + ident)
        vault.extract(ident, target, require_mode=mode)
        assert target.read_bytes() == data


def test_rec01_rec03_recover_current_snapshot_without_old_password(snapshot):
    base, files, archive, key = snapshot
    source_root = base / "source"
    assert len(list((source_root / "keyrings").glob("*.keys"))) == 3
    source_root.rename(base / "offline-source")
    raw, secret = archive.read_bytes(), key.read_bytes()
    assert raw[:8] == b"SVRA\x01\x01\x00\x00"
    assert len(raw) == 44 + int.from_bytes(raw[20:28], "big")
    assert len(secret) == 32 and secret not in raw
    assert stat.S_IMODE(key.stat().st_mode) == stat.S_IMODE(archive.stat().st_mode) == 0o600
    destination = base / "restored"
    restore(archive, key, destination, NEW)
    with pytest.raises(KeyringError):
        Vault(destination).unlock(OLD)
    _assert_restored(destination, files)
    assert len(list((destination / "keyrings").glob("*.keys"))) == 1
    assert len(list((destination / "generations").iterdir())) == 1
    assert not any(p.read_bytes() == secret for p in destination.rglob("*") if p.is_file())
    assert not list(base.glob(".svrestore-*"))
    assert len(list((base / "offline-source" / "keyrings").glob("*.keys"))) == 3


def test_rec01_empty_vault_and_fresh_independent_keys(tmp_path):
    base = tmp_path.resolve()
    offline = base / "offline"
    offline.mkdir()
    root = base / "vault"
    Vault.initialize(root, OLD)
    vault = Vault(root)
    vault.unlock(OLD)
    keys, archives = [], []
    for i in range(2):
        archive, key = base / f"{i}.svra", offline / f"{i}.svrecovery"
        backup(vault, archive, key)
        keys.append(key)
        archives.append(archive)
    assert keys[0].read_bytes() != keys[1].read_bytes()
    assert archives[0].read_bytes()[8:20] != archives[1].read_bytes()[8:20]
    with pytest.raises(AuthenticationError):
        restore(archives[1], keys[0], base / "substituted", NEW)
    assert not (base / "substituted").exists()
    restore(archives[0], keys[0], base / "restored", NEW)
    _assert_restored(base / "restored", {})


@pytest.mark.parametrize("problem", ["wrong-key", "short-key", "truncated", "trailing", "header", "nonce", "ciphertext", "tag", "oversized"])
def test_rec02_bad_recovery_input_has_no_destination(snapshot, problem):
    base, _, archive, key = snapshot
    data = bytearray(archive.read_bytes())
    if problem in ("wrong-key", "short-key"):
        key.write_bytes(os.urandom(32 if problem == "wrong-key" else 31))
    elif problem == "oversized":
        data[20:28] = (256 * 1024 * 1024 + 1).to_bytes(8, "big")
    elif problem == "truncated":
        del data[-1:]
    elif problem == "trailing":
        data.extend(b"\0")
    else:
        i = {"header": 6, "nonce": 8, "ciphertext": 28, "tag": -1}[problem]
        data[i] ^= 1
    archive.write_bytes(data)
    with pytest.raises((AuthenticationError, VaultError)):
        restore(archive, key, base / "restored", NEW)
    assert not (base / "restored").exists()
    assert not list(base.glob(".svrestore-*"))


def _authenticated_fixture(archive, key, edit):
    raw, recovery = archive.read_bytes(), key.read_bytes()
    plain = AESGCM(recovery).decrypt(raw[8:20], raw[28:], raw[:28])
    edited = edit(plain)
    nonce = os.urandom(12)
    prefix = b"SVRA\x01\x01\x00\x00" + nonce + len(edited).to_bytes(8, "big")
    archive.write_bytes(prefix + AESGCM(recovery).encrypt(nonce, edited, prefix))


@pytest.mark.parametrize("problem", ["missing-object", "manifest-id", "substituted-object", "corrupt-gcm", "extra-body"])
def test_rec02_authenticated_but_inconsistent_snapshot_is_rejected(snapshot, problem):
    base, _, archive, key = snapshot

    def edit(plain):
        start = 84 + int.from_bytes(plain[80:84], "big")
        first_len = int.from_bytes(plain[start:start + 8], "big")
        end = start + 8 + first_len
        if problem == "missing-object":
            return plain[:end]
        if problem == "substituted-object":
            return plain[:start] + plain[end:] + plain[start:end]
        if problem == "manifest-id":
            return plain[:32] + bytes([plain[32] ^ 1]) + plain[33:]
        if problem == "extra-body":
            return plain + b"extra"
        offset = start
        for _ in range(2):
            size = int.from_bytes(plain[offset:offset + 8], "big")
            if plain[offset + 8 + 5] == 1:
                position = offset + 8 + 115
                return plain[:position] + bytes([plain[position] ^ 1]) + plain[position + 1:]
            offset += 8 + size
        raise AssertionError("fixture must contain a GCM object")

    _authenticated_fixture(archive, key, edit)
    with pytest.raises((VaultError, ManifestError, AuthenticationError)):
        restore(archive, key, base / "restore", NEW)
    assert not (base / "restore").exists()
    assert not list(base.glob(".svrestore-*"))


def test_rec04_preserve_existing_destination_and_reject_symlinks(snapshot):
    base, _, archive, key = snapshot
    original = (base / "source" / "CURRENT").read_bytes()
    existing = base / "empty"
    existing.mkdir()
    alias = base / "alias"
    alias.symlink_to(base / "source")
    for target in (base / "source", existing, alias):
        with pytest.raises(VaultError, match="already exists"):
            restore(archive, key, target, NEW)
    assert (base / "source" / "CURRENT").read_bytes() == original
    assert not list(existing.iterdir())
    assert alias.is_symlink()
    key_alias = key.with_name("link.svrecovery")
    key_alias.symlink_to(key)
    with pytest.raises(VaultError):
        restore(archive, key_alias, base / "restored", NEW)
    assert not (base / "restored").exists()


def test_rec04_backup_failures_preserve_good_backup_and_clean_staging(source, monkeypatch):
    import securevault.recovery as module

    base, vault, _, offline = source
    archive, key = base / "good.svra", offline / "good.svrecovery"
    backup(vault, archive, key)
    original = archive.read_bytes(), key.read_bytes()
    with pytest.raises(VaultError):
        backup(vault, archive, key)
    assert (archive.read_bytes(), key.read_bytes()) == original
    with pytest.raises(VaultError, match="separate directory"):
        backup(vault, base / "shared.svra", base / "key.svrecovery")
    original_publish = module.publish

    def fail_archive(stage, name, parent, target):
        if target.endswith(".svra"):
            raise OSError(errno.EIO, "synthetic archive publish failure")
        original_publish(stage, name, parent, target)

    monkeypatch.setattr(module, "publish", fail_archive)
    with pytest.raises(VaultError):
        backup(vault, base / "failed.svra", offline / "fresh.svrecovery")
    assert not (base / "failed.svra").exists()
    assert not list(base.glob(".svrecovery-*")) and not list(offline.glob(".svrecovery-*"))
    assert (archive.read_bytes(), key.read_bytes()) == original


def test_rec04_corrupt_source_and_total_size_limit_publish_nothing(source, monkeypatch):
    import securevault.recovery as module

    base, vault, _, offline = source
    archive, key = base / "rejected.svra", offline / "rejected.svrecovery"
    gcm = next(p for p in (base / "source" / "objects").glob("*.svlt") if p.read_bytes()[5] == 1)
    raw = bytearray(gcm.read_bytes())
    raw[115] ^= 1
    gcm.write_bytes(raw)
    with pytest.raises(AuthenticationError):
        backup(vault, archive, key)
    raw[115] ^= 1
    gcm.write_bytes(raw)
    monkeypatch.setattr(module, "MAX_PAYLOAD_SIZE", 512)
    with pytest.raises(VaultError, match="limit"):
        backup(vault, archive, key)
    assert not archive.exists() and not key.exists()


def test_rec04_restore_rename_failure_removes_stage_and_reservation(snapshot, monkeypatch):
    base, _, archive, key = snapshot

    def fail_rename(*args, **kwargs):
        raise OSError(errno.EIO, "synthetic directory promotion failure")

    monkeypatch.setattr("securevault.recovery.os.rename", fail_rename)
    with pytest.raises(VaultError):
        restore(archive, key, base / "restored", NEW)
    assert not (base / "restored").exists()
    assert not list(base.glob(".svrestore-*"))


def test_rec04_does_not_overwrite_destination_created_during_restore(snapshot, monkeypatch):
    import securevault.recovery as module

    base, _, archive, key = snapshot
    target = base / "restored"
    original = module._publish_restore

    def compete(parent, stage, name):
        target.mkdir()
        (target / "marker").write_bytes(b"preserve destination")
        original(parent, stage, name)

    monkeypatch.setattr(module, "_publish_restore", compete)
    with pytest.raises(VaultError):
        restore(archive, key, target, NEW)
    assert (target / "marker").read_bytes() == b"preserve destination"
    assert not list(base.glob(".svrestore-*"))


_CRASH_RESTORE = """
import os
import sys
from pathlib import Path
from securevault import recovery, vault

archive, key, target, boundary = sys.argv[1:]
if boundary == "current":
    def stop(*args, **kwargs):
        os._exit(73)
    vault._activate = stop
else:
    original = recovery.os.rename
    def stop_at_rename(*args, **kwargs):
        if boundary == "after":
            original(*args, **kwargs)
        os._exit(73)
    recovery.os.rename = stop_at_rename
recovery.restore(Path(archive), Path(key), Path(target), "synthetic recovered password")
"""


@pytest.mark.parametrize("boundary", ["current", "rename", "after"])
def test_rec04_real_process_exit_observes_no_partial_active_destination(snapshot, boundary):
    base, files, archive, key = snapshot
    target = base / "restored"
    result = subprocess.run(
        [sys.executable, "-c", _CRASH_RESTORE, str(archive), str(key), str(target), boundary],
        capture_output=True, timeout=20,
    )
    assert result.returncode == 73, result.stderr.decode()
    if boundary == "after":
        _assert_restored(target, files)
        assert not list(base.glob(".svrestore-*"))
    else:
        assert not (target / "CURRENT").exists()
        interrupted, = base.glob(".svrestore-*")
        assert stat.S_IMODE(interrupted.stat().st_mode) == 0o700
        if boundary == "rename":
            assert target.is_dir() and not list(target.iterdir())
        else:
            assert not target.exists()
        retry = base / "retry"
        restore(archive, key, retry, NEW)
        _assert_restored(retry, files)


_BACKUP_WITH_GATE = """
import sys
import time
from pathlib import Path
from securevault import recovery
from securevault.vault import Vault
base = Path(sys.argv[1])
vault = Vault(base / "source")
vault.unlock("synthetic source password")
verify = recovery._verify_object
def pause(*args):
    (base / "backup-locked").touch()
    deadline = time.monotonic() + 10
    while not (base / "backup-go").exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("backup gate timed out")
        time.sleep(0.01)
    verify(*args)
recovery._verify_object = pause
recovery.backup(vault, base / "consistent.svra", base / "offline" / "consistent.svrecovery")
"""

_WRITER_WITH_GATE = """
import sys
from pathlib import Path
from securevault.vault import Vault
base = Path(sys.argv[1])
vault = Vault(base / "source")
vault.unlock("synthetic source password")
(base / "writer-ready").touch()
vault.add(base / "input")
"""


def test_rec01_backup_holds_snapshot_lock_against_independent_writer(source):
    base, vault, files, offline = source

    def start(code):
        return subprocess.Popen(
            [sys.executable, "-c", code, str(base)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def wait_for(name, process):
        deadline = time.monotonic() + 10
        while not (base / name).exists():
            assert process.poll() is None and time.monotonic() < deadline
            time.sleep(0.01)

    processes = [start(_BACKUP_WITH_GATE)]
    try:
        wait_for("backup-locked", processes[0])
        processes.append(start(_WRITER_WITH_GATE))
        wait_for("writer-ready", processes[1])
        with pytest.raises(subprocess.TimeoutExpired):
            processes[1].wait(timeout=0.15)
        (base / "backup-go").touch()
        for process in processes:
            _, stderr = process.communicate(timeout=15)
            assert process.returncode == 0, stderr.decode()
        assert len(vault.list_files()) == len(files) + 1
        restored = base / "restored"
        restore(base / "consistent.svra", offline / "consistent.svrecovery", restored, NEW)
        _assert_restored(restored, files)
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


def test_rec03_cli_uses_only_new_password_on_restore(source, monkeypatch, capsys):
    base, _, files, offline = source
    archive, key = base / "cli.svra", offline / "cli.svrecovery"
    requests = iter((OLD, NEW, NEW))
    monkeypatch.setattr("getpass.getpass", lambda prompt: next(requests))
    common = ["--archive", str(archive), "--recovery-key", str(key)]
    assert main(["vault", "backup", "--root", str(base / "source"), *common]) == 0
    target = base / "restored"
    assert main(["vault", "restore", "--root", str(target), *common]) == 0
    output = capsys.readouterr().out
    assert OLD not in output and NEW not in output and key.read_bytes().hex() not in output
    _assert_restored(target, files)


def test_c11_complete_lifecycle_and_operations_after_restore(source):
    base, vault, files, offline = source
    updated = "synthetic updated workflow passphrase"
    vault.change_password(updated)
    vault.unlock(updated)
    vault.rotate_kek(updated)
    vault.unlock(updated)
    gcm = next(ident for ident, (_, mode) in files.items() if mode == "gcm")
    vault.rotate_dek(gcm)

    archive, key = base / "workflow.svra", offline / "workflow.svrecovery"
    backup(vault, archive, key)
    destination = base / "restored"
    restore(archive, key, destination, NEW)
    _assert_restored(destination, files)
    reopened = Vault(destination)
    reopened.unlock(NEW)
    source_file = base / "extra"
    source_file.write_bytes(b"post-restore\x00\xff")
    ident = reopened.add(source_file)
    reopened.rotate_dek(ident)
    reopened.extract(ident, base / "post-restore")
    assert (base / "post-restore").read_bytes() == source_file.read_bytes()
    assert len(reopened.list_files()) == len(files) + 1


@pytest.mark.parametrize("issue", ["key", "archive", "aliased-key", "short-new-password"])
def test_c11_restore_rejects_missing_inputs_alias_and_weak_password(snapshot, issue):
    base, _, archive, key = snapshot
    password = NEW
    if issue == "key":
        key = key.with_name("missing.svrecovery")
    elif issue == "archive":
        archive = base / "missing.svra"
    elif issue == "aliased-key":
        os.link(key, key.with_name("alias.svrecovery"))
    else:
        password = "short"
    with pytest.raises(KeyringError if issue == "short-new-password" else VaultError):
        restore(archive, key, base / "restored", password)
    assert not (base / "restored").exists()
    assert not list(base.glob(".svrestore-*"))


def test_c111_exact_payload_limit_and_restore_preserve_object_bytes(source, monkeypatch):
    import securevault.recovery as module

    base, vault, files, offline = source
    archive, key = base / "size.svra", offline / "size.svrecovery"
    backup(vault, archive, key)
    payload_size = int.from_bytes(archive.read_bytes()[20:28], "big")
    monkeypatch.setattr(module, "MAX_PAYLOAD_SIZE", payload_size)
    exact, exact_key = base / "exact.svra", offline / "exact.svrecovery"
    backup(vault, exact, exact_key)
    assert exact.stat().st_size == payload_size + 44
    restored = base / "restored"
    restore(exact, exact_key, restored, NEW)
    _assert_restored(restored, files)
    original = {p.name: p.read_bytes() for p in (base / "source" / "objects").glob("*.svlt")}
    assert {p.name: p.read_bytes() for p in (restored / "objects").glob("*.svlt")} == original

    monkeypatch.setattr(module, "MAX_PAYLOAD_SIZE", payload_size - 1)
    beyond, beyond_key = base / "beyond.svra", offline / "beyond.svrecovery"
    with pytest.raises(VaultError, match="limit"):
        backup(vault, beyond, beyond_key)
    with pytest.raises(VaultError, match="length"):
        restore(exact, exact_key, base / "too-large", NEW)
    assert not beyond.exists() and not beyond_key.exists() and not (base / "too-large").exists()


def test_c111_oversized_sparse_archive_is_rejected_before_authentication(snapshot, monkeypatch):
    import securevault.recovery as module

    base, _, archive, key = snapshot
    with archive.open("r+b") as stream:
        stream.truncate(module.MAX_PAYLOAD_SIZE + 45)

    def unexpected_crypto(*args):
        pytest.fail("oversized archive must be rejected before decryption")

    monkeypatch.setattr(module, "_decrypt_archive", unexpected_crypto)
    with pytest.raises(VaultError, match="size limit"):
        restore(archive, key, base / "restored", NEW)
    assert not (base / "restored").exists()


@pytest.mark.parametrize("candidate", ["PasswordPassword", "123456789012345", "x" * 20])
def test_c111_restore_rejects_predictable_new_credentials(snapshot, candidate):
    base, _, archive, key = snapshot
    with pytest.raises(KeyringError, match="predictable"):
        restore(archive, key, base / "rejected", candidate)
    assert not (base / "rejected").exists()
