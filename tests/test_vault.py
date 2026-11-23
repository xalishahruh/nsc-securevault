"""C08 tests against actual vault directories, crypto, and independent processes."""

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from securevault.cli import main
from securevault.container import parse_container, serialize_container
from securevault.errors import (
    AuthenticationError, InvalidKeyError, KeyringError, ManifestError, ModeMismatchError, VaultError,
)
from securevault.key_wrap import unwrap_dek
from securevault.keyring import Keyring, unlock_keyring
from securevault.manifest import open_manifest
from securevault.vault import Vault


pytestmark = pytest.mark.skipif(os.name != "posix", reason="Managed vault storage requires POSIX")
PASSWORD = "synthetic vault test password"


@pytest.fixture
def active_vault(tmp_path):
    base = tmp_path.resolve()
    root = base / "vault"
    Vault.initialize(root, PASSWORD)
    vault = Vault(root)
    vault.unlock(PASSWORD)
    return base, root, vault


def add_file(base, vault, name="input", data=b"fixture", mode="gcm"):
    source = base / name
    source.write_bytes(data)
    return vault.add(source, mode=mode)


def objects(root):
    return sorted((root / "objects").glob("*.svlt"))


def active_paths(root):
    pointer = (root / "CURRENT").read_bytes()
    assert len(pointer) == 39 and pointer.startswith(b"SVCR1\n") and pointer.endswith(b"\n")
    generation = pointer[6:-1].decode("ascii")
    return (
        root / "generations" / generation / "manifest.svmf",
        root / "keyrings" / (generation + ".keys"),
    )


@pytest.mark.parametrize("mode", ["gcm", "cbc"])
def test_vault_roundtrip_restart_lock_and_private_storage(active_vault, mode):
    base, root, vault = active_vault
    previous_manifest, previous_ring = active_paths(root)
    payloads = (b"", bytes(range(17)), bytes(range(256)) * 32)
    ids = [add_file(base, vault, f"input-{i}", data, mode) for i, data in enumerate(payloads)]
    vault.lock()
    with pytest.raises(VaultError, match="locked"):
        vault.list_files()
    with pytest.raises(KeyringError):
        vault.unlock("wrong password")
    with pytest.raises(VaultError, match="locked"):
        vault.list_files()

    fresh = Vault(root)
    fresh.unlock(PASSWORD)
    assert fresh.list_files() == tuple(sorted((file_id, mode) for file_id in ids))
    assert fresh.inspect()["file_count"] == len(ids)
    for i, (file_id, data) in enumerate(zip(ids, payloads)):
        output = base / f"recovered-{i}"
        assert fresh.extract(file_id, output, require_mode=mode) == mode
        assert output.read_bytes() == data
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        with pytest.raises(VaultError):
            fresh.extract(file_id, output)
        assert output.read_bytes() == data
    assert previous_manifest.is_file() and previous_ring.is_file()
    assert previous_ring.read_bytes() == active_paths(root)[1].read_bytes()
    assert not list((root / "staging").iterdir())
    assert not list(base.glob(".securevault-*"))
    for path in (root, *root.rglob("*")):
        assert stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600)


def test_unlocked_session_reauthenticates_current_manifest(active_vault):
    base, root, vault = active_vault
    file_id = add_file(base, vault)
    manifest, _ = active_paths(root)
    data = manifest.read_bytes()
    manifest.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
    source = base / "input"
    output = base / "plaintext"
    for operation in (vault.list_files, vault.inspect, lambda: vault.extract(file_id, output),
                      lambda: vault.add(source)):
        with pytest.raises(AuthenticationError):
            operation()
    assert not output.exists()


def test_no_plaintext_on_bad_tag_and_no_cbc_downgrade(active_vault):
    base, root, vault = active_vault
    file_id = add_file(base, vault)
    output = base / "plaintext"
    encrypted, = objects(root)
    data = encrypted.read_bytes()
    encrypted.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
    with pytest.raises(AuthenticationError):
        vault.extract(file_id, output)
    assert not output.exists()
    assert not list(base.glob(".securevault-*"))
    encrypted.write_bytes(data)
    cbc = add_file(base, vault, mode="cbc")
    with pytest.raises(ModeMismatchError):
        vault.extract(cbc, output, require_mode="gcm")
    assert not output.exists()


def test_corrupted_existing_gcm_ciphertext_blocks_next_generation(active_vault):
    base, root, vault = active_vault
    add_file(base, vault, "existing", b"existing payload")
    pointer = (root / "CURRENT").read_bytes()
    encrypted, = objects(root)
    raw = bytearray(encrypted.read_bytes())
    parsed = parse_container(bytes(raw))
    raw[len(raw) - len(parsed.gcm_tag) - len(parsed.ciphertext)] ^= 1
    encrypted.write_bytes(raw)

    with pytest.raises(AuthenticationError):
        add_file(base, vault, "next", b"new payload")

    assert (root / "CURRENT").read_bytes() == pointer
    assert not list((root / "staging").iterdir())


def test_object_swap_and_key_record_association(active_vault):
    base, root, vault = active_vault
    first = add_file(base, vault)
    add_file(base, vault, "other", b"other")
    one, two = objects(root)
    left, right = one.read_bytes(), two.read_bytes()
    one.write_bytes(right)
    two.write_bytes(left)
    with pytest.raises(ManifestError):
        vault.extract(first, base / "output")
    with pytest.raises(ManifestError):
        Vault(root).unlock(PASSWORD)
    assert not (base / "output").exists()


def test_managed_object_requires_wrapped_protection_and_trusted_dek(active_vault):
    base, root, vault = active_vault
    file_id = add_file(base, vault)
    add_file(base, vault, "other", b"other")
    one, two = objects(root)
    first = parse_container(one.read_bytes())
    second = parse_container(two.read_bytes())
    if first.header.file_id.hex() != file_id:
        one, first, second = two, second, first
    output = base / "plaintext"
    one.write_bytes(serialize_container(first.header, first.ciphertext, gcm_tag=first.gcm_tag))
    with pytest.raises(ManifestError):
        vault.extract(file_id, output)
    one.write_bytes(serialize_container(first.header, first.ciphertext, 1, second.key_record, first.gcm_tag))
    with pytest.raises(InvalidKeyError):
        vault.extract(file_id, output)
    assert not output.exists()


def test_cbc_payload_remains_unauthenticated(active_vault):
    base, root, vault = active_vault
    payload = bytes(range(48))
    file_id = add_file(base, vault, data=payload, mode="cbc")
    encrypted, = objects(root)
    data = bytearray(encrypted.read_bytes())
    data[24] ^= 1  # The IV changes only the first plaintext bit.
    encrypted.write_bytes(data)
    output = base / "cbc-output"
    assert vault.extract(file_id, output, require_mode="cbc") == "cbc"
    assert output.read_bytes() == bytes([payload[0] ^ 1]) + payload[1:]


def test_keyring_from_other_vault_does_not_authorize(active_vault):
    base, root, vault = active_vault
    other = base / "another-vault"
    Vault.initialize(other, PASSWORD)
    _, current_ring = active_paths(root)
    current_ring.write_bytes(active_paths(other)[1].read_bytes())
    with pytest.raises(VaultError, match="keyring changed"):
        vault.list_files()
    with pytest.raises(ManifestError):
        Vault(root).unlock(PASSWORD)


@pytest.mark.parametrize("item", ["CURRENT", "objects", "generation", "manifest", "keyring", "object", "lock"])
def test_symlink_substitution_is_rejected(active_vault, item):
    base, root, vault = active_vault
    file_id = add_file(base, vault)
    manifest, ring = active_paths(root)
    path = {
        "CURRENT": root / "CURRENT", "objects": root / "objects", "generation": manifest.parent,
        "manifest": manifest, "keyring": ring, "object": objects(root)[0], "lock": root / ".writer.lock",
    }[item]
    elsewhere = base / "relocated"
    path.rename(elsewhere)
    path.symlink_to(elsewhere)
    with pytest.raises(VaultError):
        if item == "lock":
            vault.add(base / "input")
        else:
            vault.extract(file_id, base / "output")
    assert not (base / "output").exists()


def test_unsafe_external_paths_and_aliases(active_vault):
    base, root, vault = active_vault
    file_id = add_file(base, vault)
    link = base / "root-link"
    link.symlink_to(root)
    with pytest.raises(VaultError):
        Vault(link).unlock(PASSWORD)
    for output in (root / "plain", root / ".." / "plain", link / "plain"):
        with pytest.raises(VaultError):
            vault.extract(file_id, output)
    with pytest.raises(VaultError):
        vault.extract("../CURRENT", base / "plain")
    source_link = base / "input-link"
    source_link.symlink_to(base / "input")
    with pytest.raises(VaultError):
        vault.add(source_link)
    output_link = base / "output-link"
    output_link.symlink_to(base / "input")
    with pytest.raises(VaultError):
        vault.extract(file_id, output_link)
    assert (base / "input").read_bytes() == b"fixture"
    os.link(objects(root)[0], base / "hard-link")
    with pytest.raises(VaultError, match="aliases"):
        vault.extract(file_id, base / "plain")
    assert not (base / "plain").exists()


def test_missing_object_rejects_new_generation(active_vault):
    base, root, vault = active_vault
    file_id = add_file(base, vault)
    pointer = (root / "CURRENT").read_bytes()
    encrypted, = objects(root)
    encrypted.rename(base / "hidden")
    with pytest.raises(VaultError):
        vault.add(base / "input")
    assert (root / "CURRENT").read_bytes() == pointer
    assert not list((root / "staging").iterdir())
    (base / "hidden").rename(encrypted)
    vault.extract(file_id, base / "output")
    assert (base / "output").read_bytes() == b"fixture"


def test_io_error_preserves_current_and_cleans_stage(active_vault, monkeypatch):
    import errno
    import securevault.vault as module

    base, root, vault = active_vault
    file_id = add_file(base, vault)
    pointer = (root / "CURRENT").read_bytes()

    def fail_replace(*args, **kwargs):
        raise OSError(errno.EIO, "synthetic failure")

    monkeypatch.setattr(module.os, "replace", fail_replace)
    with pytest.raises(VaultError):
        vault.add(base / "input")
    assert (root / "CURRENT").read_bytes() == pointer
    assert not list((root / "staging").iterdir())
    assert vault.list_files() == ((file_id, "gcm"),)


@pytest.mark.parametrize("bad_pointer", [
    b"SVCR1\n" + b"A" * 32 + b"\n",
    b"SVCR1\n" + b"." * 32 + b"\n",
    b"SVCR1\n" + b"0" * 32 + b"\n",
    b"SVCR1\n" + b"0" * 32 + b"\n\n",
])
def test_invalid_or_missing_generation_does_not_activate_debris(active_vault, bad_pointer):
    _, root, vault = active_vault
    (root / "staging" / "uncommitted").mkdir(mode=0o700)
    (root / "CURRENT").write_bytes(bad_pointer)
    with pytest.raises(VaultError):
        vault.inspect()
    with pytest.raises(VaultError):
        Vault(root).unlock(PASSWORD)
    assert (root / "CURRENT").read_bytes() == bad_pointer


_CRASH_WRITER = """
import os
import sys
from pathlib import Path
import securevault.vault as module

root, source, phase, *action = sys.argv[1:]
vault = module.Vault(Path(root))
vault.unlock("synthetic vault test password")

if phase in ("stage", "staged-object"):
    original = module.write_new
    def write_then_stop(parent, name, data):
        original(parent, name, data)
        if name == ("manifest.svmf" if phase == "stage" else "object"):
            os._exit(71)
    module.write_new = write_then_stop
elif phase in ("object", "keyring", "manifest.svmf"):
    original = module.publish
    def publish_then_stop(stage, name, destination, target):
        original(stage, name, destination, target)
        if name == phase:
            os._exit(71)
    module.publish = publish_then_stop
elif phase == "after-sync":
    original = module._activate
    def activate_then_stop(*args):
        original(*args)
        os._exit(71)
    module._activate = activate_then_stop
else:
    original = module.os.replace
    def stop_at_activation(source, destination, **kwargs):
        if phase == "after":
            original(source, destination, **kwargs)
        os._exit(71)
    module.os.replace = stop_at_activation

if action == ["password"]:
    vault.change_password("synthetic changed password")
elif action == ["kek"]:
    vault.rotate_kek("synthetic vault test password")
elif action == ["dek"]:
    vault.rotate_dek(source)
else:
    vault.add(Path(source))
"""


@pytest.mark.parametrize("phase", ["stage", "before", "after"])
def test_crash_recovery_at_real_commit_boundaries(active_vault, phase):
    base, root, vault = active_vault
    first = add_file(base, vault, "first", b"old generation")
    before = (root / "CURRENT").read_bytes()
    source = base / "new-input"
    source.write_bytes(b"new generation")

    crashed = subprocess.run(
        [sys.executable, "-c", _CRASH_WRITER, str(root), str(source), phase],
        capture_output=True, timeout=20,
    )
    assert crashed.returncode == 71, crashed.stderr.decode()
    assert ((root / "CURRENT").read_bytes() != before) is (phase == "after")
    assert list((root / "staging").iterdir())

    recovered = Vault(root)
    recovered.unlock(PASSWORD)
    listed = dict(recovered.list_files())
    assert len(listed) == (2 if phase == "after" else 1)
    assert first in listed
    for file_id in listed:
        output = base / file_id
        recovered.extract(file_id, output)
        assert output.read_bytes() == (b"old generation" if file_id == first else b"new generation")
    later = recovered.add(source)
    assert later in dict(recovered.list_files())


_CONCURRENT_WRITER = """
import sys
import time
from pathlib import Path
from securevault.vault import Vault

root, source, ready, start = map(Path, sys.argv[1:])
vault = Vault(root)
vault.unlock("synthetic vault test password")
ready.touch()
deadline = time.monotonic() + 15
while not start.exists():
    if time.monotonic() > deadline:
        raise RuntimeError("Writer start barrier timed out")
    time.sleep(0.01)
print(vault.add(source))
"""


def test_independent_concurrent_writers_do_not_lose_updates(active_vault):
    import time

    base, root, vault = active_vault
    processes = []
    sources = []
    start = base / "start"
    try:
        for i in range(3):
            source = base / f"source-{i}"
            source.write_bytes(bytes([i]) * 201)
            sources.append(source)
            processes.append(subprocess.Popen(
                [sys.executable, "-c", _CONCURRENT_WRITER, str(root), str(source),
                 str(base / f"ready-{i}"), str(start)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ))
        deadline = time.monotonic() + 15
        while len(list(base.glob("ready-*"))) < len(processes):
            assert time.monotonic() < deadline
            time.sleep(0.01)
        start.touch()
        ids = []
        for process, source in zip(processes, sources):
            stdout, stderr = process.communicate(timeout=15)
            assert process.returncode == 0, stderr
            file_id = stdout.strip()
            ids.append(file_id)
            output = base / file_id
            vault.extract(file_id, output)
            assert output.read_bytes() == source.read_bytes()
        assert set(dict(vault.list_files())) == set(ids)
        assert len(ids) == len(set(ids)) == 3
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


def test_vault_cli_dispatch_with_real_storage(tmp_path, monkeypatch, capsys):
    base = tmp_path.resolve()
    root = base / "cli-vault"
    monkeypatch.setattr("getpass.getpass", lambda prompt: PASSWORD)
    source = base / "sample"
    source.write_bytes(b"CLI fixture")
    output = base / "output"

    def cli(action, *args):
        assert main(["vault", action, "--root", str(root), *map(str, args)]) == 0
        return capsys.readouterr()

    assert "initialized" in cli("init").out
    assert "verified" in cli("unlock").out
    file_id = cli("add", "--input", source, "--mode", "cbc").out.strip()
    assert cli("list").out.strip() == f"{file_id} cbc"
    assert "file_count: 1" in cli("inspect").out
    assert "unauthenticated" in cli("extract", "--file-id", file_id, "--output", output).err
    assert output.read_bytes() == b"CLI fixture"


def test_cli_refuses_visible_password_prompt(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "securevault", "vault", "init", "--root", str(tmp_path / "vault")],
        input=PASSWORD, text=True, capture_output=True, timeout=10, start_new_session=True,
    )
    assert result.returncode == 2
    assert "hidden interactive password" in result.stderr
    assert PASSWORD not in result.stderr + result.stdout
    assert not (tmp_path / "vault").exists()


def test_change_password_preserves_kek_and_objects(active_vault):
    base, root, vault = active_vault
    file_id = add_file(base, vault)
    snapshot = {path: path.read_bytes() for path in objects(root)}
    old_manifest, old_ring_path = active_paths(root)
    old_data = old_ring_path.read_bytes()
    old_ring = Keyring.parse(old_data)
    stale = Vault(root)
    stale.unlock(PASSWORD)

    updated_password = "synthetic replacement password"
    vault.change_password(updated_password)
    new_manifest, new_ring_path = active_paths(root)
    assert old_manifest != new_manifest and old_manifest.exists()
    assert snapshot == {path: path.read_bytes() for path in objects(root)}
    new_data = new_ring_path.read_bytes()
    new_ring = Keyring.parse(new_data)
    assert new_ring.salt != old_ring.salt
    assert (new_ring.vault_id, new_ring.kek_generation_id) == (old_ring.vault_id, old_ring.kek_generation_id)
    assert unlock_keyring(old_data, PASSWORD) == unlock_keyring(new_data, updated_password)
    with pytest.raises(VaultError, match="locked"):
        vault.list_files()
    with pytest.raises(VaultError, match="keyring changed"):
        stale.list_files()
    with pytest.raises(KeyringError):
        vault.unlock(PASSWORD)
    vault.unlock(updated_password)
    vault.extract(file_id, base / "recovered")
    assert (base / "recovered").read_bytes() == b"fixture"


def test_rotate_kek_rewraps_both_modes_without_payload_changes(active_vault):
    base, root, vault = active_vault
    gcm_id = add_file(base, vault, "gcm", b"GCM")
    cbc_id = add_file(base, vault, "cbc", b"CBC", mode="cbc")
    old_objects = {parse_container(path.read_bytes()).header.file_id: path for path in objects(root)}
    old_keyring = active_paths(root)[1].read_bytes()
    old_kek = unlock_keyring(old_keyring, PASSWORD)
    old_current = (root / "CURRENT").read_bytes()

    with pytest.raises(KeyringError):
        vault.rotate_kek("wrong password")
    assert (root / "CURRENT").read_bytes() == old_current

    vault.rotate_kek(PASSWORD)
    new_keyring = active_paths(root)[1].read_bytes()
    new_kek = unlock_keyring(new_keyring, PASSWORD)
    old_ring, new_ring = Keyring.parse(old_keyring), Keyring.parse(new_keyring)
    assert new_kek != old_kek and new_ring.kek_generation_id != old_ring.kek_generation_id
    assert new_ring.vault_id == old_ring.vault_id and new_ring.salt != old_ring.salt
    new_objects = [
        path for path in objects(root) if path not in old_objects.values()
    ]
    assert len(new_objects) == 2
    for path in new_objects:
        raw = path.read_bytes()
        new = parse_container(raw)
        file_id, cipher = new.header.file_id, new.header.cipher_id
        previous = old_objects[file_id].read_bytes()
        old = parse_container(previous)
        assert raw[:51] == previous[:51] and raw[115:] == previous[115:]
        assert new.key_record != old.key_record
        assert unwrap_dek(new_kek, new.key_record, file_id, cipher) == unwrap_dek(
            old_kek, old.key_record, file_id, cipher,
        )
        with pytest.raises(InvalidKeyError):
            unwrap_dek(old_kek, new.key_record, file_id, cipher)
    assert all(path.exists() for path in old_objects.values())
    with pytest.raises(VaultError, match="locked"):
        vault.list_files()
    fresh = Vault(root)
    fresh.unlock(PASSWORD)
    for file_id, expected in ((gcm_id, b"GCM"), (cbc_id, b"CBC")):
        output = base / file_id
        fresh.extract(file_id, output)
        assert output.read_bytes() == expected


def test_rotate_dek_reencrypts_only_selected_gcm_file(active_vault):
    base, root, vault = active_vault
    gcm = add_file(base, vault, "gcm", b"authenticated fixture")
    cbc = add_file(base, vault, "cbc", mode="cbc")
    original = set(objects(root))
    accepted = (root / "CURRENT").read_bytes()
    with pytest.raises(ModeMismatchError):
        vault.rotate_dek(cbc)
    assert (root / "CURRENT").read_bytes() == accepted

    old = next(container for path in original
               if (container := parse_container(path.read_bytes())).header.file_id.hex() == gcm)
    kek = unlock_keyring(active_paths(root)[1].read_bytes(), PASSWORD)
    vault.rotate_dek(gcm)
    new_path, = set(objects(root)) - original
    new = parse_container(new_path.read_bytes())
    assert new.header.file_id == old.header.file_id
    assert new.header.iv_or_nonce != old.header.iv_or_nonce
    assert new.ciphertext != old.ciphertext and new.gcm_tag != old.gcm_tag
    assert unwrap_dek(kek, new.key_record, new.header.file_id, 1) != unwrap_dek(
        kek, old.key_record, old.header.file_id, 1,
    )
    output = base / "recovered"
    vault.extract(gcm, output)
    assert output.read_bytes() == b"authenticated fixture"
    assert dict(vault.list_files()) == {gcm: "gcm", cbc: "cbc"}


@pytest.mark.parametrize("action", ["password", "kek", "dek"])
def test_lifecycle_rejects_corrupted_gcm_without_activating(active_vault, action):
    base, root, vault = active_vault
    damaged_id = add_file(base, vault, "damaged", b"tampered fixture")
    healthy_id = add_file(base, vault, "healthy", b"good fixture")
    encrypted = next(path for path in objects(root)
                     if parse_container(path.read_bytes()).header.file_id.hex() == damaged_id)
    raw = bytearray(encrypted.read_bytes())
    raw[115] ^= 1
    encrypted.write_bytes(raw)
    accepted = (root / "CURRENT").read_bytes()
    with pytest.raises(AuthenticationError):
        if action == "password":
            vault.change_password("synthetic changed password")
        elif action == "kek":
            vault.rotate_kek(PASSWORD)
        else:
            vault.rotate_dek(healthy_id)
    assert (root / "CURRENT").read_bytes() == accepted
    assert not list((root / "staging").iterdir())


@pytest.mark.parametrize("action,phase", [
    ("password", "before"), ("password", "after"),
    ("kek", "before"), ("kek", "after"), ("kek", "object"),
])
def test_lifecycle_process_exit_preserves_complete_generation(active_vault, action, phase):
    base, root, vault = active_vault
    file_id = add_file(base, vault)
    other_id = add_file(base, vault, "other", b"second file")
    accepted = (root / "CURRENT").read_bytes()
    previous_manifest, previous_ring = active_paths(root)
    crashed = subprocess.run(
        [sys.executable, "-c", _CRASH_WRITER, str(root), str(base / "input"), phase, action],
        capture_output=True, timeout=20,
    )
    assert crashed.returncode == 71, crashed.stderr.decode()
    assert ((root / "CURRENT").read_bytes() != accepted) is (phase == "after")
    assert previous_manifest.is_file() and previous_ring.is_file()
    fresh = Vault(root)
    if action == "password":
        changed = "synthetic changed password"
        current, wrong = (changed, PASSWORD) if phase == "after" else (PASSWORD, changed)
        with pytest.raises(KeyringError):
            fresh.unlock(wrong)
    else:
        current = PASSWORD
        old = previous_ring.read_bytes()
        active = active_paths(root)[1].read_bytes()
        assert (unlock_keyring(old, PASSWORD) != unlock_keyring(active, PASSWORD)) is (phase == "after")
    fresh.unlock(current)
    for ident, data in ((file_id, b"fixture"), (other_id, b"second file")):
        output = base / ident
        fresh.extract(ident, output)
        assert output.read_bytes() == data


def test_lifecycle_cli_dispatch(active_vault, monkeypatch, capsys):
    base, root, vault = active_vault
    ident = add_file(base, vault)
    replacement = "synthetic new CLI password"
    prompts = iter((PASSWORD, replacement, replacement, replacement, replacement))
    monkeypatch.setattr("getpass.getpass", lambda prompt: next(prompts))
    for command, args, message in (
        ("change-password", [], "password changed"),
        ("rotate-kek", [], "KEK rotated"),
        ("rotate-dek", ["--file-id", ident], "DEK rotated"),
    ):
        assert main(["vault", command, "--root", str(root), *args]) == 0
        output = capsys.readouterr()
        assert message in output.out
        assert replacement not in output.out + output.err
    vault.unlock(replacement)
    vault.extract(ident, base / "recovered")
    assert (base / "recovered").read_bytes() == b"fixture"


@pytest.mark.parametrize("phase", [
    "stage", "staged-object", "object", "keyring", "manifest.svmf", "before", "after", "after-sync",
])
def test_c11_dek_rotation_process_exit_keeps_complete_generation(active_vault, phase):
    base, root, vault = active_vault
    file_id = add_file(base, vault, "selected", bytes(range(256)))
    other_id = add_file(base, vault, "other", b"independent object", mode="cbc")

    def active_object_id():
        manifest_path, ring_path = active_paths(root)
        ring_data = ring_path.read_bytes()
        ring = Keyring.parse(ring_data)
        manifest = open_manifest(
            manifest_path.read_bytes(), unlock_keyring(ring_data, PASSWORD),
            expected_vault_id=ring.vault_id, expected_generation_id=bytes.fromhex(manifest_path.parent.name),
            expected_kek_generation_id=ring.kek_generation_id,
        )
        return manifest.file(bytes.fromhex(file_id)).object_id

    pointer = (root / "CURRENT").read_bytes()
    old_manifest, old_ring = active_paths(root)
    old_object = active_object_id()
    exited = subprocess.run(
        [sys.executable, "-c", _CRASH_WRITER, str(root), file_id, phase, "dek"],
        capture_output=True, timeout=20,
    )
    assert exited.returncode == 71, exited.stderr.decode()
    expected_activation = phase in ("after", "after-sync")
    assert ((root / "CURRENT").read_bytes() != pointer) is expected_activation
    assert (active_object_id() != old_object) is expected_activation
    assert old_manifest.is_file() and old_ring.is_file()
    restarted = Vault(root)
    restarted.unlock(PASSWORD)
    assert dict(restarted.list_files()) == {file_id: "gcm", other_id: "cbc"}
    for ident, payload in ((file_id, bytes(range(256))), (other_id, b"independent object")):
        output = base / ("recovered-" + ident)
        restarted.extract(ident, output)
        assert output.read_bytes() == payload
    restarted.rotate_dek(file_id)  # Abandoned work does not prevent a later commit.


def test_c11_rollback_of_complete_historical_generation_is_possible(active_vault):
    base, root, vault = active_vault
    old_id = add_file(base, vault, "old", b"historical snapshot")
    pointer = (root / "CURRENT").read_bytes()
    old_manifest, old_ring = active_paths(root)
    newer_id = add_file(base, vault, "new", b"new addition")
    vault.change_password("synthetic replacement password")
    assert old_manifest.is_file() and old_ring.is_file()

    (root / "CURRENT").write_bytes(pointer)
    restarted = Vault(root)
    restarted.unlock(PASSWORD)
    assert dict(restarted.list_files()) == {old_id: "gcm"}
    with pytest.raises(ManifestError):
        restarted.extract(newer_id, base / "absent")
    restarted.extract(old_id, base / "historical")
    assert (base / "historical").read_bytes() == b"historical snapshot"


@pytest.mark.parametrize("candidate", ["x" * 14, " " * 15, "é" * 8, b"\xff" * 16])
def test_c11_password_policy_applies_only_when_setting_password(active_vault, candidate):
    base, root, vault = active_vault
    accepted = (root / "CURRENT").read_bytes()
    with pytest.raises(KeyringError):
        Vault.initialize(base / "reject", candidate)
    assert not (base / "reject").exists()
    with pytest.raises(KeyringError):
        vault.change_password(candidate)
    assert (root / "CURRENT").read_bytes() == accepted
    assert vault.list_files() == ()


def test_c11_legacy_short_password_can_unlock_rotate_kek_and_upgrade(tmp_path):
    from securevault.keyring import create_keyring
    from securevault.vault import _commit
    from securevault.vault_storage import open_storage

    root = tmp_path.resolve() / "legacy"
    old_password = "old"
    new_password = "á" * 14 + "b"
    ring, kek = create_keyring(old_password)
    with open_storage(root, create=True) as store, store.writer() as lock:
        _commit(store, lock, None, ring, kek, [])
    legacy = Vault(root)
    legacy.unlock(old_password)
    legacy.rotate_kek(old_password)
    legacy.unlock(old_password)
    legacy.change_password(new_password.encode("utf-8"))
    with pytest.raises(KeyringError):
        legacy.unlock(old_password)
    legacy.unlock(new_password)
    assert legacy.list_files() == ()


@pytest.mark.parametrize("candidate", [" Password Password ", "qwertyuiopasdfgh", "z" * 16])
def test_c111_reject_predictable_new_credentials_without_touching_current(active_vault, candidate):
    base, root, vault = active_vault
    current = (root / "CURRENT").read_bytes()
    with pytest.raises(KeyringError, match="predictable"):
        Vault.initialize(base / "rejected", candidate)
    with pytest.raises(KeyringError, match="predictable"):
        vault.change_password(candidate)
    assert not (base / "rejected").exists()
    assert (root / "CURRENT").read_bytes() == current
    assert vault.list_files() == ()


@pytest.mark.parametrize("mode,iv_length", [("gcm", 12), ("cbc", 16)])
def test_c111_managed_import_draws_independent_key_and_iv(active_vault, mode, iv_length):
    base, root, vault = active_vault
    for index in range(3):
        add_file(base, vault, f"input-{index}", b"identical input", mode)
    ring = active_paths(root)[1].read_bytes()
    kek = unlock_keyring(ring, PASSWORD)
    ivs, keys = set(), set()
    for path in objects(root):
        obj = parse_container(path.read_bytes())
        iv = obj.header.iv_or_nonce
        dek = unwrap_dek(kek, obj.key_record, obj.header.file_id, obj.header.cipher_id)
        assert len(iv) == iv_length and len(dek) == 32
        ivs.add(iv)
        keys.add(dek)
    assert len(keys) == len(ivs) == 3
