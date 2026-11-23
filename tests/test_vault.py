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

root, source, phase = sys.argv[1:]
vault = module.Vault(Path(root))
vault.unlock("synthetic vault test password")

if phase == "stage":
    original = module.write_new
    def write_then_stop(parent, name, data):
        original(parent, name, data)
        if name == "manifest.svmf":
            os._exit(71)
    module.write_new = write_then_stop
else:
    original = module.os.replace
    def stop_at_activation(source, destination, **kwargs):
        if phase == "after":
            original(source, destination, **kwargs)
        os._exit(71)
    module.os.replace = stop_at_activation

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
