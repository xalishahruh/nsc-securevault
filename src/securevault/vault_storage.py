"""POSIX descriptor-relative storage for the managed vault."""

import os
import stat
from contextlib import ExitStack, contextmanager
from pathlib import Path

from securevault.errors import VaultError

try:
    import fcntl
except ImportError:
    fcntl = None


def _require_platform() -> None:
    if fcntl is None or not hasattr(os, "O_NOFOLLOW"):
        raise VaultError("Managed vault storage requires POSIX directory descriptors and file locking.")


def identity(fd: int) -> tuple[int, int]:
    info = os.fstat(fd)
    return info.st_dev, info.st_ino


def _private(info: os.stat_result) -> bool:
    return info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0


@contextmanager
def directory(parent: int | None, name: str, *, private: bool = True):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        if private and not _private(os.fstat(fd)):
            raise VaultError("Vault directories must be private and owned by the current user.")
        if private and parent is not None and identity(fd)[0] != identity(parent)[0]:
            raise VaultError("Vault storage must be on one filesystem.")
        yield fd
    finally:
        os.close(fd)


@contextmanager
def path_directory(path: Path, *, outside: tuple[int, int] | None = None):
    """Open every path component without following links, including ancestors."""
    _require_platform()
    path = Path(path).absolute()
    if path.anchor != "/" or ".." in path.parts:
        raise VaultError("Unsafe directory path.")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in path.parts[1:]:
            if identity(fd) == outside:
                raise VaultError("Input and output paths must be outside the vault.")
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        if identity(fd) == outside:
            raise VaultError("Input and output paths must be outside the vault.")
        yield fd
    finally:
        os.close(fd)


@contextmanager
def _regular(parent: int, name: str, *, private: bool):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise VaultError("Expected a regular file.")
        if private and (not _private(info) or info.st_nlink != 1 or info.st_dev != identity(parent)[0]):
            raise VaultError("Vault files must be private and cannot have aliases.")
        yield fd, info.st_size
    finally:
        os.close(fd)


def read(parent: int, name: str, limit: int, *, private: bool = True) -> bytes:
    with _regular(parent, name, private=private) as (fd, size):
        if size > limit:
            raise VaultError("File exceeds the supported size limit.")
        with open(fd, "rb", closefd=False) as stream:
            data = stream.read(size)
            if len(data) != size or stream.read(1):
                raise VaultError("File changed size while being read.")
            return data


def write_new(parent: int, name: str, data: bytes) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent)
    try:
        with open(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        os.unlink(name, dir_fd=parent)
        raise


def publish(stage: int, name: str, destination: int, target: str) -> None:
    """Install an immutable dependency without replacing an existing name."""
    os.link(name, target, src_dir_fd=stage, dst_dir_fd=destination, follow_symlinks=False)
    os.unlink(name, dir_fd=stage)
    os.fsync(destination)


class Storage:
    def __init__(self, stack: ExitStack, root: int):
        self.root = root
        self.objects = stack.enter_context(directory(root, "objects"))
        self.generations = stack.enter_context(directory(root, "generations"))
        self.keyrings = stack.enter_context(directory(root, "keyrings"))
        self.staging = stack.enter_context(directory(root, "staging"))

    @contextmanager
    def writer(self):
        with _regular(self.root, ".writer.lock", private=True) as (fd, _):
            fcntl.flock(fd, fcntl.LOCK_EX)
            self.check_writer(fd)
            yield fd

    def check_writer(self, fd: int) -> None:
        with _regular(self.root, ".writer.lock", private=True) as (current, _):
            if identity(fd) != identity(current):
                raise VaultError("The vault writer lock was replaced.")

    def check_layout(self) -> None:
        for name in ("objects", "generations", "keyrings", "staging"):
            with directory(self.root, name) as current:
                if identity(current) != identity(getattr(self, name)):
                    raise VaultError("A vault storage directory was replaced.")

    @contextmanager
    def stage(self, name: str):
        os.mkdir(name, 0o700, dir_fd=self.staging)
        try:
            with directory(self.staging, name) as fd:
                try:
                    yield fd
                finally:
                    for entry in ("manifest.svmf", "keyring", "object", "CURRENT"):
                        try:
                            os.unlink(entry, dir_fd=fd)
                        except FileNotFoundError:
                            pass
        finally:
            os.rmdir(name, dir_fd=self.staging)


@contextmanager
def open_storage(root: Path, *, create: bool = False):
    try:
        with ExitStack() as stack:
            if create:
                parent = stack.enter_context(path_directory(root.parent))
                os.mkdir(root.name, 0o700, dir_fd=parent)
                fd = stack.enter_context(directory(parent, root.name))
                for name in ("objects", "generations", "keyrings", "staging"):
                    os.mkdir(name, 0o700, dir_fd=fd)
                write_new(fd, ".writer.lock", b"")
                os.fsync(fd)
                os.fsync(parent)
            else:
                fd = stack.enter_context(path_directory(root))
                if not _private(os.fstat(fd)):
                    raise VaultError("Vault directories must be private and owned by the current user.")
            yield Storage(stack, fd)
    except OSError as exc:
        raise VaultError(f"Vault storage operation failed (OS error {exc.errno}).") from None
