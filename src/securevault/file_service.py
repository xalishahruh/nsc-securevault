"""Safe staging, atomic commit, and high-level file encryption/decryption operations."""

import logging
import os
import stat
import tempfile
import warnings
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

from securevault.container import (
    ContainerHeader,
    serialize_container,
    parse_container,
    CIPHER_GCM,
    CIPHER_CBC,
    KEY_PROT_EXTERNAL,
    MAX_CIPHERTEXT_SIZE,
    HEADER_SIZE,
    KEY_DESC_SIZE,
    GCM_TAG_SIZE,
)
from securevault.crypto.gcm import (
    generate_gcm_dek,
    generate_gcm_nonce,
    encrypt_gcm,
    decrypt_gcm,
)
from securevault.crypto.cbc import (
    generate_cbc_dek,
    generate_cbc_iv,
    encrypt_cbc,
    decrypt_cbc,
)
from securevault.key_provider import ExternalKeyRecord, KEY_RECORD_SIZE
from securevault.key_wrap import WRAPPED_DEK_SIZE
from securevault.errors import (
    FileExistsSecurityError,
    SameFileError,
    PathSecurityError,
    FileServiceError,
    ModeMismatchError,
)

MAX_CONTAINER_SIZE = HEADER_SIZE + KEY_DESC_SIZE + WRAPPED_DEK_SIZE + MAX_CIPHERTEXT_SIZE + GCM_TAG_SIZE


def _warn_storage(message: str) -> None:
    logger.warning(message)
    try:
        warnings.warn(message, UserWarning, stacklevel=3)
    except UserWarning:
        # A warning-as-error filter must preserve the real publication outcome.
        pass


def _read_bounded(path: Path, limit: int) -> bytes:
    """Read a regular file within its size limit, even if it grows during the read."""
    if not stat.S_ISREG(path.lstat().st_mode):
        raise PathSecurityError("SecureVault inputs must be regular files, without symlinks.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise PathSecurityError("SecureVault inputs must be regular files.")
        if metadata.st_size > limit:
            raise FileServiceError(f"Input exceeds the supported limit of {limit} bytes.")
        data = source.read(metadata.st_size)
        if len(data) != metadata.st_size or source.read(1):
            raise FileServiceError("Input size changed during reading.")
        return data


def _check_path_safety(src: Path, dst: Path, overwrite: bool = False) -> None:
    """Validate source and destination paths for security constraints."""
    if not src.exists():
        raise FileNotFoundError(f"Source file does not exist: {src}")

    # Prevent symlink traversal if requested
    if src.is_symlink() or dst.is_symlink():
        raise PathSecurityError("Symlinks are not permitted for SecureVault operations.")

    src_resolved = src.resolve()
    dst_resolved = dst.resolve()

    if src_resolved == dst_resolved or (dst.exists() and src.samefile(dst)):
        raise SameFileError(f"Source and destination point to the same file: {src_resolved}")

    if dst.exists() and not overwrite:
        raise FileExistsSecurityError(
            f"Destination file already exists: {dst}. Refusing to overwrite without explicit permission."
        )


def _safe_write_bytes(target: Path, data: bytes, overwrite: bool = False, file_mode: int = 0o600) -> None:
    """Safely stage and atomically commit bytes to target path with no-overwrite protection."""
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)

    if target.exists() and not overwrite:
        raise FileExistsSecurityError(f"Target file already exists: {target}")

    tmp_file = tempfile.NamedTemporaryFile(
        dir=parent,
        prefix=".svlt_tmp_",
        delete=False,
    )
    tmp_path = Path(tmp_file.name)
    published = False
    try:
        with tmp_file:
            tmp_file.write(data)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())

        # Restrict permissions to owner-only
        try:
            os.chmod(tmp_path, file_mode)
        except OSError:
            pass  # Fallback gracefully on filesystems without POSIX chmod

        if not overwrite:
            # Race-safe atomic exclusive publication using hard link
            try:
                os.link(tmp_path, target)
                published = True
            except FileExistsError as err:
                raise FileExistsSecurityError(f"Target file already exists: {target}") from err
            except OSError as err:
                # Fail closed: never fall back to clobbering replace when overwrite=False
                raise FileServiceError(
                    f"Atomic exclusive publication unsupported or failed on this filesystem: {err}"
                ) from err

            # Post-publication cleanup: target link is established; remove staging link.
            # Note: while payload bytes are fsync'd, parent directory metadata durability depends on OS/filesystem sync semantics.
            try:
                tmp_path.unlink()
            except OSError as err:
                # Cleanup failure of staging link must not compromise, roll back, or remove published target
                _warn_storage(f"Failed to remove temporary staging file {tmp_path.name}: {err}")
        else:
            os.replace(tmp_path, target)
            published = True
    except BaseException:
        if not published:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                logger.warning("Could not remove unpublished staging file %s.", tmp_path.name)
        raise


def encrypt_file(
    input_path: Path,
    output_path: Path,
    key_output_path: Path,
    mode: str = "gcm",
    overwrite: bool = False,
) -> Dict[str, Any]:
    """Encrypt a local file to .svlt container format with fresh DEK and external key."""
    if key_output_path is None:
        raise ValueError("A valid key_output_path must be provided to store the encryption key.")

    if overwrite:
        raise FileServiceError(
            "Overwriting existing container or key files is not supported during encryption; "
            "use distinct output paths to prevent unrecoverable data loss."
        )

    mode_lower = mode.lower()
    if mode_lower not in ("gcm", "cbc"):
        raise ValueError(f"Unsupported mode: '{mode}'. Allowed modes are 'gcm' and 'cbc'.")

    _check_path_safety(input_path, output_path, overwrite=False)
    _check_path_safety(input_path, key_output_path, overwrite=False)
    if output_path.resolve() == key_output_path.resolve():
        raise SameFileError("Output container and key output cannot be the same file.")

    # CBC's mandatory final padding block must also fit the ciphertext limit.
    plaintext = _read_bounded(input_path, MAX_CIPHERTEXT_SIZE - (mode_lower == "cbc"))

    file_id = os.urandom(16)

    if mode_lower == "gcm":
        cipher_id = CIPHER_GCM
        dek = generate_gcm_dek()
        nonce = generate_gcm_nonce()

        header = ContainerHeader(
            version=1,
            cipher_id=cipher_id,
            flags=0,
            file_id=file_id,
            iv_or_nonce=nonce,
            ciphertext_length=len(plaintext),
        )
        aad = header.serialize()
        ciphertext, tag = encrypt_gcm(dek, nonce, plaintext, associated_data=aad)
        container_bytes = serialize_container(
            header=header,
            ciphertext=ciphertext,
            key_protection_id=KEY_PROT_EXTERNAL,
            gcm_tag=tag,
        )
    else:  # CBC
        cipher_id = CIPHER_CBC
        dek = generate_cbc_dek()
        iv = generate_cbc_iv()

        ciphertext = encrypt_cbc(dek, iv, plaintext)
        header = ContainerHeader(
            version=1,
            cipher_id=cipher_id,
            flags=0,
            file_id=file_id,
            iv_or_nonce=iv,
            ciphertext_length=len(ciphertext),
        )
        container_bytes = serialize_container(
            header=header,
            ciphertext=ciphertext,
            key_protection_id=KEY_PROT_EXTERNAL,
        )

    # Publish key record first
    key_record = ExternalKeyRecord(
        version=1,
        file_id=file_id,
        cipher_id=cipher_id,
        dek=dek,
    )
    _safe_write_bytes(key_output_path, key_record.serialize(), overwrite=False, file_mode=0o600)

    try:
        _safe_write_bytes(output_path, container_bytes, overwrite=False, file_mode=0o600)
    except Exception:
        # Container publication failed after key file was published.
        # To avoid TOCTOU races and accidental deletion of pre-existing/concurrent files,
        # never automatically unlink the key file. Preserve it and emit an observable warning.
        msg = (
            f"Container publication failed; preserved published key at '{key_output_path.name}'. "
            "An orphaned key file may remain."
        )
        _warn_storage(msg)
        raise

    return {
        "file_id": file_id.hex(),
        "mode": mode_lower,
        "input_bytes": len(plaintext),
        "ciphertext_bytes": len(ciphertext),
        "container_bytes": len(container_bytes),
        "output_path": str(output_path),
        "key_path": str(key_output_path),
    }


def decrypt_file(
    input_path: Path,
    output_path: Path,
    key_file_path: Path,
    require_mode: Optional[str] = None,
    overwrite: bool = False,
) -> Dict[str, Any]:
    """Decrypt a .svlt container using an external key file and safely publish plaintext."""
    _check_path_safety(input_path, output_path, overwrite=overwrite)
    _check_path_safety(key_file_path, output_path, overwrite=overwrite)

    container_bytes = _read_bounded(input_path, MAX_CONTAINER_SIZE)
    parsed = parse_container(container_bytes)
    if parsed.key_protection_id != KEY_PROT_EXTERNAL:
        raise ModeMismatchError("Standalone decryption requires an external-key container.")

    # Mode enforcement check
    if require_mode is not None:
        req_norm = require_mode.lower()
        container_mode = "gcm" if parsed.header.cipher_id == CIPHER_GCM else "cbc"
        if req_norm != container_mode:
            raise ModeMismatchError(
                f"Mode policy violation: caller required mode '{req_norm}', but container has mode '{container_mode}'."
            )

    key_bytes = _read_bounded(key_file_path, KEY_RECORD_SIZE)
    key_record = ExternalKeyRecord.parse(key_bytes)
    key_record.validate_association(parsed.header.file_id, parsed.header.cipher_id)

    # Cryptographic decryption
    if parsed.header.cipher_id == CIPHER_GCM:
        assert parsed.gcm_tag is not None
        plaintext = decrypt_gcm(
            dek=key_record.dek,
            nonce=parsed.header.iv_or_nonce,
            ciphertext=parsed.ciphertext,
            tag=parsed.gcm_tag,
            associated_data=parsed.immutable_header_bytes,
        )
    elif parsed.header.cipher_id == CIPHER_CBC:
        plaintext = decrypt_cbc(
            dek=key_record.dek,
            iv=parsed.header.iv_or_nonce,
            ciphertext=parsed.ciphertext,
        )
    else:
        raise ModeMismatchError(f"Unsupported cipher ID: {parsed.header.cipher_id}")

    # Publish only after GCM authentication or successful CBC unpadding.
    _safe_write_bytes(output_path, plaintext, overwrite=overwrite, file_mode=0o600)

    mode_name = "gcm" if parsed.header.cipher_id == CIPHER_GCM else "cbc"
    return {
        "file_id": parsed.header.file_id.hex(),
        "mode": mode_name,
        "recovered_bytes": len(plaintext),
        "output_path": str(output_path),
        "cbc_warning": mode_name == "cbc",
    }


def inspect_file(input_path: Path) -> Dict[str, Any]:
    """Inspect and return nonsecret structural metadata of a .svlt container without decryption."""
    data = _read_bounded(input_path, MAX_CONTAINER_SIZE)
    parsed = parse_container(data)

    mode_name = "AES-256-GCM" if parsed.header.cipher_id == CIPHER_GCM else "AES-256-CBC"
    key_prot = "External key (.svkey)" if parsed.key_protection_id == KEY_PROT_EXTERNAL else "AES-KWP (Vault)"

    return {
        "magic": "SVLT",
        "version": parsed.header.version,
        "cipher_mode": mode_name,
        "flags": parsed.header.flags,
        "file_id": parsed.header.file_id.hex(),
        "iv_or_nonce": parsed.header.iv_or_nonce.hex(),
        "ciphertext_length": parsed.header.ciphertext_length,
        "key_protection": key_prot,
        "has_gcm_tag": parsed.gcm_tag is not None,
        "total_container_bytes": len(data),
        "tag_verified": False,  # Inspect only checks structure; does not authenticate ciphertext without DEK
    }

