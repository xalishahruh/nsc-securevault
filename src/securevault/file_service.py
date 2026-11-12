"""Safe staging, atomic commit, and high-level file encryption/decryption operations."""

import os
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional

from securevault.container import (
    ContainerHeader,
    serialize_container,
    parse_container,
    CIPHER_GCM,
    CIPHER_CBC,
    KEY_PROT_EXTERNAL,
    MAX_CIPHERTEXT_SIZE,
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
from securevault.key_provider import ExternalKeyRecord
from securevault.errors import (
    FileExistsSecurityError,
    SameFileError,
    PathSecurityError,
    FileServiceError,
    ModeMismatchError,
    AuthenticationError,
    PaddingError,
)


def _check_path_safety(src: Path, dst: Path, overwrite: bool = False) -> None:
    """Validate source and destination paths for security constraints."""
    if not src.exists():
        raise FileNotFoundError(f"Source file does not exist: {src}")

    # Prevent symlink traversal if requested
    if src.is_symlink() or dst.is_symlink():
        raise PathSecurityError("Symlinks are not permitted for SecureVault operations.")

    src_resolved = src.resolve()
    dst_resolved = dst.resolve()

    if src_resolved == dst_resolved:
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
    try:
        tmp_file.write(data)
        tmp_file.flush()
        os.fsync(tmp_file.fileno())
        tmp_file.close()

        # Restrict permissions to owner-only
        try:
            os.chmod(tmp_path, file_mode)
        except OSError:
            pass  # Fallback gracefully on filesystems without POSIX chmod

        if not overwrite:
            # Race-safe atomic creation: os.link fails with FileExistsError if target exists
            try:
                os.link(tmp_path, target)
                tmp_path.unlink()
            except (FileExistsError, OSError) as err:
                if isinstance(err, FileExistsError) or target.exists():
                    raise FileExistsSecurityError(f"Target file already exists: {target}")
                # If hard linking is not supported across filesystem or platform, fallback to atomic replace
                os.replace(tmp_path, target)
        else:
            os.replace(tmp_path, target)
    except Exception:
        # Guarantee cleanup of temporary staged output on any failure
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise


def encrypt_file(
    input_path: Path,
    output_path: Path,
    key_output_path: Optional[Path] = None,
    mode: str = "gcm",
    overwrite: bool = False,
) -> Dict[str, Any]:
    """Encrypt a local file to .svlt container format with fresh DEK and external key."""
    mode_lower = mode.lower()
    if mode_lower not in ("gcm", "cbc"):
        raise ValueError(f"Unsupported mode: '{mode}'. Allowed modes are 'gcm' and 'cbc'.")

    _check_path_safety(input_path, output_path, overwrite=overwrite)
    if key_output_path is not None:
        _check_path_safety(input_path, key_output_path, overwrite=overwrite)
        if output_path.resolve() == key_output_path.resolve():
            raise SameFileError("Output container and key output cannot be the same file.")

    plaintext = input_path.read_bytes()
    if len(plaintext) > MAX_CIPHERTEXT_SIZE:
        raise ValueError(
            f"File size {len(plaintext)} exceeds maximum supported size {MAX_CIPHERTEXT_SIZE} bytes."
        )

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

    # Write key record first (if requested) then container
    if key_output_path is not None:
        key_record = ExternalKeyRecord(
            version=1,
            file_id=file_id,
            cipher_id=cipher_id,
            dek=dek,
        )
        _safe_write_bytes(key_output_path, key_record.serialize(), overwrite=overwrite, file_mode=0o600)

    try:
        _safe_write_bytes(output_path, container_bytes, overwrite=overwrite, file_mode=0o600)
    except Exception:
        # If writing container fails, clean up the newly created key file if we created it
        if key_output_path is not None and key_output_path.exists() and not overwrite:
            try:
                key_output_path.unlink()
            except OSError:
                pass
        raise

    return {
        "file_id": file_id.hex(),
        "mode": mode_lower,
        "input_bytes": len(plaintext),
        "ciphertext_bytes": len(ciphertext),
        "container_bytes": len(container_bytes),
        "output_path": str(output_path),
        "key_path": str(key_output_path) if key_output_path else None,
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
    if not key_file_path.exists():
        raise FileNotFoundError(f"Key file does not exist: {key_file_path}")

    container_bytes = input_path.read_bytes()
    parsed = parse_container(container_bytes)

    # Mode enforcement check
    if require_mode is not None:
        req_norm = require_mode.lower()
        container_mode = "gcm" if parsed.header.cipher_id == CIPHER_GCM else "cbc"
        if req_norm != container_mode:
            raise ModeMismatchError(
                f"Mode policy violation: caller required mode '{req_norm}', but container has mode '{container_mode}'."
            )

    key_bytes = key_file_path.read_bytes()
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

    # Publish plaintext only after complete cryptographic verification
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
    if not input_path.exists():
        raise FileNotFoundError(f"File not found: {input_path}")

    data = input_path.read_bytes()
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

