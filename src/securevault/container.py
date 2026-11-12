"""SVLT v1 binary container format serialization, parsing, and validation."""

import struct
from dataclasses import dataclass
from typing import Optional, Tuple
from securevault.errors import (
    InvalidHeaderError,
    MalformedContainerError,
    ModeMismatchError,
)

# Constants for SVLT v1
MAGIC_CONTAINER = b"SVLT"
CONTAINER_VERSION = 1

CIPHER_GCM = 1
CIPHER_CBC = 2

KEY_PROT_EXTERNAL = 0
KEY_PROT_KWP = 1

HEADER_SIZE = 48
KEY_DESC_SIZE = 3  # 1 byte key_protection_id + 2 bytes key_record_len
GCM_TAG_SIZE = 16

# Maximum supported ciphertext length in initial bounded-memory implementation (256 MiB)
MAX_CIPHERTEXT_SIZE = 256 * 1024 * 1024


@dataclass(frozen=True)
class ContainerHeader:
    """Represents the 48-byte immutable header of a .svlt container."""
    version: int
    cipher_id: int
    flags: int
    file_id: bytes
    iv_or_nonce: bytes  # 12-byte nonce for GCM (without trailing zero padding), 16-byte IV for CBC
    ciphertext_length: int

    def serialize(self) -> bytes:
        """Serialize into exact 48-byte immutable header."""
        if self.cipher_id == CIPHER_GCM:
            if len(self.iv_or_nonce) != 12:
                raise ValueError("GCM nonce must be 12 bytes.")
            iv_slot = self.iv_or_nonce + b"\x00\x00\x00\x00"
        elif self.cipher_id == CIPHER_CBC:
            if len(self.iv_or_nonce) != 16:
                raise ValueError("CBC IV must be 16 bytes.")
            iv_slot = self.iv_or_nonce
        else:
            raise InvalidHeaderError(f"Unsupported cipher ID: {self.cipher_id}")

        if len(self.file_id) != 16:
            raise ValueError("file_id must be 16 bytes.")

        header = struct.pack(
            ">4sBBH16s16sQ",
            MAGIC_CONTAINER,
            self.version,
            self.cipher_id,
            self.flags,
            self.file_id,
            iv_slot,
            self.ciphertext_length,
        )
        assert len(header) == HEADER_SIZE
        return header


@dataclass(frozen=True)
class ParsedContainer:
    """Represents a validated, parsed .svlt container structure."""
    header: ContainerHeader
    immutable_header_bytes: bytes  # Exact 48 bytes (used as GCM AAD)
    key_protection_id: int
    key_record: bytes
    ciphertext: bytes
    gcm_tag: Optional[bytes]


def serialize_container(
    header: ContainerHeader,
    ciphertext: bytes,
    key_protection_id: int = KEY_PROT_EXTERNAL,
    key_record: bytes = b"",
    gcm_tag: Optional[bytes] = None,
) -> bytes:
    """Serialize components into a complete .svlt binary container.

    Layout:
      0..47: Immutable header (48 bytes)
      48: Key protection ID (1 byte)
      49..50: Key record length (2 bytes, big-endian)
      51..51+len: Key record bytes (0 for external, 64 for wrapped)
      next: Ciphertext (ciphertext_length bytes)
      final: GCM tag (16 bytes if GCM, absent if CBC)
    """
    if len(ciphertext) != header.ciphertext_length:
        raise MalformedContainerError(
            f"Ciphertext length {len(ciphertext)} does not match header length {header.ciphertext_length}."
        )

    header_bytes = header.serialize()

    if key_protection_id == KEY_PROT_EXTERNAL:
        if len(key_record) != 0:
            raise MalformedContainerError("External key mode requires empty key record in container.")
    elif key_protection_id == KEY_PROT_KWP:
        if len(key_record) != 64:
            raise MalformedContainerError(f"AES-KWP key record must be 64 bytes; got {len(key_record)}.")
    else:
        raise MalformedContainerError(f"Unsupported key protection ID: {key_protection_id}")

    key_desc = struct.pack(">BH", key_protection_id, len(key_record))

    if header.cipher_id == CIPHER_GCM:
        if gcm_tag is None or len(gcm_tag) != GCM_TAG_SIZE:
            raise MalformedContainerError(f"GCM requires a {GCM_TAG_SIZE}-byte authentication tag.")
        return header_bytes + key_desc + key_record + ciphertext + gcm_tag
    elif header.cipher_id == CIPHER_CBC:
        if gcm_tag is not None and len(gcm_tag) > 0:
            raise MalformedContainerError("CBC mode must not have a GCM tag.")
        return header_bytes + key_desc + key_record + ciphertext
    else:
        raise InvalidHeaderError(f"Unsupported cipher ID: {header.cipher_id}")


def parse_container(data: bytes, max_allowed_size: int = MAX_CIPHERTEXT_SIZE) -> ParsedContainer:
    """Parse and strictly validate a .svlt container from raw bytes.

    Raises typed ContainerFormatError if validation fails.
    """
    total_len = len(data)
    min_required = HEADER_SIZE + KEY_DESC_SIZE
    if total_len < min_required:
        raise MalformedContainerError(
            f"Container truncated: expected at least {min_required} bytes, got {total_len}."
        )

    # 1. Parse fixed immutable header (bytes 0..47)
    header_bytes = data[:HEADER_SIZE]
    magic, version, cipher_id, flags, file_id, iv_slot, ct_len = struct.unpack(
        ">4sBBH16s16sQ", header_bytes
    )

    if magic != MAGIC_CONTAINER:
        raise InvalidHeaderError(f"Invalid magic: expected {MAGIC_CONTAINER!r}, got {magic!r}.")
    if version != CONTAINER_VERSION:
        raise InvalidHeaderError(f"Unsupported version: expected {CONTAINER_VERSION}, got {version}.")
    if flags != 0:
        raise InvalidHeaderError(f"Reserved flags must be zero; got {flags}.")
    if cipher_id not in (CIPHER_GCM, CIPHER_CBC):
        raise InvalidHeaderError(f"Unsupported cipher ID: {cipher_id}.")

    if ct_len > max_allowed_size:
        raise MalformedContainerError(
            f"Declared ciphertext size {ct_len} exceeds maximum allowed limit {max_allowed_size}."
        )

    # Validate IV slot according to mode
    if cipher_id == CIPHER_GCM:
        nonce = iv_slot[:12]
        padding_slot = iv_slot[12:]
        if padding_slot != b"\x00\x00\x00\x00":
            raise InvalidHeaderError("GCM IV slot must have zero padding in the last 4 bytes.")
        iv_or_nonce = nonce
    else:  # CIPHER_CBC
        if ct_len == 0 or ct_len % 16 != 0:
            raise MalformedContainerError(
                f"CBC ciphertext length must be non-zero and divisible by 16; got {ct_len}."
            )
        iv_or_nonce = iv_slot

    header = ContainerHeader(
        version=version,
        cipher_id=cipher_id,
        flags=flags,
        file_id=file_id,
        iv_or_nonce=iv_or_nonce,
        ciphertext_length=ct_len,
    )

    # 2. Parse Key Descriptor (bytes 48..50)
    key_prot_id, key_rec_len = struct.unpack(">BH", data[HEADER_SIZE : HEADER_SIZE + KEY_DESC_SIZE])
    if key_prot_id not in (KEY_PROT_EXTERNAL, KEY_PROT_KWP):
        raise MalformedContainerError(f"Unsupported key protection ID: {key_prot_id}.")

    if key_prot_id == KEY_PROT_EXTERNAL and key_rec_len != 0:
        raise MalformedContainerError(f"External key mode expects key record length 0; got {key_rec_len}.")
    if key_prot_id == KEY_PROT_KWP and key_rec_len != 64:
        raise MalformedContainerError(f"Wrapped key mode expects key record length 64; got {key_rec_len}.")

    offset = HEADER_SIZE + KEY_DESC_SIZE
    if total_len < offset + key_rec_len:
        raise MalformedContainerError("Container truncated in key record.")

    key_record = data[offset : offset + key_rec_len]
    offset += key_rec_len

    # 3. Verify exact remaining payload size
    expected_tag_size = GCM_TAG_SIZE if cipher_id == CIPHER_GCM else 0
    expected_total = offset + ct_len + expected_tag_size

    if total_len < expected_total:
        raise MalformedContainerError(
            f"Container truncated: expected {expected_total} bytes, got {total_len}."
        )
    if total_len > expected_total:
        raise MalformedContainerError(
            f"Container contains trailing bytes: expected {expected_total} bytes, got {total_len}."
        )

    ciphertext = data[offset : offset + ct_len]
    offset += ct_len

    gcm_tag: Optional[bytes] = None
    if cipher_id == CIPHER_GCM:
        gcm_tag = data[offset : offset + GCM_TAG_SIZE]
        if len(gcm_tag) != GCM_TAG_SIZE:
            raise MalformedContainerError(f"Missing or truncated GCM tag: got {len(gcm_tag)} bytes.")

    return ParsedContainer(
        header=header,
        immutable_header_bytes=header_bytes,
        key_protection_id=key_prot_id,
        key_record=key_record,
        ciphertext=ciphertext,
        gcm_tag=gcm_tag,
    )

