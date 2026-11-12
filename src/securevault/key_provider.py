"""Key provider abstractions and external development key (.svkey) adapter."""

import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional
from securevault.errors import InvalidKeyError, ModeMismatchError

MAGIC_KEY = b"SVKY"
KEY_RECORD_VERSION = 1
KEY_RECORD_SIZE = 54  # 4 + 1 + 16 + 1 + 32


@dataclass(frozen=True)
class ExternalKeyRecord:
    """Represents a 54-byte external key record (.svkey)."""
    version: int
    file_id: bytes
    cipher_id: int
    dek: bytes

    def serialize(self) -> bytes:
        """Serialize into exact 54-byte external key record."""
        if len(self.file_id) != 16:
            raise ValueError(f"file_id must be 16 bytes; got {len(self.file_id)}.")
        if len(self.dek) != 32:
            raise InvalidKeyError(f"DEK must be 32 bytes; got {len(self.dek)}.")
        if self.cipher_id not in (1, 2):
            raise ValueError(f"cipher_id must be 1 (GCM) or 2 (CBC); got {self.cipher_id}.")

        packed = struct.pack(
            ">4sB16sB32s",
            MAGIC_KEY,
            self.version,
            self.file_id,
            self.cipher_id,
            self.dek,
        )
        assert len(packed) == KEY_RECORD_SIZE
        return packed

    @classmethod
    def parse(cls, data: bytes) -> "ExternalKeyRecord":
        """Parse and strictly validate a 54-byte external key record."""
        if len(data) != KEY_RECORD_SIZE:
            raise InvalidKeyError(
                f"External key record must be exactly {KEY_RECORD_SIZE} bytes; got {len(data)}."
            )

        magic, version, file_id, cipher_id, dek = struct.unpack(">4sB16sB32s", data)
        if magic != MAGIC_KEY:
            raise InvalidKeyError(f"Invalid key file magic: expected {MAGIC_KEY!r}, got {magic!r}.")
        if version != KEY_RECORD_VERSION:
            raise InvalidKeyError(f"Unsupported key file version: expected {KEY_RECORD_VERSION}, got {version}.")
        if cipher_id not in (1, 2):
            raise InvalidKeyError(f"Unsupported cipher ID in key file: {cipher_id}.")

        return cls(
            version=version,
            file_id=file_id,
            cipher_id=cipher_id,
            dek=dek,
        )

    def validate_association(self, expected_file_id: bytes, expected_cipher_id: int) -> None:
        """Validate that this key matches the container's file ID and cipher mode."""
        if self.file_id != expected_file_id:
            raise InvalidKeyError(
                f"Key file ID ({self.file_id.hex()}) does not match container file ID ({expected_file_id.hex()})."
            )
        if self.cipher_id != expected_cipher_id:
            mode_names = {1: "GCM", 2: "CBC"}
            key_m = mode_names.get(self.cipher_id, str(self.cipher_id))
            cont_m = mode_names.get(expected_cipher_id, str(expected_cipher_id))
            raise ModeMismatchError(
                f"Key cipher mode ({key_m}) does not match container cipher mode ({cont_m})."
            )


class BaseKeyProvider(ABC):
    """Abstract interface for retrieving or generating file encryption keys."""

    @abstractmethod
    def get_dek_for_decryption(self, file_id: bytes, cipher_id: int) -> bytes:
        """Retrieve the 32-byte DEK matching the given file ID and cipher mode."""
        pass


class ExternalKeyProvider(BaseKeyProvider):
    """Key provider backed by an ExternalKeyRecord (.svkey)."""

    def __init__(self, key_record: ExternalKeyRecord):
        self._record = key_record

    @property
    def record(self) -> ExternalKeyRecord:
        return self._record

    def get_dek_for_decryption(self, file_id: bytes, cipher_id: int) -> bytes:
        self._record.validate_association(file_id, cipher_id)
        return self._record.dek

