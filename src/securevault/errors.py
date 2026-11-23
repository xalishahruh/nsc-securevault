"""Typed, user-safe exception hierarchy for SecureVault."""


class SecureVaultError(Exception):
    """Base class for all SecureVault errors."""


# --- Cryptographic Errors ---

class CryptoError(SecureVaultError):
    """Base class for cryptographic operation failures."""


class AuthenticationError(CryptoError):
    """Raised when GCM authentication tag verification fails (ciphertext/header modified)."""


class PaddingError(CryptoError):
    """Raised when CBC PKCS#7 padding validation or removal fails."""


class InvalidKeyError(CryptoError):
    """Raised when a key is malformed, invalid in length, or of wrong type."""


class KeyringError(CryptoError):
    """Raised when a protected keyring is malformed or cannot be unlocked."""


class ModeMismatchError(CryptoError):
    """Raised when caller requested mode does not match the file or key cipher mode."""


class KeyReuseError(CryptoError):
    """Raised when an attempt is made to reuse a previously used DEK for new encryption."""


# --- Container Format Errors ---

class ContainerFormatError(SecureVaultError):
    """Base class for .svlt container parsing and serialization errors."""


class InvalidHeaderError(ContainerFormatError):
    """Raised when .svlt header magic, version, flags, or cipher ID is invalid."""


class MalformedContainerError(ContainerFormatError):
    """Raised when container sizes are invalid, truncated, or contain trailing bytes."""


# --- File and Storage Errors ---

class FileServiceError(SecureVaultError):
    """Base class for safe file staging and I/O errors."""


class FileExistsSecurityError(FileServiceError):
    """Raised when target output file already exists and overwrite is not permitted."""


class SameFileError(FileServiceError):
    """Raised when source and destination files refer to the same filesystem entity."""


class PathSecurityError(FileServiceError):
    """Raised when path traversal or forbidden symlink is encountered."""



class ManifestError(SecureVaultError):
    """Raised when a manifest format or expected association is invalid."""
