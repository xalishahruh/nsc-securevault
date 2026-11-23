"""Password key derivation for the protected vault keyring."""

from dataclasses import dataclass

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from securevault.errors import KeyringError

SALT_SIZE = 16
UNLOCK_KEY_SIZE = 32
MIN_MEMORY_KIB = 8192
MAX_MEMORY_KIB = 262144
MIN_ITERATIONS = 1
MAX_ITERATIONS = 10
MIN_PARALLELISM = 1
MAX_PARALLELISM = 8
MAX_PASSWORD_BYTES = 1024
MIN_NEW_PASSWORD_CHARS = 15
_PREDICTABLE_PASSWORDS = frozenset({
    "123456789012345", "1234567890123456", "passwordpassword", "password12345678",
    "password password", "qwertyuiopasdfgh", "letmeinletmeinletmein", "correcthorsebatterystaple",
})


@dataclass(frozen=True)
class KDFParameters:
    memory_cost: int = 65536
    iterations: int = 3
    parallelism: int = 4

    def validate(self) -> None:
        values = (self.memory_cost, self.iterations, self.parallelism)
        if any(type(value) is not int for value in values):
            raise KeyringError("Argon2id memory cost, iterations, and parallelism must be integers.")
        if not MIN_MEMORY_KIB <= self.memory_cost <= MAX_MEMORY_KIB:
            raise KeyringError("Argon2id memory cost is outside the supported bounds.")
        if not MIN_ITERATIONS <= self.iterations <= MAX_ITERATIONS:
            raise KeyringError("Argon2id iteration count is outside the supported bounds.")
        if not MIN_PARALLELISM <= self.parallelism <= MAX_PARALLELISM:
            raise KeyringError("Argon2id parallelism is outside the supported bounds.")


DEFAULT_KDF_PARAMETERS = KDFParameters()


def password_bytes(password: str | bytes) -> bytes:
    if isinstance(password, str):
        encoded = password.encode("utf-8")
    elif isinstance(password, bytes):
        encoded = password
    else:
        raise TypeError("Password must be str or bytes.")
    if not encoded or len(encoded) > MAX_PASSWORD_BYTES:
        raise KeyringError("Password must contain between 1 and 1024 UTF-8 bytes.")
    return encoded


def validate_new_password(password: str | bytes) -> None:
    """Apply the managed vault policy only when setting a new password."""
    try:
        text = password_bytes(password).decode("utf-8")
    except UnicodeError:
        raise KeyringError("New vault passwords must be valid UTF-8.") from None
    if len(text) < MIN_NEW_PASSWORD_CHARS or text.isspace():
        raise KeyringError("New vault passwords must be at least 15 characters and contain non-whitespace.")
    # Compare the whole candidate only. Keep the actual KDF input byte-for-byte.
    comparison = text.strip().casefold()
    if comparison in _PREDICTABLE_PASSWORDS or len(set(comparison)) == 1:
        raise KeyringError("New vault password is a commonly predictable value. Choose a different passphrase.")


def derive_unlock_key(
    password: str | bytes,
    salt: bytes,
    parameters: KDFParameters = DEFAULT_KDF_PARAMETERS,
) -> bytes:
    """Derive the 32-byte unlock key using cryptography's Argon2id API."""
    parameters.validate()
    if not isinstance(salt, bytes) or len(salt) != SALT_SIZE:
        raise KeyringError(f"Argon2id salt must be exactly {SALT_SIZE} bytes.")
    return Argon2id(
        salt=salt,
        length=UNLOCK_KEY_SIZE,
        iterations=parameters.iterations,
        lanes=parameters.parallelism,
        memory_cost=parameters.memory_cost,
    ).derive(password_bytes(password))
