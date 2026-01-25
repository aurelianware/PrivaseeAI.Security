"""Encryption utilities for PrivaseeAI.Security."""

from cryptography.fernet import Fernet, InvalidToken

from privaseeai_security.core.exceptions import EncryptionError
from privaseeai_security.core.logger import get_logger

logger = get_logger(__name__)


class CryptoManager:
    """Manager for encryption and decryption operations."""

    def __init__(self, encryption_key: str | None = None):
        """Initialize crypto manager.

        Args:
            encryption_key: Base64-encoded Fernet key. If None, a new key is generated.

        Raises:
            EncryptionError: If the encryption key is invalid
        """
        if encryption_key:
            try:
                self.cipher = Fernet(encryption_key.encode())
            except Exception as e:
                raise EncryptionError(f"Invalid encryption key: {e}") from e
        else:
            # Generate a new key if none provided
            key = Fernet.generate_key()
            self.cipher = Fernet(key)
            logger.warning(
                "No encryption key provided. Generated a new key. "
                "This key should be saved and used consistently."
            )

    @staticmethod
    def generate_key() -> str:
        """Generate a new Fernet encryption key.

        Returns:
            Base64-encoded encryption key as string
        """
        key = Fernet.generate_key()
        return key.decode()

    def encrypt(self, data: str | bytes) -> bytes:
        """Encrypt data.

        Args:
            data: Data to encrypt (string or bytes)

        Returns:
            Encrypted data as bytes

        Raises:
            EncryptionError: If encryption fails
        """
        try:
            if isinstance(data, str):
                data = data.encode()
            return self.cipher.encrypt(data)
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}") from e

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data.

        Args:
            encrypted_data: Encrypted data as bytes

        Returns:
            Decrypted data as bytes

        Raises:
            EncryptionError: If decryption fails
        """
        try:
            return self.cipher.decrypt(encrypted_data)
        except InvalidToken as e:
            raise EncryptionError("Invalid token or corrupted data") from e
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {e}") from e

    def encrypt_string(self, data: str) -> str:
        """Encrypt a string and return as base64-encoded string.

        Args:
            data: String to encrypt

        Returns:
            Base64-encoded encrypted string
        """
        encrypted = self.encrypt(data)
        return encrypted.decode()

    def decrypt_string(self, encrypted_data: str) -> str:
        """Decrypt a base64-encoded encrypted string.

        Args:
            encrypted_data: Base64-encoded encrypted string

        Returns:
            Decrypted string
        """
        decrypted = self.decrypt(encrypted_data.encode())
        return decrypted.decode()


def hash_string(data: str) -> str:
    """Create a hash of a string for comparison purposes.

    Args:
        data: String to hash

    Returns:
        Hex-encoded hash string

    Note:
        This uses SHA-256 for hashing and is suitable for non-cryptographic
        purposes like deduplication and comparison.
    """
    import hashlib

    return hashlib.sha256(data.encode()).hexdigest()


def secure_random_string(length: int = 32) -> str:
    """Generate a secure random string.

    Args:
        length: Length of the random string

    Returns:
        Hex-encoded random string
    """
    import secrets

    return secrets.token_hex(length // 2)
