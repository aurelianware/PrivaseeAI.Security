"""Unit tests for encryption utilities."""

import pytest

from privaseeai_security.core.exceptions import EncryptionError
from privaseeai_security.utils.crypto import CryptoManager, hash_string, secure_random_string


def test_generate_key():
    """Test key generation."""
    key = CryptoManager.generate_key()
    assert isinstance(key, str)
    assert len(key) > 0


def test_crypto_manager_with_generated_key():
    """Test CryptoManager with auto-generated key."""
    manager = CryptoManager()
    assert manager.cipher is not None


def test_crypto_manager_with_provided_key():
    """Test CryptoManager with provided key."""
    key = CryptoManager.generate_key()
    manager = CryptoManager(key)
    assert manager.cipher is not None


def test_crypto_manager_invalid_key():
    """Test CryptoManager with invalid key."""
    with pytest.raises(EncryptionError):
        CryptoManager("invalid-key")


def test_encrypt_decrypt_bytes():
    """Test encryption and decryption of bytes."""
    manager = CryptoManager()
    data = b"test data"

    encrypted = manager.encrypt(data)
    assert encrypted != data
    assert isinstance(encrypted, bytes)

    decrypted = manager.decrypt(encrypted)
    assert decrypted == data


def test_encrypt_decrypt_string():
    """Test encryption and decryption of strings."""
    manager = CryptoManager()
    data = "test data string"

    encrypted = manager.encrypt(data)
    assert isinstance(encrypted, bytes)

    decrypted = manager.decrypt(encrypted)
    assert decrypted.decode() == data


def test_encrypt_string_decrypt_string():
    """Test string-based encryption and decryption."""
    manager = CryptoManager()
    data = "test data string"

    encrypted = manager.encrypt_string(data)
    assert isinstance(encrypted, str)
    assert encrypted != data

    decrypted = manager.decrypt_string(encrypted)
    assert decrypted == data


def test_decrypt_invalid_data():
    """Test decryption of invalid data."""
    manager = CryptoManager()

    with pytest.raises(EncryptionError):
        manager.decrypt(b"invalid encrypted data")


def test_decrypt_string_invalid_data():
    """Test string decryption of invalid data."""
    manager = CryptoManager()

    with pytest.raises(EncryptionError):
        manager.decrypt_string("invalid encrypted data")


def test_hash_string():
    """Test string hashing."""
    data = "test data"
    hash1 = hash_string(data)

    assert isinstance(hash1, str)
    assert len(hash1) == 64  # SHA-256 produces 64 hex characters

    # Same data should produce same hash
    hash2 = hash_string(data)
    assert hash1 == hash2

    # Different data should produce different hash
    hash3 = hash_string("different data")
    assert hash1 != hash3


def test_secure_random_string():
    """Test secure random string generation."""
    random1 = secure_random_string(32)
    assert isinstance(random1, str)
    assert len(random1) == 32

    # Should generate different strings
    random2 = secure_random_string(32)
    assert random1 != random2

    # Test different lengths
    random3 = secure_random_string(64)
    assert len(random3) == 64
