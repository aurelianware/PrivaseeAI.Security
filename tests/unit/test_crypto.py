"""Unit tests for cryptographic utilities."""

import pytest

from privaseeai_security.crypto import Crypto, CryptoError


class TestCrypto:
    """Test cases for Crypto class."""

    def test_generate_key_default_size(self):
        """Test key generation with default size (32 bytes)."""
        key = Crypto.generate_key()
        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_generate_key_custom_size(self):
        """Test key generation with custom size."""
        key = Crypto.generate_key(key_size=16)
        assert len(key) == 16

    def test_generate_key_uniqueness(self):
        """Test that generated keys are unique."""
        key1 = Crypto.generate_key()
        key2 = Crypto.generate_key()
        assert key1 != key2

    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption roundtrip."""
        data = b"Sensitive security data"
        key = Crypto.generate_key()
        
        encrypted = Crypto.encrypt(data, key)
        decrypted = Crypto.decrypt(encrypted, key)
        
        assert decrypted == data

    def test_encrypt_empty_data(self):
        """Test encryption with empty data raises error."""
        key = Crypto.generate_key()
        with pytest.raises(CryptoError, match="Data cannot be empty"):
            Crypto.encrypt(b"", key)

    def test_encrypt_invalid_key_size(self):
        """Test encryption with invalid key size."""
        data = b"Test data"
        invalid_key = b"short_key"
        with pytest.raises(CryptoError, match="Key must be 32 bytes"):
            Crypto.encrypt(data, invalid_key)

    def test_decrypt_empty_data(self):
        """Test decryption with empty data raises error."""
        key = Crypto.generate_key()
        with pytest.raises(CryptoError, match="Encrypted data cannot be empty"):
            Crypto.decrypt(b"", key)

    def test_decrypt_invalid_key_size(self):
        """Test decryption with invalid key size."""
        data = b"Test encrypted data"
        invalid_key = b"short_key"
        with pytest.raises(CryptoError, match="Key must be 32 bytes"):
            Crypto.decrypt(data, invalid_key)

    def test_decrypt_too_short_data(self):
        """Test decryption with data too short."""
        key = Crypto.generate_key()
        short_data = b"short"
        with pytest.raises(CryptoError, match="Encrypted data too short"):
            Crypto.decrypt(short_data, key)

    def test_encrypted_data_includes_nonce(self):
        """Test that encrypted data includes nonce (first 12 bytes)."""
        data = b"Test data"
        key = Crypto.generate_key()
        encrypted = Crypto.encrypt(data, key)
        
        # Encrypted data should be at least 13 bytes (12-byte nonce + data)
        assert len(encrypted) >= 13

    def test_hash_data_sha256(self):
        """Test SHA-256 hashing."""
        data = b"Test data for hashing"
        hash_value = Crypto.hash_data(data, algorithm="sha256")
        
        assert isinstance(hash_value, str)
        assert len(hash_value) == 64  # SHA-256 produces 64 hex characters

    def test_hash_data_default_algorithm(self):
        """Test hashing with default algorithm (SHA-256)."""
        data = b"Test data"
        hash_value = Crypto.hash_data(data)
        
        # Should use SHA-256 by default
        assert len(hash_value) == 64

    def test_hash_data_deterministic(self):
        """Test that hashing is deterministic."""
        data = b"Consistent data"
        hash1 = Crypto.hash_data(data)
        hash2 = Crypto.hash_data(data)
        
        assert hash1 == hash2

    def test_hash_data_different_inputs(self):
        """Test that different inputs produce different hashes."""
        hash1 = Crypto.hash_data(b"Data 1")
        hash2 = Crypto.hash_data(b"Data 2")
        
        assert hash1 != hash2

    def test_hash_data_invalid_algorithm(self):
        """Test hashing with invalid algorithm."""
        data = b"Test data"
        with pytest.raises(CryptoError, match="Unsupported hash algorithm"):
            Crypto.hash_data(data, algorithm="invalid_algo")

    def test_verify_hash_correct(self):
        """Test hash verification with correct hash."""
        data = b"Test verification data"
        hash_value = Crypto.hash_data(data)
        
        assert Crypto.verify_hash(data, hash_value) is True

    def test_verify_hash_incorrect(self):
        """Test hash verification with incorrect hash."""
        data = b"Test data"
        wrong_hash = "0" * 64
        
        assert Crypto.verify_hash(data, wrong_hash) is False

    def test_verify_hash_modified_data(self):
        """Test hash verification with modified data."""
        original_data = b"Original data"
        hash_value = Crypto.hash_data(original_data)
        modified_data = b"Modified data"
        
        assert Crypto.verify_hash(modified_data, hash_value) is False

    def test_hash_data_sha512(self):
        """Test hashing with SHA-512."""
        data = b"Test data"
        hash_value = Crypto.hash_data(data, algorithm="sha512")
        
        # SHA-512 produces 128 hex characters
        assert len(hash_value) == 128
