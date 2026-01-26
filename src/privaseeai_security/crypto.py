"""Cryptographic utilities for PrivaseeAI Security."""

import base64
import hashlib
import secrets


class CryptoError(Exception):
    """Cryptography error exception."""
    pass


class Crypto:
    """Cryptographic operations handler."""

    @staticmethod
    def generate_key(key_size: int = 32) -> bytes:
        """Generate a random encryption key.
        
        Args:
            key_size: Size of key in bytes (default: 32 for AES-256)
            
        Returns:
            Random key bytes
        """
        return secrets.token_bytes(key_size)

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        """Encrypt data using AES-256-GCM.
        
        Args:
            data: Data to encrypt
            key: Encryption key
            
        Returns:
            Encrypted data with nonce prepended
            
        Note:
            This is a stub implementation. Real implementation would use
            cryptography library for actual AES-GCM encryption.
        """
        if not data:
            raise CryptoError("Data cannot be empty")
        if len(key) != 32:
            raise CryptoError("Key must be 32 bytes for AES-256")
        
        # Stub implementation - just return base64 encoded data
        # Real implementation would use proper AES-GCM encryption
        nonce = secrets.token_bytes(12)
        encrypted = base64.b64encode(data)
        return nonce + encrypted

    @staticmethod
    def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-256-GCM.
        
        Args:
            encrypted_data: Encrypted data with nonce prepended
            key: Decryption key
            
        Returns:
            Decrypted data
            
        Raises:
            CryptoError: If decryption fails
        """
        if not encrypted_data:
            raise CryptoError("Encrypted data cannot be empty")
        if len(key) != 32:
            raise CryptoError("Key must be 32 bytes for AES-256")
        if len(encrypted_data) < 13:  # 12 bytes nonce + at least 1 byte data
            raise CryptoError("Encrypted data too short")
        
        # Stub implementation - extract and decode base64
        # Note: In real implementation, first 12 bytes would be the nonce for AES-GCM
        encrypted = encrypted_data[12:]
        return base64.b64decode(encrypted)

    @staticmethod
    def hash_data(data: bytes, algorithm: str = "sha256") -> str:
        """Hash data using specified algorithm.
        
        Args:
            data: Data to hash
            algorithm: Hash algorithm (default: sha256)
            
        Returns:
            Hex string of hash
            
        Raises:
            CryptoError: If algorithm is not supported
        """
        if algorithm not in hashlib.algorithms_available:
            raise CryptoError(f"Unsupported hash algorithm: {algorithm}")
        
        hasher = hashlib.new(algorithm)
        hasher.update(data)
        return hasher.hexdigest()

    @staticmethod
    def verify_hash(data: bytes, hash_value: str, algorithm: str = "sha256") -> bool:
        """Verify data hash.
        
        Args:
            data: Data to verify
            hash_value: Expected hash value
            algorithm: Hash algorithm
            
        Returns:
            True if hash matches, False otherwise
        """
        computed_hash = Crypto.hash_data(data, algorithm)
        return secrets.compare_digest(computed_hash, hash_value)
