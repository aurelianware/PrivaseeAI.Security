"""Cryptographic utilities for PrivaseeAI Security.

This package exposes the same public API that previously lived in
`src/privaseeai_security/crypto.py`. Moving it into a package allows
submodules, such as `cert_validator`, to live under
`privaseeai_security.crypto` without name conflicts.
"""

import hashlib
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AES-GCM parameters. 96-bit nonces are the size the GCM spec is defined for,
# and the 128-bit tag is what AESGCM appends to the ciphertext.
_NONCE_BYTES = 12
_TAG_BYTES = 16
_KEY_BYTES = 32  # AES-256


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
            data: Plaintext to encrypt. Must be non-empty.
            key: 32-byte encryption key, e.g. from :meth:`generate_key`.

        Returns:
            ``nonce || ciphertext``, where the ciphertext carries the GCM
            authentication tag. A fresh random nonce is generated per call, so
            encrypting the same plaintext twice yields different output.

        Raises:
            CryptoError: If the data is empty or the key is the wrong size.
        """
        if not data:
            raise CryptoError("Data cannot be empty")
        if len(key) != _KEY_BYTES:
            raise CryptoError("Key must be 32 bytes for AES-256")

        nonce = secrets.token_bytes(_NONCE_BYTES)
        ciphertext = AESGCM(key).encrypt(nonce, data, None)
        return nonce + ciphertext

    @staticmethod
    def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt and authenticate data produced by :meth:`encrypt`.

        Args:
            encrypted_data: ``nonce || ciphertext`` as returned by
                :meth:`encrypt`.
            key: The same 32-byte key used to encrypt.

        Returns:
            The original plaintext.

        Raises:
            CryptoError: If the key is wrong, the ciphertext was tampered with,
                or the input is malformed. GCM authenticates the ciphertext, so
                a wrong key fails here rather than returning garbage.
        """
        if not encrypted_data:
            raise CryptoError("Encrypted data cannot be empty")
        if len(key) != _KEY_BYTES:
            raise CryptoError("Key must be 32 bytes for AES-256")
        if len(encrypted_data) < _NONCE_BYTES + _TAG_BYTES:
            raise CryptoError("Encrypted data too short")

        nonce = encrypted_data[:_NONCE_BYTES]
        ciphertext = encrypted_data[_NONCE_BYTES:]
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise CryptoError(
                "Decryption failed: wrong key or corrupted ciphertext"
            ) from exc

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


__all__ = ["Crypto", "CryptoError"]
