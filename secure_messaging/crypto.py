"""Cryptographic primitives for the secure messaging application."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Dict, Tuple

import bcrypt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HKDF_INFO = b"secure-messaging-2025"
PASSWORD_INFO = b"secure-messaging-password-wrap"

# HMAC constants
HMAC_BLOCK_SIZE = 64  # SHA-256 block size
HMAC_OPAD = bytes([0x5C] * HMAC_BLOCK_SIZE)
HMAC_IPAD = bytes([0x36] * HMAC_BLOCK_SIZE)


@dataclass
class UserSecrets:
    """Holds private keys loaded for a user session."""

    x25519_private: x25519.X25519PrivateKey
    ed25519_private: ed25519.Ed25519PrivateKey

    @property
    def x25519_public_bytes(self) -> bytes:
        return self.x25519_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def ed25519_public_bytes(self) -> bytes:
        return self.ed25519_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


def generate_user_secrets() -> Tuple[UserSecrets, dict]:
    """Generate a new key pair bundle for a user."""

    x_priv = x25519.X25519PrivateKey.generate()
    e_priv = ed25519.Ed25519PrivateKey.generate()
    secrets = UserSecrets(x_priv, e_priv)
    public_payload = {
        "x25519": b64encode(secrets.x25519_public_bytes),
        "ed25519": b64encode(secrets.ed25519_public_bytes),
    }
    return secrets, public_payload


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def _password_kdf(password: str, salt: bytes) -> bytes:
    """Derive a key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(password.encode("utf-8"))


def wrap_private_keys(password: str, secrets: UserSecrets) -> dict:
    """Encrypt private keys with a password-derived key."""

    salt = os.urandom(16)
    key = _password_kdf(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    payload = json.dumps(
        {
            "x25519": b64encode(
                secrets.x25519_private.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            ),
            "ed25519": b64encode(
                secrets.ed25519_private.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            ),
        }
    ).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, payload, PASSWORD_INFO)
    return {
        "salt": b64encode(salt),
        "nonce": b64encode(nonce),
        "blob": b64encode(ciphertext),
    }


def unwrap_private_keys(password: str, wrapped: dict) -> UserSecrets:
    """Decrypt and unwrap private keys using a password."""
    salt = b64decode(wrapped["salt"])
    nonce = b64decode(wrapped["nonce"])
    blob = b64decode(wrapped["blob"])
    key = _password_kdf(password, salt)
    aesgcm = AESGCM(key)
    payload = aesgcm.decrypt(nonce, blob, PASSWORD_INFO)
    data = json.loads(payload.decode("utf-8"))
    x_priv = x25519.X25519PrivateKey.from_private_bytes(b64decode(data["x25519"]))
    e_priv = ed25519.Ed25519PrivateKey.from_private_bytes(b64decode(data["ed25519"]))
    return UserSecrets(x_priv, e_priv)


def derive_message_key(
    sender_private: x25519.X25519PrivateKey, recipient_public_bytes: bytes
) -> Tuple[bytes, bytes]:
    """
    Derive a shared message encryption key using X25519 ECDH and HKDF.
    
    Returns:
        Tuple of (aes_key, hmac_key) - both 32 bytes
    """
    peer_public = x25519.X25519PublicKey.from_public_bytes(recipient_public_bytes)
    shared = sender_private.exchange(peer_public)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=HKDF_INFO,
    )
    key_material = hkdf.derive(shared)
    return key_material[:32], key_material[32:]


def _hmac_sha256(key: bytes, message: bytes) -> bytes:
    """
    Manual HMAC-SHA256 implementation.
    
    Implements HMAC as specified in RFC 2104:
    HMAC(k, m) = H((k' ⊕ opad) || H((k' ⊕ ipad) || m))
    
    Where:
    - k' is the key padded/truncated to block size (64 bytes for SHA-256)
    - opad = 0x5C repeated, ipad = 0x36 repeated
    - H is SHA-256
    
    Args:
        key: HMAC key (any length)
        message: Message to authenticate
    
    Returns:
        32-byte HMAC tag
    """
    # Step 1: Prepare key (k')
    if len(key) > HMAC_BLOCK_SIZE:
        # If key is longer than block size, hash it first
        key = hashlib.sha256(key).digest()
    
    # Pad key to block size with zeros
    key_padded = key + bytes(HMAC_BLOCK_SIZE - len(key))
    
    # Step 2: Inner hash: H((k' ⊕ ipad) || m)
    inner_key = bytes(a ^ b for a, b in zip(key_padded, HMAC_IPAD))
    inner_hash = hashlib.sha256(inner_key + message).digest()
    
    # Step 3: Outer hash: H((k' ⊕ opad) || inner_hash)
    outer_key = bytes(a ^ b for a, b in zip(key_padded, HMAC_OPAD))
    hmac_tag = hashlib.sha256(outer_key + inner_hash).digest()
    
    return hmac_tag


def hmac_b64(key: bytes, message: bytes) -> str:
    """
    Compute HMAC-SHA256 and return base64-encoded result.
    
    Args:
        key: HMAC key
        message: Message to authenticate
    
    Returns:
        Base64-encoded HMAC tag
    """
    return b64encode(_hmac_sha256(key, message))


def compare_digest(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison of two byte strings.
    
    Prevents timing attacks by ensuring comparison takes constant time
    regardless of where the first difference occurs.
    
    Args:
        a: First byte string
        b: Second byte string
    
    Returns:
        True if strings are equal, False otherwise
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0


def encrypt_message(key: bytes, plaintext: bytes, hmac_key: bytes | None = None) -> Dict[str, str]:
    """
    Encrypt a message using AES-256-GCM and compute HMAC over nonce || ciphertext.
    
    The encryption key is used for AES-GCM, and the HMAC is computed using
    a separate HMAC key for defense-in-depth security.
    
    Args:
        key: 32-byte AES encryption key
        plaintext: Message to encrypt
        hmac_key: 32-byte HMAC key (if None, uses the same key as AES - backward compat)
    
    Returns:
        Dictionary with base64-encoded:
        - nonce: 12-byte nonce used for AES-GCM
        - ciphertext: Encrypted message
        - hmac: HMAC-SHA256 of (nonce || ciphertext)
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    # Compute HMAC over nonce || ciphertext
    # This provides an additional integrity check beyond AES-GCM's built-in authentication
    # Use separate HMAC key if provided, otherwise fall back to AES key (backward compat)
    hmac_key_final = hmac_key if hmac_key is not None else key
    hmac_input = nonce + ciphertext
    hmac_tag = _hmac_sha256(hmac_key_final, hmac_input)
    
    return {
        "nonce": b64encode(nonce),
        "ciphertext": b64encode(ciphertext),
        "hmac": b64encode(hmac_tag),
    }


def decrypt_message_legacy(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Legacy decryption function for messages created before HMAC was added.
    
    This function does not verify HMAC and is only for backward compatibility
    with old messages in the database.
    
    Args:
        key: 32-byte AES decryption key
        nonce: 12-byte nonce
        ciphertext: Encrypted message
    
    Returns:
        Decrypted plaintext
    
    Raises:
        ValueError: If decryption fails
    """
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}") from e


def decrypt_message(key: bytes, encrypted_data: Dict[str, str], hmac_key: bytes | None = None) -> bytes:
    """
    Decrypt a message after verifying HMAC.
    
    First verifies the HMAC over nonce || ciphertext, then decrypts if valid.
    This provides defense-in-depth: even if AES-GCM authentication is bypassed,
    the HMAC provides an additional integrity check.
    
    Args:
        key: 32-byte AES decryption key (same as used for encryption)
        encrypted_data: Dictionary with base64-encoded:
            - nonce: 12-byte nonce
            - ciphertext: Encrypted message
            - hmac: HMAC-SHA256 tag
        hmac_key: 32-byte HMAC key (if None, uses the same key as AES - backward compat)
    
    Returns:
        Decrypted plaintext
    
    Raises:
        ValueError: If HMAC verification fails or decryption fails
    """
    # Decode base64 fields
    nonce = b64decode(encrypted_data["nonce"])
    ciphertext = b64decode(encrypted_data["ciphertext"])
    received_hmac = b64decode(encrypted_data["hmac"])
    
    # Verify HMAC before attempting decryption
    # Use separate HMAC key if provided, otherwise fall back to AES key (backward compat)
    hmac_key_final = hmac_key if hmac_key is not None else key
    hmac_input = nonce + ciphertext
    computed_hmac = _hmac_sha256(hmac_key_final, hmac_input)
    
    # Constant-time comparison to prevent timing attacks
    if not compare_digest(computed_hmac, received_hmac):
        raise ValueError("HMAC verification failed: message may have been tampered with")
    
    # HMAC verified, now decrypt
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}") from e


def sign_message(private_key: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
    """Sign a message using Ed25519."""
    return private_key.sign(message)


def verify_signature(public_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify an Ed25519 signature.
    
    Returns:
        True if signature is valid, False otherwise
    """
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def b64encode(payload: bytes) -> str:
    """Encode bytes to base64 string."""
    return base64.b64encode(payload).decode("utf-8")


def b64decode(payload: str) -> bytes:
    """Decode base64 string to bytes."""
    return base64.b64decode(payload.encode("utf-8"))
