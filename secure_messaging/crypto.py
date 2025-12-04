"""Cryptographic primitives for the secure messaging application."""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Tuple

import bcrypt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HKDF_INFO = b"secure-messaging-2025"
PASSWORD_INFO = b"secure-messaging-password-wrap"


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
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def _password_kdf(password: str, salt: bytes) -> bytes:
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


def encrypt_message(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt_message(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def sign_message(private_key: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
    return private_key.sign(message)


def verify_signature(public_bytes: bytes, message: bytes, signature: bytes) -> bool:
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def b64encode(payload: bytes) -> str:
    return base64.b64encode(payload).decode("utf-8")


def b64decode(payload: str) -> bytes:
    return base64.b64decode(payload.encode("utf-8"))
