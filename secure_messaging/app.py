"""Command-line Secure Messaging application."""
from __future__ import annotations
import secrets
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from getpass import getpass
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from . import crypto
from .db import Database
from .emailer import send_reset_token_email
from .validation import validate_password
from .totp import generate_totp_secret, generate_totp_qr_code, verify_totp


@dataclass
class ActiveSession:
    username: str
    secrets: crypto.UserSecrets
    public_profile: dict


class AuthService:
    def __init__(self, database: Optional[Database] = None):
        self.db = database or Database()

    def register(self, username: str, password: str, email: str | None = None) -> None:
        """
        Register a new user with password complexity validation.
        
        Raises ValueError if password doesn't meet complexity requirements
        or if username already exists.
        """
        # Validate password complexity
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            raise ValueError(error_msg)
        
        if self.db.get_user(username):
            raise ValueError("User already exists")
        secrets, public_payload = crypto.generate_user_secrets()
        password_hash = crypto.hash_password(password)
        wrapped_keys = crypto.wrap_private_keys(password, secrets)
        user_record = {
            "username": username,
            "password_hash": password_hash,
            "wrapped_keys": wrapped_keys,
            "public": public_payload,
            "created_at": datetime.utcnow().isoformat(),
            "email": email,
            "reset_code": None,
            "reset_code_created_at": None,
            "totp_secret": None,
            "reset_token": None,
            "reset_token_expires_at": None,
        }
        self.db.create_user(user_record)

    def login(self, username: str, password: str, totp_token: str | None = None) -> Tuple[ActiveSession, bool]:
        """
        Login a user with optional TOTP verification.
        
        Returns:
            Tuple of (ActiveSession, requires_totp)
            - If user has TOTP enabled and token not provided, returns (None, True)
            - If TOTP token provided but invalid, raises ValueError
            - If successful, returns (ActiveSession, False)
        """
        user = self.db.get_user(username)
        if not user:
            raise ValueError("Unknown user")
        if not crypto.verify_password(password, user["password_hash"]):
            raise ValueError("Invalid credentials")
        
        # Check if TOTP is enabled
        if user.get("totp_secret"):
            if not totp_token:
                # Password correct but TOTP required
                return None, True
            # Verify TOTP token
            if not verify_totp(user["totp_secret"], totp_token):
                raise ValueError("Invalid TOTP token")
        
        secrets = crypto.unwrap_private_keys(password, user["wrapped_keys"])
        return ActiveSession(username=username, secrets=secrets, public_profile=user["public"]), False
    
    def setup_totp(self, username: str) -> Tuple[str, str]:
        """
        Generate TOTP secret and QR code for a user.
        
        Returns:
            Tuple of (secret, qr_code_data_url)
        """
        user = self.db.get_user(username)
        if not user:
            raise ValueError("Unknown user")
        
        secret = generate_totp_secret(username)
        qr_code = generate_totp_qr_code(secret, username)
        self.db.set_totp_secret(username, secret)
        return secret, qr_code
    
    def disable_totp(self, username: str) -> None:
        """Disable TOTP for a user."""
        self.db.set_totp_secret(username, None)

    def list_users(self) -> List[dict]:
        return self.db.list_users()

    def reset_password_for_username(self, username: str, new_password: str) -> None:
        """
        Reset a user's password and key material.
        
        Validates password complexity before resetting.

        NOTE: For simplicity and security, this regenerates the user's keypair
        and deletes all stored messages to/from that user. Old messages can no
        longer be decrypted after a reset.
        """
        # Validate password complexity
        is_valid, error_msg = validate_password(new_password)
        if not is_valid:
            raise ValueError(error_msg)
        
        user = self.db.get_user(username)
        if not user:
            raise ValueError("Unknown user")
        secrets, public_payload = crypto.generate_user_secrets()
        password_hash = crypto.hash_password(new_password)
        wrapped_keys = crypto.wrap_private_keys(new_password, secrets)
        user_record = {
            "username": username,
            "password_hash": password_hash,
            "wrapped_keys": wrapped_keys,
            "public": public_payload,
            "created_at": datetime.utcnow().isoformat(),
        }
        self.db.reset_user(user_record)
        self.db.delete_messages_for_user(username)

    def start_password_reset(self, email: str) -> None:
        """
        Generate and store a secure reset token with expiration (1 hour TTL).
        Send the token to the user's registered email address.
        
        This is a production-ready implementation where the token is never exposed
        to the frontend and is only sent via secure email.
        
        For security, this method does not reveal whether the email exists or not.
        If the email is not registered, it silently succeeds (prevents email enumeration).
        If SMTP fails, it raises an exception.
        
        Raises:
            ValueError: If SMTP configuration is missing or email sending fails
        """
        user = self.db.get_user_by_email(email)
        if not user:
            # Security: Don't reveal whether email exists (prevents email enumeration)
            # Silently return - the server endpoint will return generic success message
            return
        
        # Generate secure token (32 bytes, URL-safe)
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.utcnow() + timedelta(hours=1)).isoformat()
        self.db.set_reset_token(user["username"], token, expires_at)
        
        # Build reset URL with token as query parameter
        # In production, this would be your actual domain (e.g., https://yourdomain.com/reset_password.html?token=...)
        reset_url = f"/reset_password.html?token={token}"
        
        # Send email with reset token
        # This will raise ValueError if SMTP fails (configuration issue or network error)
        try:
            send_reset_token_email(email, token, reset_url)
        except ValueError as e:
            # Re-raise SMTP errors so they can be handled appropriately
            # These are actual failures that should be reported
            raise ValueError(f"Failed to send reset email. Please try again later or contact support.") from e

    def complete_password_reset(self, token: str, new_password: str) -> None:
        """
        Complete password reset using secure token.
        
        Validates token expiration and password complexity.
        """
        # Validate password complexity
        is_valid, error_msg = validate_password(new_password)
        if not is_valid:
            raise ValueError(error_msg)
        
        user = self.db.get_user_by_reset_token(token)
        if not user:
            raise ValueError("Invalid or expired reset token")
        
        # Check expiration
        if user.get("reset_token_expires_at"):
            expires_at = datetime.fromisoformat(user["reset_token_expires_at"])
            if datetime.utcnow() > expires_at:
                raise ValueError("Reset token has expired")
        
        self.reset_password_for_username(user["username"], new_password)
        # Clear reset token after successful reset
        self.db.set_reset_token(user["username"], None, None)


class MessagingService:
    def __init__(self, database: Optional[Database] = None):
        self.db = database or Database()

    def send_message(self, session: ActiveSession, recipient_username: str, plaintext: str) -> dict:
        recipient = self.db.get_user(recipient_username)
        if not recipient:
            raise ValueError("Recipient not found")
        recipient_public = recipient["public"]
        eph_private = x25519.X25519PrivateKey.generate()
        aes_key, hmac_key = crypto.derive_message_key(
            eph_private, crypto.b64decode(recipient_public["x25519"])
        )
        # encrypt_message now returns a dict with nonce, ciphertext, and hmac (all base64-encoded)
        # Pass both AES key and HMAC key for defense-in-depth
        encrypted = crypto.encrypt_message(aes_key, plaintext.encode("utf-8"), hmac_key)
        envelope = {
            "sender": session.username,
            "recipient": recipient_username,
            "timestamp": datetime.utcnow().isoformat(),
            "nonce": encrypted["nonce"],
            "ciphertext": encrypted["ciphertext"],
            "hmac": encrypted["hmac"],
            "ephemeral_pub": crypto.b64encode(
                eph_private.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ),
        }
        signature_payload = json.dumps(envelope, sort_keys=True).encode("utf-8")
        signature = crypto.sign_message(session.secrets.ed25519_private, signature_payload)
        envelope["signature"] = crypto.b64encode(signature)
        self.db.add_message(envelope)
        return envelope

    def inbox(self, session: ActiveSession) -> List[dict]:
        messages = self.db.messages_for_user(session.username)
        decrypted = []
        for msg in messages:
            payload = json.dumps({k: msg[k] for k in msg if k != "signature"}, sort_keys=True).encode("utf-8")
            sender = self.db.get_user(msg["sender"])
            signature_valid = False
            if sender:
                signature_valid = crypto.verify_signature(
                    crypto.b64decode(sender["public"]["ed25519"]),
                    payload,
                    crypto.b64decode(msg["signature"]),
                )
            aes_key, hmac_key = crypto.derive_message_key(
                session.secrets.x25519_private,
                crypto.b64decode(msg["ephemeral_pub"]),
            )
            plaintext = ""
            try:
                # decrypt_message now takes a dict with nonce, ciphertext, and hmac
                # It verifies HMAC before decrypting
                encrypted_data = {
                    "nonce": msg["nonce"],
                    "ciphertext": msg["ciphertext"],
                    "hmac": msg.get("hmac", ""),  # Support old messages without HMAC (backward compat)
                }
                # If HMAC is missing (old message), skip HMAC verification
                if not encrypted_data.get("hmac"):
                    # Fallback for messages created before HMAC was added
                    plaintext_bytes = crypto.decrypt_message_legacy(
                        aes_key,
                        crypto.b64decode(msg["nonce"]),
                        crypto.b64decode(msg["ciphertext"]),
                    )
                else:
                    plaintext_bytes = crypto.decrypt_message(aes_key, encrypted_data, hmac_key)
                plaintext = plaintext_bytes.decode("utf-8")
            except Exception as exc:  # pragma: no cover - displayed to user
                plaintext = f"<decryption failed: {exc}>"
            decrypted.append(
                {
                    "from": msg["sender"],
                    "timestamp": msg["timestamp"],
                    "message": plaintext,
                    "signature_valid": signature_valid,
                }
            )
        return decrypted


class SecureMessagingCLI:
    def __init__(self):
        database = Database()
        self.auth = AuthService(database=database)
        self.messaging = MessagingService(database=database)
        self.session: Optional[ActiveSession] = None

    def run(self):
        print("Secure Messaging CLI")
        print("Type 'help' for options.")
        while True:
            prefix = self.session.username if self.session else "guest"
            command = input(f"[{prefix}] > ").strip().lower()
            if command in {"quit", "exit"}:
                print("Goodbye!")
                break
            if command == "help":
                self._print_help()
                continue
            if not self.session:
                if command == "register":
                    self._register()
                elif command == "login":
                    self._login()
                else:
                    print("Please login or register first.")
            else:
                if command == "send":
                    self._send()
                elif command == "inbox":
                    self._inbox()
                elif command == "users":
                    self._list_users()
                elif command == "logout":
                    self.session = None
                else:
                    print("Unknown command.")

    def _print_help(self):
        print("Commands: register, login, send, inbox, users, logout, quit")

    def _register(self):
        username = input("Choose username: ").strip()
        password = getpass("Choose password: ")
        confirm = getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.")
            return
        try:
            self.auth.register(username, password)
            print("User registered.")
        except ValueError as err:
            print(f"Registration failed: {err}")

    def _login(self):
        username = input("Username: ").strip()
        password = getpass("Password: ")
        try:
            session, requires_totp = self.auth.login(username, password)
            if requires_totp:
                totp_token = input("TOTP code (6 digits): ").strip()
                session, _ = self.auth.login(username, password, totp_token)
            self.session = session
            print(f"Welcome {username}!")
        except ValueError as err:
            print(f"Login failed: {err}")

    def _send(self):
        assert self.session
        recipient = input("Recipient username: ").strip()
        message = input("Message: ")
        try:
            self.messaging.send_message(self.session, recipient, message)
            print("Message sent.")
        except ValueError as err:
            print(f"Send failed: {err}")

    def _inbox(self):
        assert self.session
        messages = self.messaging.inbox(self.session)
        if not messages:
            print("No messages.")
            return
        for idx, msg in enumerate(messages, start=1):
            status = "valid" if msg["signature_valid"] else "invalid"
            print(f"[{idx}] From {msg['from']} @ {msg['timestamp']} ({status} signature)")
            print(f"    {msg['message']}")

    def _list_users(self):
        users = self.auth.list_users()
        print("Registered users:")
        for user in users:
            print(f" - {user['username']}")


def main():  # pragma: no cover - entrypoint
    SecureMessagingCLI().run()


if __name__ == "__main__":  # pragma: no cover
    main()
