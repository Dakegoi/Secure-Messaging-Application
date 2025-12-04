"""Command-line Secure Messaging application."""
from __future__ import annotations
import secrets
import json
import secrets
from dataclasses import dataclass
from datetime import datetime
from getpass import getpass
from typing import List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from . import crypto
from .db import Database
from .emailer import send_reset_code_email


@dataclass
class ActiveSession:
    username: str
    secrets: crypto.UserSecrets
    public_profile: dict


class AuthService:
    def __init__(self, database: Optional[Database] = None):
        self.db = database or Database()

    def register(self, username: str, password: str, email: str | None = None) -> None:
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
        }
        self.db.create_user(user_record)

    def login(self, username: str, password: str) -> ActiveSession:
        user = self.db.get_user(username)
        if not user:
            raise ValueError("Unknown user")
        if not crypto.verify_password(password, user["password_hash"]):
            raise ValueError("Invalid credentials")
        secrets = crypto.unwrap_private_keys(password, user["wrapped_keys"])
        return ActiveSession(username=username, secrets=secrets, public_profile=user["public"])

    def list_users(self) -> List[dict]:
        return self.db.list_users()

    def reset_password_for_username(self, username: str, new_password: str) -> None:
        """
        Reset a user's password and key material.

        NOTE: For simplicity and security, this regenerates the user's keypair
        and deletes all stored messages to/from that user. Old messages can no
        longer be decrypted after a reset.
        """
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

    def start_password_reset(self, email: str) -> str:
        """Generate and store a 4-digit reset code for a user identified by email."""
        user = self.db.get_user_by_email(email)
        if not user:
            raise ValueError("Unknown email")
        code = f"{secrets.randbelow(10_000):04d}"
        self.db.set_reset_code(user["username"], code, datetime.utcnow().isoformat())
        # Fire-and-forget email; errors are swallowed inside send_reset_code_email
        send_reset_code_email(email, code)
        return code

    def complete_password_reset(self, email: str, code: str, new_password: str) -> None:
        user = self.db.get_user_by_email(email)
        if not user:
            raise ValueError("Unknown email")
        if not user.get("reset_code") or user["reset_code"] != code:
            raise ValueError("Invalid reset code")
        self.reset_password_for_username(user["username"], new_password)


class MessagingService:
    def __init__(self, database: Optional[Database] = None):
        self.db = database or Database()

    def send_message(self, session: ActiveSession, recipient_username: str, plaintext: str) -> dict:
        recipient = self.db.get_user(recipient_username)
        if not recipient:
            raise ValueError("Recipient not found")
        recipient_public = recipient["public"]
        eph_private = x25519.X25519PrivateKey.generate()
        aes_key, _ = crypto.derive_message_key(
            eph_private, crypto.b64decode(recipient_public["x25519"])
        )
        nonce, ciphertext = crypto.encrypt_message(aes_key, plaintext.encode("utf-8"))
        envelope = {
            "sender": session.username,
            "recipient": recipient_username,
            "timestamp": datetime.utcnow().isoformat(),
            "nonce": crypto.b64encode(nonce),
            "ciphertext": crypto.b64encode(ciphertext),
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
            shared_key, _ = crypto.derive_message_key(
                session.secrets.x25519_private,
                crypto.b64decode(msg["ephemeral_pub"]),
            )
            plaintext = ""
            try:
                plaintext_bytes = crypto.decrypt_message(
                    shared_key,
                    crypto.b64decode(msg["nonce"]),
                    crypto.b64decode(msg["ciphertext"]),
                )
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
            self.session = self.auth.login(username, password)
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
