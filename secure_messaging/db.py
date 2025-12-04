"""SQLite-backed persistence layer for secure messaging."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import List, Optional, Union

DB_PATH = Path("data/app.db")


class Database:
    def __init__(self, path: Union[Path, str] = DB_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _migrate(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    wrapped_keys TEXT NOT NULL,
                    public_payload TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    ciphertext TEXT NOT NULL,
                    ephemeral_pub TEXT NOT NULL,
                    signature TEXT NOT NULL
                )
                """
            )
            # Lightweight schema evolution for existing DBs
            try:
                conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE users ADD COLUMN reset_code TEXT")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE users ADD COLUMN reset_code_created_at TEXT")
            except sqlite3.OperationalError:
                pass
            # Add TOTP secret for MFA
            try:
                conn.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
            except sqlite3.OperationalError:
                pass
            # Add reset token (replaces simple 4-digit code)
            try:
                conn.execute("ALTER TABLE users ADD COLUMN reset_token TEXT")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE users ADD COLUMN reset_token_expires_at TEXT")
            except sqlite3.OperationalError:
                pass
            conn.commit()

    # User helpers ---------------------------------------------------------
    def list_users(self) -> List[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT username, password_hash, wrapped_keys, public_payload, created_at, email, reset_code, reset_code_created_at, totp_secret, reset_token, reset_token_expires_at FROM users"
            ).fetchall()
        return [self._row_to_user(row) for row in rows]

    def get_user(self, username: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT username, password_hash, wrapped_keys, public_payload, created_at, email, reset_code, reset_code_created_at, totp_secret, reset_token, reset_token_expires_at FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        return self._row_to_user(row) if row else None

    def get_user_by_email(self, email: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT username, password_hash, wrapped_keys, public_payload, created_at, email, reset_code, reset_code_created_at, totp_secret, reset_token, reset_token_expires_at FROM users WHERE email = ?",
                (email,),
            ).fetchone()
        return self._row_to_user(row) if row else None

    def create_user(self, user: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, wrapped_keys, public_payload, created_at, email, reset_code, reset_code_created_at, totp_secret, reset_token, reset_token_expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user["username"],
                    user["password_hash"],
                    json.dumps(user["wrapped_keys"]),
                    json.dumps(user["public"]),
                    user["created_at"],
                    user.get("email"),
                    user.get("reset_code"),
                    user.get("reset_code_created_at"),
                    user.get("totp_secret"),
                    user.get("reset_token"),
                    user.get("reset_token_expires_at"),
                ),
            )
            conn.commit()

    def reset_user(self, user: dict) -> None:
        """Update password + key material for an existing user."""
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE users
                SET password_hash = ?, wrapped_keys = ?, public_payload = ?, created_at = ?, reset_code = NULL, reset_code_created_at = NULL
                WHERE username = ?
                """,
                (
                    user["password_hash"],
                    json.dumps(user["wrapped_keys"]),
                    json.dumps(user["public"]),
                    user["created_at"],
                    user["username"],
                ),
            )
            conn.commit()

    def set_reset_code(self, username: str, code: str, created_at: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE users SET reset_code = ?, reset_code_created_at = ? WHERE username = ?",
                (code, created_at, username),
            )
            conn.commit()

    def set_totp_secret(self, username: str, secret: str) -> None:
        """Store TOTP secret for a user."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE users SET totp_secret = ? WHERE username = ?",
                (secret, username),
            )
            conn.commit()

    def set_reset_token(self, username: str, token: str, expires_at: str) -> None:
        """Store secure reset token with expiration."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE users SET reset_token = ?, reset_token_expires_at = ? WHERE username = ?",
                (token, expires_at, username),
            )
            conn.commit()

    def get_user_by_reset_token(self, token: str) -> Optional[dict]:
        """Get user by reset token (for password reset flow)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT username, password_hash, wrapped_keys, public_payload, created_at, email, reset_code, reset_code_created_at, totp_secret, reset_token, reset_token_expires_at FROM users WHERE reset_token = ?",
                (token,),
            ).fetchone()
        return self._row_to_user(row) if row else None

    # Message helpers ------------------------------------------------------
    def add_message(self, message: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO messages (sender, recipient, timestamp, nonce, ciphertext, ephemeral_pub, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message["sender"],
                    message["recipient"],
                    message["timestamp"],
                    message["nonce"],
                    message["ciphertext"],
                    message["ephemeral_pub"],
                    message["signature"],
                ),
            )
            conn.commit()

    def messages_for_user(self, username: str) -> List[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT sender, recipient, timestamp, nonce, ciphertext, ephemeral_pub, signature
                FROM messages
                WHERE recipient = ?
                ORDER BY id DESC
                """,
                (username,),
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_messages_for_user(self, username: str) -> None:
        """Delete all messages to or from a user (used on password reset)."""
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM messages WHERE sender = ? OR recipient = ?",
                (username, username),
            )
            conn.commit()

    # Internal utilities ---------------------------------------------------
    @staticmethod
    def _row_to_user(row: sqlite3.Row) -> dict:
        return {
            "username": row["username"],
            "password_hash": row["password_hash"],
            "wrapped_keys": json.loads(row["wrapped_keys"]),
            "public": json.loads(row["public_payload"]),
            "created_at": row["created_at"],
            "email": row["email"] if "email" in row.keys() else None,
            "reset_code": row["reset_code"] if "reset_code" in row.keys() else None,
            "reset_code_created_at": row["reset_code_created_at"] if "reset_code_created_at" in row.keys() else None,
            "totp_secret": row["totp_secret"] if "totp_secret" in row.keys() else None,
            "reset_token": row["reset_token"] if "reset_token" in row.keys() else None,
            "reset_token_expires_at": row["reset_token_expires_at"] if "reset_token_expires_at" in row.keys() else None,
        }
