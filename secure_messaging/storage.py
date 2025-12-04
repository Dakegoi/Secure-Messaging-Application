"""Persistence helpers for file-backed JSON storage."""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Dict, List, Optional

DEFAULT_DATA_DIR = Path("data")
USERS_FILE = DEFAULT_DATA_DIR / "users.json"
MESSAGES_FILE = DEFAULT_DATA_DIR / "messages.json"


class JSONStore:
    """Minimal file-backed JSON utility with in-memory caching."""

    def __init__(self, path: Path, default):
        self.path = path
        self.default = default
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write(default)

    def _read(self):
        with self.path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _write(self, payload):
        with self.path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    def read(self):
        with self._lock:
            return self._read()

    def write(self, payload):
        with self._lock:
            self._write(payload)


class UserStorage:
    def __init__(self, path: Path = USERS_FILE):
        self.store = JSONStore(path, default={"users": []})

    def list_users(self) -> List[dict]:
        data = self.store.read()
        return data.get("users", [])

    def get_user(self, username: str) -> Optional[dict]:
        for user in self.list_users():
            if user["username"] == username:
                return user
        return None

    def save_user(self, new_user: dict) -> None:
        data = self.store.read()
        users = data.get("users", [])
        for idx, user in enumerate(users):
            if user["username"] == new_user["username"]:
                users[idx] = new_user
                break
        else:
            users.append(new_user)
        self.store.write({"users": users})


class MessageStorage:
    def __init__(self, path: Path = MESSAGES_FILE):
        self.store = JSONStore(path, default={"messages": []})

    def list_messages(self) -> List[dict]:
        data = self.store.read()
        return data.get("messages", [])

    def append_message(self, message: dict) -> None:
        data = self.store.read()
        msgs = data.get("messages", [])
        msgs.append(message)
        self.store.write({"messages": msgs})

    def messages_for_user(self, username: str) -> List[dict]:
        return [msg for msg in self.list_messages() if msg["recipient"] == username]
