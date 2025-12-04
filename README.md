# Secure Messaging Application

A reference end-to-end encrypted messaging workflow with both a command-line
client and a small web front end backed by a FastAPI server. Storage is JSON-
file based to keep the cryptography easy to inspect.

## Features

- AES-256-GCM confidentiality with per-message nonces
- X25519 ECDH key exchange (fresh ephemeral keys per message for forward secrecy)
- Ed25519 digital signatures for sender authentication and message integrity
- Bcrypt password hashing plus PBKDF2-wrapped private keys at rest
- REST API (FastAPI + Uvicorn) with a single-page frontend (HTML/CSS/JS)
- Optional CLI interface for terminal-only interaction

> Transport note: run the API behind HTTPS (reverse proxy or `uvicorn --ssl-*`)
> before exposing it beyond localhost to satisfy TLS requirements.

## Project Layout

```
secure_messaging/
  __init__.py
  __main__.py       # CLI entrypoint
  app.py            # shared auth + messaging services
  crypto.py         # AES, ECDH, signatures, password protection
  storage.py        # (legacy) JSON helpers, not used by default
  db.py             # SQLite persistence
  server.py         # FastAPI application + static hosting
frontend/
  index.html
  app.js
  styles.css
data/
  users.json
  messages.json
requirements.txt
README.md
```

Application data (users, messages) is stored in `data/app.db` (SQLite).

## Running the Full Stack (web UI)

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn secure_messaging.server:app --reload --port 8080
```

Then browse to <http://127.0.0.1:8080>. The static frontend is served directly
by FastAPI. Register a couple of users, log in, and exchange messages. All API
calls live under `/api/*` (see `secure_messaging/server.py` for the schema).

### TLS / HTTPS

For production-style deployments terminate TLS in front of the ASGI server.
Options include:

- `uvicorn secure_messaging.server:app --port 8080 --ssl-keyfile ... --ssl-certfile ...`
- Running behind nginx/Traefik/Caddy with LetsEncrypt certificates

## CLI Mode (optional)

The original CLI is still available:

```
python -m secure_messaging
```

Use the prompts (`register`, `login`, `send`, `inbox`, `users`, `logout`, `quit`)
to exercise the same cryptographic flow without the web stack.

## Cryptographic Design

- **Key Exchange**: X25519 ECDH derives a shared secret between the sender’s
  ephemeral key pair and the recipient’s long-term public key. HKDF-SHA256
  expands this secret into a 256-bit AES key (plus spare bytes reserved for
  future HMAC/extensibility).
- **Encryption**: AES-256-GCM protects message bodies and ensures
  confidentiality + integrity.
- **Authentication**: Ed25519 signatures cover the entire message envelope
  (metadata + ciphertext). Recipients verify signatures using the sender’s
  published public key.
- **Password Security**: Bcrypt hashes user passwords and PBKDF2-derived keys
  wrap private key material on disk.

## Extending the Demo

- Replace the JSON stores with a database, HSM, or OS keychain.
- Add group messaging by encrypting per-participant message keys or grafting a
  group key agreement protocol.
- Integrate push notifications, media attachments, or delivery receipts.
