# Secure Messaging Application

A production-ready end-to-end encrypted messaging application with comprehensive security features, including multi-factor authentication, secure password reset, and modern authentication practices.

## Security Features

### Core Cryptography
- **AES-256-GCM** encryption for message confidentiality with per-message nonces
- **X25519 ECDH** key exchange with fresh ephemeral keys per message (forward secrecy)
- **Ed25519** digital signatures for sender authentication and message integrity
- **Bcrypt** password hashing with configurable cost factor
- **PBKDF2** key derivation for wrapping private keys at rest

### Authentication & Authorization
- **Password Complexity Validation**: Minimum 8 characters, requires at least one letter, one number, and one special character
- **Multi-Factor Authentication (MFA)**: TOTP-based 2FA using authenticator apps (Google Authenticator, Authy, etc.)
- **Secure Session Management**: HttpOnly and Secure cookies for JWT storage (prevents XSS attacks)
- **Secure Password Reset**: Cryptographically secure tokens with 1-hour expiration (replaces simple 4-digit codes)

### Additional Security
- **SQLite Database** for persistent storage with schema migrations
- **Email Integration** for password reset notifications (configurable SMTP)
- **Error Handling**: Comprehensive error messages for all security operations
- **Group Messaging**: End-to-end encrypted group messages

## Project Layout

```
secure_messaging/
  __init__.py
  __main__.py           # CLI entrypoint
  app.py                # Auth + messaging services (password validation, TOTP)
  crypto.py             # AES, ECDH, signatures, password protection
  db.py                 # SQLite persistence with TOTP and reset token support
  server.py             # FastAPI application with cookie-based auth
  validation.py         # Password complexity validation
  totp.py               # TOTP generation and QR code creation
  emailer.py            # SMTP email sending for password reset
frontend/
  index.html            # Main SPA with TOTP setup UI
  app.js                # Frontend logic (cookie-based auth, password validation)
  reset_password.html   # Password reset page with token validation
  styles.css            # UI styling
data/
  app.db                # SQLite database (users, messages, TOTP secrets)
requirements.txt
README.md
LICENSE
```

## Installation

### Prerequisites
- Python 3.9 or higher
- pip (Python package manager)

### Setup

1. **Create virtual environment**:
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Configure email (optional, for password reset)**:
```bash
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USER="your-email@gmail.com"
export SMTP_PASSWORD="your-app-password"  # Use Gmail App Password, not regular password
export SMTP_FROM="your-email@gmail.com"
```

## Running the Application

### Web Interface (Recommended)

Start the FastAPI server:
```bash
uvicorn secure_messaging.server:app --reload --port 8080
```

Then open your browser to `http://127.0.0.1:8080`.

**Features:**
- User registration with password complexity validation
- Login with optional TOTP verification
- TOTP setup with QR code scanning
- Secure password reset with token-based flow
- End-to-end encrypted messaging
- Group messaging support

### CLI Mode

For terminal-based interaction:
```bash
python -m secure_messaging
```

Commands: `register`, `login`, `send`, `inbox`, `users`, `logout`, `quit`

## Security Best Practices

### Password Requirements
- Minimum 8 characters
- At least one letter (a-z, A-Z)
- At least one number (0-9)
- At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)

### TOTP Setup
1. Log in to your account
2. Click "Set up Two-Factor Authentication"
3. Scan the QR code with an authenticator app (Google Authenticator, Authy, Microsoft Authenticator)
4. On next login, you'll be prompted for a 6-digit TOTP code

### Password Reset Flow
1. Click "Forgot password" on login page
2. Enter your registered email address
3. Receive a secure reset token (valid for 1 hour)
4. Navigate to reset page and enter token + new password
5. Password complexity validation applies to new password

### Production Deployment

**Critical Security Settings:**

1. **Enable HTTPS**: Use TLS/SSL certificates
   ```bash
   uvicorn secure_messaging.server:app --ssl-keyfile key.pem --ssl-certfile cert.pem --port 443
   ```

2. **Set Secure Cookie Flag**: In `server.py`, change:
   ```python
   secure=True,  # Requires HTTPS
   ```

3. **Configure CORS**: Restrict origins in `server.py`:
   ```python
   allow_origins=["https://yourdomain.com"]  # Replace with your domain
   ```

4. **Environment Variables**: Store sensitive data (SMTP credentials, secrets) in environment variables, not in code

5. **Database Security**: Use a production database (PostgreSQL, MySQL) with proper access controls

## API Endpoints

### Authentication
- `POST /api/register` - Register new user (requires password complexity)
- `POST /api/login` - Login (returns cookie, may require TOTP)
- `POST /api/logout` - Logout and clear session cookie

### TOTP Management
- `POST /api/totp/setup` - Generate TOTP secret and QR code
- `POST /api/totp/disable` - Disable TOTP for current user

### Password Reset
- `POST /api/forgot-password` - Generate reset token (sends email in production)
- `POST /api/reset-password` - Complete password reset with token

### Messaging
- `GET /api/users` - List registered users
- `GET /api/messages` - Get inbox (decrypted messages)
- `POST /api/messages` - Send encrypted message
- `POST /api/group-messages` - Send message to multiple recipients

## Cryptographic Design

### Key Exchange
X25519 ECDH derives a shared secret between the sender's ephemeral key pair and the recipient's long-term public key. HKDF-SHA256 expands this secret into a 256-bit AES key.

### Encryption
AES-256-GCM protects message bodies and ensures confidentiality + integrity. Each message uses a fresh ephemeral key for forward secrecy.

### Authentication
Ed25519 signatures cover the entire message envelope (metadata + ciphertext). Recipients verify signatures using the sender's published public key.

### Password Security
- **Bcrypt** hashes user passwords (configurable cost factor)
- **PBKDF2** derives keys for wrapping private key material on disk
- **Password complexity validation** prevents weak passwords

### Session Management
- **HttpOnly cookies** prevent JavaScript access (XSS protection)
- **Secure flag** (in production) ensures cookies only sent over HTTPS
- **SameSite=Lax** prevents CSRF attacks

## Error Handling

All endpoints return appropriate HTTP status codes and error messages:
- `400 Bad Request`: Invalid input (weak password, invalid token, etc.)
- `401 Unauthorized`: Authentication required or failed
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server-side errors

Error messages are user-friendly and informative:
- "Password must be at least 8 characters long"
- "Invalid TOTP token"
- "Reset token has expired"
- "User already exists"

## Development

### Running Tests
```bash
# Add pytest to requirements.txt for testing
pytest tests/
```

### Code Structure
- **Backend**: FastAPI with dependency injection for session management
- **Frontend**: Vanilla JavaScript SPA with cookie-based authentication
- **Database**: SQLite with schema migrations for easy development

### Adding Features
- New endpoints: Add to `server.py` with proper error handling
- Frontend changes: Update `app.js` and `index.html`
- Database changes: Add migrations in `db.py._migrate()`

## License

See [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with proper error handling
4. Test thoroughly
5. Submit a pull request

## Acknowledgments

- Uses `cryptography` library for cryptographic primitives
- Uses `pyotp` for TOTP implementation
- Uses `qrcode` for QR code generation
- Uses `bcrypt` for password hashing
- Uses `FastAPI` for the web framework
