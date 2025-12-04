"""TOTP (Time-based One-Time Password) utilities for MFA."""
import base64
import pyotp
import qrcode
from io import BytesIO
from typing import Tuple


def generate_totp_secret(username: str) -> str:
    """
    Generate a new TOTP secret for a user.
    
    Returns a base32-encoded secret suitable for QR code generation.
    """
    return pyotp.random_base32()


def generate_totp_qr_code(secret: str, username: str, issuer: str = "Secure Messaging") -> str:
    """
    Generate a QR code data URL for TOTP setup.
    
    The QR code contains an otpauth:// URL that authenticator apps can scan.
    
    Returns:
        Base64-encoded data URL (data:image/png;base64,...)
    """
    # Create otpauth URL following Google Authenticator format
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name=issuer
    )
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    
    # Convert to base64 data URL
    img_data = base64.b64encode(buffer.read()).decode()
    return f"data:image/png;base64,{img_data}"


def verify_totp(secret: str, token: str, window: int = 1) -> bool:
    """
    Verify a TOTP token against a secret.
    
    Args:
        secret: Base32-encoded TOTP secret
        token: 6-digit code from authenticator app
        window: Time window tolerance (default 1 = ±30 seconds)
    
    Returns:
        True if token is valid, False otherwise
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=window)

