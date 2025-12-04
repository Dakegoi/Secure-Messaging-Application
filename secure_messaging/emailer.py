"""Email utilities for sending password reset tokens."""
from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage


SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))

# For Gmail, SMTP_USER should be the full Gmail address and SMTP_PASSWORD an app password.
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

# Default from-address – can be overridden via SMTP_FROM.
FROM_EMAIL = os.getenv("SMTP_FROM", "kanatnuradil0905@gmail.com")


def send_reset_token_email(to_email: str, token: str, reset_url: str | None = None) -> None:
    """
    Send a secure password reset token to the given email.
    
    This uses SMTP with STARTTLS for secure email transmission.
    Make sure SMTP_USER/SMTP_PASSWORD are set in the environment.
    
    Args:
        to_email: Recipient email address
        token: Secure reset token (secrets.token_urlsafe(32))
        reset_url: Optional full URL to reset page (if None, user must enter token manually)
    
    Raises:
        ValueError: If SMTP credentials are not configured
        smtplib.SMTPException: If email sending fails
    """
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError(
            "SMTP credentials not configured. Set SMTP_USER and SMTP_PASSWORD environment variables."
        )

    msg = EmailMessage()
    msg["Subject"] = "Secure Messaging – Password Reset Request"
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email
    
    # Build reset link if URL provided, otherwise provide token
    if reset_url:
        reset_instruction = f"Click the following link to reset your password:\n\n{reset_url}\n\n"
        token_display = "The link above contains your reset token."
    else:
        reset_instruction = (
            "To reset your password, go to the reset password page and enter the following token:\n\n"
        )
        token_display = f"Reset Token: {token}"
    
    msg.set_content(
        f"""Hello,

You requested a password reset for your Secure Messaging account.

{reset_instruction}{token_display}

This token is valid for 1 hour. If you did not request this password reset, 
please ignore this email and your account will remain secure.

Best regards,
Secure Messaging
"""
    )

    # Send email with STARTTLS for secure transmission
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls(context=context)  # Secure connection with STARTTLS
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
    except smtplib.SMTPException as e:
        # Re-raise with more context
        raise ValueError(f"Failed to send password reset email: {str(e)}") from e


# Legacy function for backward compatibility (deprecated)
def send_reset_code_email(to_email: str, code: str) -> None:
    """
    DEPRECATED: Use send_reset_token_email instead.
    
    Send a 4-digit reset code to the given email.
    This function is kept for backward compatibility but should not be used in production.
    """
    if not SMTP_USER or not SMTP_PASSWORD:
        return  # Fail silently in demo mode
    
    msg = EmailMessage()
    msg["Subject"] = "Secure Messaging – Password Reset Code"
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email
    msg.set_content(
        f"""Hello,

You requested a password reset for your Secure Messaging account.

Your 4-digit reset code is: {code}

If you did not request this, you can ignore this email.

Best regards,
Secure Messaging
"""
    )

    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls(context=context)
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)

