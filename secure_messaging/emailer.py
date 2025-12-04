"""Email utilities for sending password reset codes."""
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


def send_reset_code_email(to_email: str, code: str) -> None:
    """
    Send a 4-digit reset code to the given email.

    This uses plain SMTP with STARTTLS. Make sure SMTP_USER/SMTP_PASSWORD are
    set in the environment before running the server.
    """
    if not SMTP_USER or not SMTP_PASSWORD:
        # Fail silently in demo mode so the rest of the flow still works.
        # You can change this to raise an exception if you want hard failures.
        return

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


