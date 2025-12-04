"""FastAPI server exposing the secure messaging features via HTTP."""
from __future__ import annotations

import secrets
from pathlib import Path
from typing import Dict, Optional, List

from fastapi import Depends, FastAPI, Header, HTTPException, status, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime, timedelta

from .app import ActiveSession, AuthService, MessagingService
from .db import Database

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


def _raise_unauthorized(message: str = "Unauthorized") -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=message)


class RegisterRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str
    totp_token: Optional[str] = None


class TOTPSetupResponse(BaseModel):
    secret: str
    qr_code: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class MessageRequest(BaseModel):
    recipient: str
    message: str


class GroupMessageRequest(BaseModel):
    recipients: List[str]
    message: str


class SessionToken(BaseModel):
    token: str
    username: str
    requires_totp: bool = False


class SessionManager:
    """In-memory session tracking for demo purposes."""

    def __init__(self):
        self._sessions: Dict[str, ActiveSession] = {}

    def create(self, session: ActiveSession) -> str:
        token = secrets.token_urlsafe(32)
        self._sessions[token] = session
        return token

    def destroy(self, token: str) -> None:
        self._sessions.pop(token, None)

    def get(self, token: str) -> Optional[ActiveSession]:
        return self._sessions.get(token)


class ApplicationState:
    def __init__(self):
        self.db = Database()
        self.auth = AuthService(database=self.db)
        self.messaging = MessagingService(database=self.db)
        self.sessions = SessionManager()


state = ApplicationState()
app = FastAPI(title="Secure Messaging API", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_current_session(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> ActiveSession:
    """
    Get current session from either Bearer token (backward compat) or HttpOnly cookie.
    
    Prefers cookie-based authentication for security (HttpOnly prevents XSS).
    Falls back to Bearer token for API clients.
    """
    # Try cookie first (more secure)
    token = request.cookies.get("session_token")
    
    # Fallback to Bearer token for backward compatibility
    if not token and authorization:
        if authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1]
    
    if not token:
        raise _raise_unauthorized("Missing authentication")
    
    session = state.sessions.get(token)
    if not session:
        raise _raise_unauthorized("Invalid or expired session")
    return session


@app.post("/api/register")
async def register(payload: RegisterRequest):
    try:
        state.auth.register(payload.username, payload.password, payload.email)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {"status": "ok"}


@app.post("/api/login")
async def login(payload: LoginRequest, response: Response):
    """
    Login endpoint with TOTP support.
    
    Returns session token in HttpOnly cookie and JSON response.
    If TOTP is enabled, returns requires_totp=true and user must submit TOTP token.
    """
    try:
        session, requires_totp = state.auth.login(
            payload.username, payload.password, payload.totp_token
        )
        
        if requires_totp:
            # Password correct but TOTP required
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"requires_totp": True, "message": "TOTP token required"}
            )
        
        # Login successful - create session token
        token = state.sessions.create(session)
        
        # Set HttpOnly, Secure cookie (in production, set Secure=True for HTTPS only)
        response.set_cookie(
            key="session_token",
            value=token,
            httponly=True,
            secure=False,  # Set to True in production with HTTPS
            samesite="lax",
            max_age=86400,  # 24 hours
        )
        
        return {
            "status": "ok",
            "username": session.username,
            "token": token,  # Also return in JSON for backward compat (not recommended)
        }
    except ValueError as exc:
        raise _raise_unauthorized(str(exc)) from exc


@app.post("/api/logout")
async def logout(
    request: Request,
    response: Response,
    current: ActiveSession = Depends(get_current_session),
):
    """Logout and clear session cookie."""
    token = request.cookies.get("session_token") or (
        request.headers.get("authorization", "").split(" ", 1)[1] if "bearer " in request.headers.get("authorization", "").lower() else None
    )
    if token:
        state.sessions.destroy(token)
    # Clear cookie
    response.delete_cookie(key="session_token", httponly=True, samesite="lax")
    return {"status": "ok"}


@app.post("/api/forgot-password")
async def forgot_password(payload: ForgotPasswordRequest):
    """
    Initiate password reset with secure token (1 hour expiration).
    
    The reset token is sent to the user's registered email address via SMTP.
    The token is never returned in the API response for security.
    
    Security features:
    - Returns generic success message regardless of whether email exists (prevents email enumeration)
    - Token is only sent via secure email (STARTTLS)
    - Token has 1-hour expiration stored in database
    
    Returns:
        Success message (even if email doesn't exist, for security)
    
    Raises:
        HTTPException: If SMTP configuration is missing or email sending fails
    """
    try:
        state.auth.start_password_reset(payload.email)
    except ValueError as exc:
        # Check if this is an SMTP configuration/sending error
        error_msg = str(exc)
        if "SMTP" in error_msg or "email" in error_msg.lower() or "Failed to send" in error_msg:
            # This is an actual SMTP failure - return error
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send reset email. Please check SMTP configuration or try again later."
            ) from exc
        # For any other ValueError (shouldn't happen with current implementation), return generic success
    
    # Always return generic success message (security: prevent email enumeration)
    # This message is shown whether email exists or not
    return {
        "status": "ok",
        "message": "If this email is registered, a password reset token has been sent. Please check your email."
    }


@app.post("/api/reset-password")
async def reset_password(payload: ResetPasswordRequest):
    """
    Complete password reset using secure token.
    
    Validates token expiration and password complexity.
    """
    try:
        state.auth.complete_password_reset(payload.token, payload.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {"status": "ok", "message": "Password reset successful"}


@app.get("/api/users")
async def list_users(current: ActiveSession = Depends(get_current_session)):
    users = state.auth.list_users()
    return [user["username"] for user in users]


@app.get("/api/messages")
async def inbox(current: ActiveSession = Depends(get_current_session)):
    return state.messaging.inbox(current)


@app.post("/api/messages")
async def send_message(payload: MessageRequest, current: ActiveSession = Depends(get_current_session)):
    try:
        envelope = state.messaging.send_message(current, payload.recipient, payload.message)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return envelope


@app.post("/api/group-messages")
async def send_group_message(payload: GroupMessageRequest, current: ActiveSession = Depends(get_current_session)):
    if not payload.recipients:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Recipients required")
    sent = 0
    for recipient in payload.recipients:
        try:
            state.messaging.send_message(current, recipient, payload.message)
            sent += 1
        except ValueError:
            # Skip invalid recipients; in a real app you would report which failed.
            continue
    if sent == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No valid recipients")
    return {"status": "ok", "sent": sent}


@app.get("/api/health")
async def healthcheck():
    return {"status": "ok"}


@app.post("/api/totp/setup")
async def setup_totp(
    current: ActiveSession = Depends(get_current_session),
):
    """
    Generate TOTP secret and QR code for current user.
    
    User must scan QR code with authenticator app (Google Authenticator, Authy, etc.)
    """
    try:
        secret, qr_code = state.auth.setup_totp(current.username)
        return {
            "status": "ok",
            "secret": secret,
            "qr_code": qr_code,
            "message": "Scan QR code with your authenticator app"
        }
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/api/totp/disable")
async def disable_totp(
    current: ActiveSession = Depends(get_current_session),
):
    """Disable TOTP for current user."""
    try:
        state.auth.disable_totp(current.username)
        return {"status": "ok", "message": "TOTP disabled"}
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request, exc):  # pragma: no cover - convenience
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


if FRONTEND_DIR.exists():
    # Mount after API routes so /api/* stays handled by FastAPI.
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run("secure_messaging.server:app", host="0.0.0.0", port=8000, reload=True)
