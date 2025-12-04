"""FastAPI server exposing the secure messaging features via HTTP."""
from __future__ import annotations

import secrets
from pathlib import Path
from typing import Dict, Optional, List

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

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


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    email: str
    code: str
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


def get_current_session(authorization: Optional[str] = Header(default=None)) -> ActiveSession:
    if not authorization:
        raise _raise_unauthorized("Missing Authorization header")
    if not authorization.lower().startswith("bearer "):
        raise _raise_unauthorized("Authorization must be Bearer token")
    token = authorization.split(" ", 1)[1]
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


@app.post("/api/login", response_model=SessionToken)
async def login(payload: LoginRequest):
    try:
        session = state.auth.login(payload.username, payload.password)
    except ValueError as exc:
        raise _raise_unauthorized(str(exc)) from exc
    token = state.sessions.create(session)
    return SessionToken(token=token, username=session.username)


@app.post("/api/logout")
async def logout(
    current: ActiveSession = Depends(get_current_session),
    authorization: Optional[str] = Header(default=None),
):
    assert authorization is not None  # already validated
    token = authorization.split(" ", 1)[1]
    state.sessions.destroy(token)
    return {"status": "ok"}


@app.post("/api/forgot-password")
async def forgot_password(payload: ForgotPasswordRequest):
    try:
        code = state.auth.start_password_reset(payload.email)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    # In a real app you would email the code. Here we return it for demo purposes.
    return {"status": "ok", "code": code}


@app.post("/api/reset-password")
async def reset_password(payload: ResetPasswordRequest):
    try:
        state.auth.complete_password_reset(payload.email, payload.code, payload.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {"status": "ok"}


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


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request, exc):  # pragma: no cover - convenience
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


if FRONTEND_DIR.exists():
    # Mount after API routes so /api/* stays handled by FastAPI.
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run("secure_messaging.server:app", host="0.0.0.0", port=8000, reload=True)
