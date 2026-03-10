from __future__ import annotations
"""Authentication module — signup, signin, session management."""

import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi import Cookie, HTTPException, Request

from app.db import get_conn


def _init_auth_tables() -> None:
    """Create auth tables if they don't exist."""
    from app.settings import settings
    from pathlib import Path

    db_path = Path(settings.database_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(settings.database_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('reviewer', 'parent')),
                display_name TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )


def _hash_password(password: str, salt: str) -> str:
    """Hash password with PBKDF2-HMAC-SHA256."""
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=200_000,
    )
    return dk.hex()


def signup(username: str, password: str, role: str, display_name: str = "") -> dict:
    """Register a new user. Returns user info."""
    if role not in ("reviewer", "parent"):
        raise ValueError("role must be 'reviewer' or 'parent'")
    if len(username) < 3 or len(username) > 40:
        raise ValueError("username must be 3-40 characters")
    if len(password) < 4:
        raise ValueError("password must be at least 4 characters")

    salt = secrets.token_hex(16)
    password_hash = _hash_password(password, salt)

    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, salt, role, display_name) VALUES (?, ?, ?, ?, ?)",
                (username.strip().lower(), password_hash, salt, role, display_name.strip() or username),
            )
            row = conn.execute(
                "SELECT id, username, role, display_name FROM users WHERE username = ?",
                (username.strip().lower(),),
            ).fetchone()
    except sqlite3.IntegrityError:
        raise ValueError("username already taken")

    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "display_name": row["display_name"],
    }


def signin(username: str, password: str) -> dict:
    """Authenticate user and return session token."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, salt, role, display_name FROM users WHERE username = ?",
            (username.strip().lower(),),
        ).fetchone()

    if not row:
        raise ValueError("invalid credentials")

    if _hash_password(password, row["salt"]) != row["password_hash"]:
        raise ValueError("invalid credentials")

    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(days=7)

    with get_conn() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
            (token, row["id"], expires.isoformat()),
        )

    return {
        "token": token,
        "user": {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
            "display_name": row["display_name"],
        },
    }


def get_session_user(token: str) -> dict | None:
    """Validate a session token and return user info or None."""
    if not token:
        return None

    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT s.token, s.expires_at, u.id, u.username, u.role, u.display_name
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = ?
            """,
            (token,),
        ).fetchone()

    if not row:
        return None

    # Check expiry
    try:
        expires = datetime.fromisoformat(row["expires_at"])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires:
            return None
    except (ValueError, TypeError):
        return None

    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "display_name": row["display_name"],
    }


def signout(token: str) -> None:
    """Delete a session token."""
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


def require_auth(request: Request, required_role: str | None = None) -> dict:
    """Extract and validate auth from request. Raises HTTPException if invalid."""
    token = None

    # Check Authorization header first
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]

    # Fall back to cookie
    if not token:
        token = request.cookies.get("guardian_token")

    if not token:
        raise HTTPException(status_code=401, detail="not_authenticated")

    user = get_session_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="session_expired")

    if required_role and user["role"] != required_role:
        raise HTTPException(status_code=403, detail="forbidden_role")

    return user
