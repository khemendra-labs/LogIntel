"""Authentication and authorization boundary for LogIntel local IPC/API."""

from __future__ import annotations

import os
import secrets
from typing import Optional
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from logintel.config import settings
from logintel.logging import get_logger

logger = get_logger("api.auth")

_ACTIVE_TOKEN: Optional[str] = None
bearer_scheme = HTTPBearer(auto_error=False)


def init_engine_token() -> str:
    """Generate and persist a cryptographically secure random token with 0600 permissions."""
    global _ACTIVE_TOKEN
    token = secrets.token_hex(32)
    token_file = settings.token_path
    token_file.parent.mkdir(parents=True, exist_ok=True)

    # Write securely with 0600 (owner read/write only)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = 0o600
    fd = os.open(str(token_file), flags, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(token)
    except Exception:
        os.close(fd)
        raise

    _ACTIVE_TOKEN = token
    logger.info("Initialized local IPC engine authentication token at %s (mode 0600)", token_file)
    return token


def get_current_token() -> str:
    """Retrieve the active engine token, loading from disk if not cached in memory."""
    global _ACTIVE_TOKEN
    if _ACTIVE_TOKEN:
        return _ACTIVE_TOKEN

    token_file = settings.token_path
    if token_file.exists():
        try:
            token = token_file.read_text(encoding="utf-8").strip()
            if token:
                _ACTIVE_TOKEN = token
                return token
        except Exception as exc:
            logger.error("Failed reading engine token file: %s", exc)

    return init_engine_token()


def verify_engine_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> str:
    """Validate Bearer token in constant time. Reject missing or mismatching tokens."""
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Missing Authorization header with Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    expected_token = get_current_token()
    if not secrets.compare_digest(credentials.credentials.strip(), expected_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid engine token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials
