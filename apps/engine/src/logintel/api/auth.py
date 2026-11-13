"""Authentication and authorization boundary for LogIntel local IPC/API."""

from __future__ import annotations

import os
from pathlib import Path
import secrets
from typing import Optional
from fastapi import Depends, Header, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from logintel.config import settings
from logintel.logging import get_logger

logger = get_logger("api.auth")

_ACTIVE_TOKEN: Optional[str] = None
bearer_scheme = HTTPBearer(auto_error=False)


def init_engine_token() -> str:
    """Generate and persist a cryptographically secure random token for local IPC."""
    global _ACTIVE_TOKEN
    token = secrets.token_hex(32)
    token_file = settings.token_path
    token_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(token_file.parent), 0o755)
    except Exception:
        pass

    # Write securely with 0644 (owner rw, group/world read) so local desktop clients can authenticate
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = 0o644
    fd = os.open(str(token_file), flags, mode)
    with open(fd, "w", encoding="utf-8", closefd=True) as f:
        f.write(token)

    try:
        os.chmod(str(token_file), 0o644)
    except Exception:
        pass

    try:
        import grp
        adm_gid = grp.getgrnam("adm").gr_gid
        os.chown(str(token_file), -1, adm_gid)
    except Exception:
        pass

    # Mirror token to runtime directories for rapid IPC resolution
    for target in [Path("/run/logintel/engine.token"), Path("/etc/logintel/engine.token")]:
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(token, encoding="utf-8")
            os.chmod(str(target), 0o644)
        except Exception:
            pass

    _ACTIVE_TOKEN = token
    logger.info("Initialized local IPC engine authentication token at %s", token_file)
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


def verify_agent_token(
    agent_token: Optional[str] = Header(default=None, alias="X-LogIntel-Agent-Token"),
) -> str:
    """Authorize an explicitly enabled remote collector batch.

    This deliberately uses a separate token from desktop IPC so an agent
    compromise cannot impersonate the local operator API.
    """
    configured = settings.remote_ingest.agent_token
    if not settings.remote_ingest.enabled or not configured:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remote ingestion is disabled.")
    if not agent_token or not secrets.compare_digest(agent_token.strip(), configured):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized remote collector.",
            headers={"WWW-Authenticate": "AgentToken"},
        )
    return agent_token
