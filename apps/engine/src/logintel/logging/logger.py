"""Structured logging setup for LogIntel with file rotation and console output."""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

_initialized = False


def setup_logging(
    log_file: Optional[Path] = None,
    level: str = "INFO",
    max_bytes: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5,
) -> logging.Logger:
    """Configure structured logging for LogIntel."""
    global _initialized
    logger = logging.getLogger("logintel")
    
    if _initialized:
        return logger
        
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s.%(module)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Rotating file handler
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            str(log_file),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
    _initialized = True
    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the logintel namespace."""
    return logging.getLogger(f"logintel.{name}")
