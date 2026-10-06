"""Linux Filesystem High-Value Target (HVT) integrity and state scanner (M6.5).

Scans sensitive persistence directories and configuration files:
- Inspects file metadata (inode, size, permissions, owner UID/GID, timestamps).
- Computes SHA-256 hash for regular files under the safe size limit (default 10 MB).
- Handles unprivileged permissions gracefully: records PERMISSION_RESTRICTED when content
  is unreadable (e.g. /etc/shadow) rather than failing.
- Defends against symlink loops and path traversal attacks.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
from typing import Dict, List, Optional

from logintel.filesystem.models import (
    DEFAULT_HVT_TARGETS,
    FileState,
    HVTTarget,
    TargetCategory,
)

DEFAULT_MAX_HASH_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_FILES_PER_SCAN = 2000
HASH_CHUNK_SIZE = 65536  # 64 KB


class FileIntegrityScanner:
    """Scans and extracts forensic integrity states across High-Value Targets."""

    def __init__(
        self,
        targets: Optional[List[HVTTarget]] = None,
        max_hash_size_bytes: int = DEFAULT_MAX_HASH_SIZE_BYTES,
    ) -> None:
        self.targets = targets if targets is not None else DEFAULT_HVT_TARGETS
        self.max_hash_size_bytes = max_hash_size_bytes

    def scan_path(self, target_path: str, category: TargetCategory) -> Optional[FileState]:
        """Scan a single file path and compute its forensic state."""
        try:
            p = Path(target_path)
            # Use lstat to examine the path without automatically following symlinks
            st = os.lstat(target_path)
        except (FileNotFoundError, OSError):
            return None

        is_symlink = stat.S_ISLNK(st.st_mode)
        is_dir = stat.S_ISDIR(st.st_mode)
        symlink_target: Optional[str] = None
        if is_symlink:
            try:
                symlink_target = os.readlink(target_path)
            except OSError:
                symlink_target = None

        mode_octal = oct(stat.S_IMODE(st.st_mode))
        sha256_hash: Optional[str] = None
        epistemic_status = "OBSERVED"

        if not is_dir and not is_symlink and stat.S_ISREG(st.st_mode):
            if st.st_size <= self.max_hash_size_bytes:
                try:
                    hasher = hashlib.sha256()
                    with open(target_path, "rb") as f:
                        while chunk := f.read(HASH_CHUNK_SIZE):
                            hasher.update(chunk)
                    sha256_hash = hasher.hexdigest()
                except PermissionError:
                    # File exists and metadata observed, but content unreadable (e.g. /etc/shadow)
                    epistemic_status = "PERMISSION_RESTRICTED"
                    sha256_hash = None
                except OSError:
                    epistemic_status = "UNKNOWN"
                    sha256_hash = None
            else:
                # File exceeds maximum hashing size
                epistemic_status = "SIZE_EXCEEDED"

        return FileState(
            path=str(p.resolve() if not is_symlink else p),
            category=category,
            exists=True,
            inode=st.st_ino,
            size_bytes=st.st_size,
            mode_octal=mode_octal,
            uid=st.st_uid,
            gid=st.st_gid,
            mtime=st.st_mtime,
            ctime=st.st_ctime,
            sha256_hash=sha256_hash,
            is_dir=is_dir,
            is_symlink=is_symlink,
            symlink_target=symlink_target,
            epistemic_status=epistemic_status,
        )

    def scan_all(self) -> Dict[str, FileState]:
        """Scan all configured targets and return path-to-FileState mapping."""
        results: Dict[str, FileState] = {}

        for target in self.targets:
            if len(results) >= MAX_FILES_PER_SCAN:
                break

            target_path = Path(target.path)
            if not target.is_directory:
                state = self.scan_path(str(target_path), target.category)
                if state:
                    results[state.path] = state
            else:
                # Target is a directory: inspect directory itself and its direct children
                dir_state = self.scan_path(str(target_path), target.category)
                if dir_state:
                    results[dir_state.path] = dir_state

                if target_path.is_dir():
                    try:
                        entries = os.listdir(target_path)
                    except (PermissionError, OSError):
                        continue

                    for entry_name in entries:
                        if len(results) >= MAX_FILES_PER_SCAN:
                            break
                        child_path = target_path / entry_name
                        state = self.scan_path(str(child_path), target.category)
                        if state:
                            results[state.path] = state

        return results
