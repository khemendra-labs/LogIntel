"""Systemd active unit state reader and inspector (M6.6).

Extracts running, activating, failed, and inactive systemd units:
- Safe unprivileged execution via systemctl list-units.
- Bounded execution with strict timeouts.
- Distinguishes OBSERVED states from UNKNOWN when systemctl is unavailable or restricted.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Dict, List, Optional

from logintel.systemd.models import (
    SystemdUnitInfo,
    UnitState,
)


class SystemdUnitTracker:
    """Queries and tracks systemd unit states."""

    def __init__(self, systemctl_bin: Optional[str] = None) -> None:
        self.systemctl_bin = systemctl_bin or shutil.which("systemctl")

    def check_availability(self) -> tuple[bool, Optional[str]]:
        """Verify whether systemctl is accessible and functional."""
        if not self.systemctl_bin:
            return False, "systemctl command not found in PATH"
        try:
            res = subprocess.run(
                [self.systemctl_bin, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2,
            )
            if res.returncode == 0:
                return True, None
            return False, f"systemctl exited with returncode {res.returncode}"
        except Exception as exc:
            return False, f"Error executing systemctl: {exc}"

    def list_units(self, unit_type: Optional[str] = None) -> List[SystemdUnitInfo]:
        """List active and loaded units from systemd."""
        if not self.systemctl_bin:
            return []

        cmd = [self.systemctl_bin, "list-units", "--all", "--no-legend", "--plain", "--no-pager"]
        if unit_type:
            cmd.extend(["--type", unit_type])

        try:
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            if res.returncode != 0:
                return []

            units: List[SystemdUnitInfo] = []
            for line in res.stdout.splitlines():
                parts = line.strip().split(None, 4)
                if len(parts) < 4:
                    continue

                unit_name = parts[0]
                load_state = parts[1]
                active_str = parts[2].lower()
                sub_state = parts[3]
                desc = parts[4] if len(parts) > 4 else None

                u_type = unit_name.rsplit(".", 1)[-1] if "." in unit_name else "unit"

                try:
                    active_state = UnitState(active_str)
                except ValueError:
                    active_state = UnitState.UNKNOWN

                units.append(
                    SystemdUnitInfo(
                        unit_name=unit_name,
                        unit_type=u_type,
                        description=desc,
                        load_state=load_state,
                        active_state=active_state,
                        sub_state=sub_state,
                        epistemic_status="OBSERVED",
                    )
                )
            return units
        except Exception:
            return []

    def get_unit_details(self, unit_name: str) -> Optional[SystemdUnitInfo]:
        """Retrieve granular properties of a specific unit via systemctl show."""
        if not self.systemctl_bin:
            return None

        cmd = [
            self.systemctl_bin,
            "show",
            unit_name,
            "--no-pager",
            "--property=Id,Description,LoadState,ActiveState,SubState,MainPID,ExecMainCode,ExecMainStatus,User",
        ]
        try:
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3,
            )
            if res.returncode != 0:
                return None

            props: Dict[str, str] = {}
            for line in res.stdout.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    props[k.strip()] = v.strip()

            if not props or props.get("LoadState") == "not-found":
                return None

            uid_str = props.get("MainPID")
            main_pid = int(uid_str) if uid_str and uid_str.isdigit() and int(uid_str) > 0 else None

            exit_code_str = props.get("ExecMainStatus")
            exit_code = int(exit_code_str) if exit_code_str and exit_code_str.isdigit() else None

            active_str = props.get("ActiveState", "unknown").lower()
            try:
                active_state = UnitState(active_str)
            except ValueError:
                active_state = UnitState.UNKNOWN

            u_type = unit_name.rsplit(".", 1)[-1] if "." in unit_name else "unit"

            return SystemdUnitInfo(
                unit_name=props.get("Id", unit_name),
                unit_type=u_type,
                description=props.get("Description"),
                load_state=props.get("LoadState", "loaded"),
                active_state=active_state,
                sub_state=props.get("SubState", "unknown"),
                main_pid=main_pid,
                exit_code=exit_code,
                user=props.get("User") or None,
                epistemic_status="OBSERVED",
            )
        except Exception:
            return None
