"""Linux kernel namespace and cgroup inspector (M6.7).

Inspects /proc/<pid>/ns and /proc/<pid>/cgroup:
- Establishes host baseline namespaces from PID 1 or self.
- Detects process namespace divergence (mnt, net, pid, ipc, uts, user, cgroup).
- Extracts container IDs and runtimes from cgroups (Docker, containerd, Podman, K8s).
- Correlates host processes to container instances unprivileged.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Set

from logintel.containers.models import (
    ContainerInfo,
    ContainerRuntime,
    ContainerState,
    NamespaceInfo,
    NamespaceType,
    ProcessNamespaceProfile,
)

DOCKER_CGROUP_RE = re.compile(r"/docker[/-]([a-f0-9]{12,64})", re.IGNORECASE)
CONTAINERD_CGROUP_RE = re.compile(r"/containerd/.*?([a-f0-9]{12,64})", re.IGNORECASE)
LIBPOD_CGROUP_RE = re.compile(r"/libpod-([a-f0-9]{12,64})", re.IGNORECASE)
KUBEPODS_CGROUP_RE = re.compile(r"/kubepods/.*?([a-f0-9]{12,64})", re.IGNORECASE)
NSPAWN_CGROUP_RE = re.compile(r"/machine-([a-zA-Z0-9_\-]+)\.scope", re.IGNORECASE)
NS_INODE_RE = re.compile(r"\[(\d+)\]")


class NamespaceInspector:
    """Inspects Linux kernel namespaces and cgroups via procfs."""

    def __init__(self, proc_root: str = "/proc") -> None:
        self.proc_root = proc_root
        self._host_namespaces: Dict[NamespaceType, int] = {}
        self._init_host_baseline()

    def _read_ns_inode(self, path: str) -> Optional[int]:
        """Read namespace inode number from procfs symlink."""
        try:
            target = os.readlink(path)
            m = NS_INODE_RE.search(target)
            if m:
                return int(m.group(1))
        except (OSError, ValueError):
            pass
        return None

    def _init_host_baseline(self) -> None:
        """Establish host baseline namespace inodes from PID 1 or current process."""
        baseline_pids = [1, os.getpid()]
        for pid in baseline_pids:
            ns_dir = os.path.join(self.proc_root, str(pid), "ns")
            if not os.path.isdir(ns_dir):
                continue

            for ns_type in NamespaceType:
                ns_file = os.path.join(ns_dir, ns_type.value)
                inode = self._read_ns_inode(ns_file)
                if inode is not None:
                    self._host_namespaces[ns_type] = inode

            if self._host_namespaces:
                break

    def get_host_namespaces(self) -> Dict[NamespaceType, int]:
        """Return the observed host baseline namespace inodes."""
        return dict(self._host_namespaces)

    def inspect_process(self, pid: int) -> Optional[ProcessNamespaceProfile]:
        """Profile namespace isolation and container binding for a specific process."""
        pid_dir = os.path.join(self.proc_root, str(pid))
        if not os.path.isdir(pid_dir):
            return None

        ns_dir = os.path.join(pid_dir, "ns")
        cgroup_file = os.path.join(pid_dir, "cgroup")

        isolated_namespaces: List[NamespaceType] = []
        is_isolated = False

        if os.path.isdir(ns_dir):
            for ns_type in NamespaceType:
                target_file = os.path.join(ns_dir, ns_type.value)
                target_inode = self._read_ns_inode(target_file)
                host_inode = self._host_namespaces.get(ns_type)

                if target_inode is not None and host_inode is not None:
                    if target_inode != host_inode:
                        isolated_namespaces.append(ns_type)
                        # Typical container isolation boundaries
                        if ns_type in (NamespaceType.MNT, NamespaceType.PID, NamespaceType.NET, NamespaceType.IPC):
                            is_isolated = True

        cgroup_content = ""
        container_id: Optional[str] = None
        container_runtime = ContainerRuntime.HOST_NATIVE
        epistemic_status = "OBSERVED"

        if os.path.exists(cgroup_file):
            try:
                with open(cgroup_file, "r", encoding="utf-8", errors="replace") as f:
                    cgroup_content = f.read().strip()
            except OSError:
                pass

        if cgroup_content:
            m = DOCKER_CGROUP_RE.search(cgroup_content)
            if m:
                container_id = m.group(1)[:12]
                container_runtime = ContainerRuntime.DOCKER
                is_isolated = True
            else:
                m = CONTAINERD_CGROUP_RE.search(cgroup_content)
                if m:
                    container_id = m.group(1)[:12]
                    container_runtime = ContainerRuntime.CONTAINERD
                    is_isolated = True
                else:
                    m = LIBPOD_CGROUP_RE.search(cgroup_content)
                    if m:
                        container_id = m.group(1)[:12]
                        container_runtime = ContainerRuntime.PODMAN
                        is_isolated = True
                    else:
                        m = KUBEPODS_CGROUP_RE.search(cgroup_content)
                        if m:
                            container_id = m.group(1)[:12]
                            container_runtime = ContainerRuntime.CRIO
                            is_isolated = True
                        else:
                            m = NSPAWN_CGROUP_RE.search(cgroup_content)
                            if m:
                                container_id = m.group(1)
                                container_runtime = ContainerRuntime.SYSTEMD_NSPAWN
                                is_isolated = True

        if is_isolated and not container_id:
            container_runtime = ContainerRuntime.UNKNOWN
            epistemic_status = "INFERRED"
        elif not is_isolated:
            container_runtime = ContainerRuntime.HOST_NATIVE
            epistemic_status = "OBSERVED"

        return ProcessNamespaceProfile(
            pid=pid,
            is_isolated=is_isolated,
            isolated_namespaces=isolated_namespaces,
            container_id=container_id,
            container_runtime=container_runtime,
            cgroup_path=cgroup_content[:200],
            epistemic_status=epistemic_status,
        )

    def discover_containers(self) -> List[ContainerInfo]:
        """Scan procfs and group processes by discovered container context."""
        containers_by_id: Dict[str, ContainerInfo] = {}

        try:
            entries = os.listdir(self.proc_root)
        except OSError:
            return []

        for entry in entries:
            if not entry.isdigit():
                continue
            pid = int(entry)
            profile = self.inspect_process(pid)
            if not profile or not profile.container_id:
                continue

            cid = profile.container_id
            if cid not in containers_by_id:
                containers_by_id[cid] = ContainerInfo(
                    container_id=cid,
                    container_name=f"container-{cid[:8]}",
                    image="unknown",
                    runtime=profile.container_runtime,
                    state=ContainerState.RUNNING,
                    pids=[pid],
                    epistemic_status=profile.epistemic_status,
                )
            else:
                if pid not in containers_by_id[cid].pids:
                    containers_by_id[cid].pids.append(pid)

        return list(containers_by_id.values())
