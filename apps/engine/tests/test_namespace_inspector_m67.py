"""Unit tests for NamespaceInspector (Milestone M6.7)."""

import os
import pytest
from logintel.containers.models import ContainerRuntime, NamespaceType
from logintel.containers.namespace_inspector import NamespaceInspector


def test_namespace_inspector_host_baseline():
    """Verify NamespaceInspector reads host namespaces on live system."""
    insp = NamespaceInspector()
    host_ns = insp.get_host_namespaces()
    assert isinstance(host_ns, dict)
    assert len(host_ns) > 0
    assert NamespaceType.MNT in host_ns or NamespaceType.NET in host_ns


def test_namespace_inspector_self_process():
    """Verify inspecting the current python process identifies host native profile."""
    insp = NamespaceInspector()
    profile = insp.inspect_process(os.getpid())
    assert profile is not None
    assert profile.pid == os.getpid()
    assert profile.container_runtime == ContainerRuntime.HOST_NATIVE
    assert profile.is_isolated is False
    assert profile.epistemic_status == "OBSERVED"


def test_namespace_inspector_missing_pid():
    """Verify non-existent PID returns None cleanly."""
    insp = NamespaceInspector()
    assert insp.inspect_process(999999999) is None


def test_namespace_inspector_synthetic_cgroup_parsing(tmp_path):
    """Verify parsing synthetic cgroup formats across container runtimes."""
    proc_root = tmp_path / "proc"
    proc_root.mkdir()

    # 1. Docker container
    docker_pid = proc_root / "101"
    docker_pid.mkdir()
    (docker_pid / "ns").mkdir()
    (docker_pid / "cgroup").write_text("0::/system.slice/docker-1234567890abcdef1234.scope\n")

    # 2. Podman container
    podman_pid = proc_root / "102"
    podman_pid.mkdir()
    (podman_pid / "ns").mkdir()
    (podman_pid / "cgroup").write_text("0::/user.slice/libpod-abcdef1234567890abcdef.scope\n")

    # 3. K8s / containerd
    k8s_pid = proc_root / "103"
    k8s_pid.mkdir()
    (k8s_pid / "ns").mkdir()
    (k8s_pid / "cgroup").write_text("0::/kubepods/burstable/pod123/fedcba0987654321fedcba\n")

    insp = NamespaceInspector(proc_root=str(proc_root))

    p101 = insp.inspect_process(101)
    assert p101 is not None
    assert p101.container_runtime == ContainerRuntime.DOCKER
    assert p101.container_id == "1234567890ab"
    assert p101.is_isolated is True

    p102 = insp.inspect_process(102)
    assert p102 is not None
    assert p102.container_runtime == ContainerRuntime.PODMAN
    assert p102.container_id == "abcdef123456"

    p103 = insp.inspect_process(103)
    assert p103 is not None
    assert p103.container_runtime == ContainerRuntime.CRIO
    assert p103.container_id == "fedcba098765"
