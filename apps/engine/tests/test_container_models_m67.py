"""Unit tests for Container and Namespace Telemetry Models (Milestone M6.7)."""

import pytest
from logintel.containers.models import (
    ContainerInfo,
    ContainerLifecycleEvent,
    ContainerRuntime,
    ContainerState,
    NamespaceInfo,
    NamespaceType,
    ProcessNamespaceProfile,
)


def test_container_info_initialization():
    """Verify ContainerInfo model attributes and defaults."""
    c = ContainerInfo(
        container_id="a1b2c3d4e5f6",
        container_name="web-ingress",
        image="nginx:alpine",
        runtime=ContainerRuntime.DOCKER,
        state=ContainerState.RUNNING,
        pids=[1042, 1043],
        privileged=False,
        epistemic_status="OBSERVED",
    )
    assert c.container_id == "a1b2c3d4e5f6"
    assert c.container_name == "web-ingress"
    assert c.runtime == ContainerRuntime.DOCKER
    assert c.state == ContainerState.RUNNING
    assert len(c.pids) == 2
    assert c.epistemic_status == "OBSERVED"


def test_process_namespace_profile_initialization():
    """Verify ProcessNamespaceProfile attributes."""
    prof = ProcessNamespaceProfile(
        pid=5555,
        is_isolated=True,
        isolated_namespaces=[NamespaceType.MNT, NamespaceType.NET, NamespaceType.PID],
        container_id="c9d8e7f6a5b4",
        container_runtime=ContainerRuntime.CONTAINERD,
        cgroup_path="/system.slice/containerd.service",
        epistemic_status="OBSERVED",
    )
    assert prof.pid == 5555
    assert prof.is_isolated is True
    assert len(prof.isolated_namespaces) == 3
    assert prof.container_id == "c9d8e7f6a5b4"
    assert prof.container_runtime == ContainerRuntime.CONTAINERD


def test_container_lifecycle_event_model():
    """Verify ContainerLifecycleEvent captures lifecycle properties."""
    ev = ContainerLifecycleEvent(
        container_id="123456789abc",
        container_name="database",
        action="start",
        image="postgres:16",
        privileged=True,
        raw_message="Container started with privileged mode",
    )
    assert ev.action == "start"
    assert ev.privileged is True
    assert ev.image == "postgres:16"
