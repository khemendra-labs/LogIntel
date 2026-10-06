"""Unit tests for Network & Socket Models (Milestone M6.4)."""

from datetime import datetime, timezone
import pytest

from logintel.network.models import (
    SocketEntry,
    SocketProtocol,
    SocketSnapshot,
    SocketState,
    TCP_HEX_STATES,
)


def test_socket_entry_properties():
    """Verify socket key, listening, established, loopback, and outbound properties."""
    entry = SocketEntry(
        protocol=SocketProtocol.TCP,
        local_address="192.168.1.50",
        local_port=54321,
        remote_address="93.184.216.34",
        remote_port=443,
        state=SocketState.ESTABLISHED,
        inode=123456,
        uid=1000,
        pid=9876,
        process_name="curl",
        epistemic_status="OBSERVED",
    )

    assert entry.is_established
    assert not entry.is_listening
    assert not entry.is_loopback
    assert entry.is_outbound
    assert entry.socket_key == "tcp:192.168.1.50:54321->93.184.216.34:443:123456"


def test_socket_entry_listener():
    """Verify listening socket properties."""
    entry = SocketEntry(
        protocol=SocketProtocol.TCP,
        local_address="0.0.0.0",
        local_port=8080,
        remote_address="0.0.0.0",
        remote_port=0,
        state=SocketState.LISTEN,
        inode=5555,
        uid=0,
        pid=None,
        epistemic_status="UNKNOWN",
    )

    assert entry.is_listening
    assert not entry.is_established
    assert not entry.is_outbound


def test_socket_entry_loopback():
    """Verify loopback connection properties."""
    entry = SocketEntry(
        protocol=SocketProtocol.TCP,
        local_address="127.0.0.1",
        local_port=8000,
        remote_address="127.0.0.1",
        remote_port=55122,
        state=SocketState.ESTABLISHED,
        inode=9999,
        uid=1000,
    )

    assert entry.is_loopback
    assert not entry.is_outbound


def test_socket_snapshot_filtering():
    """Verify snapshot filtering for listening, established, and outbound entries."""
    e_listen = SocketEntry(
        protocol=SocketProtocol.TCP,
        local_address="0.0.0.0",
        local_port=22,
        remote_address="0.0.0.0",
        remote_port=0,
        state=SocketState.LISTEN,
        inode=100,
        uid=0,
    )
    e_estab = SocketEntry(
        protocol=SocketProtocol.TCP,
        local_address="10.0.0.5",
        local_port=44122,
        remote_address="1.1.1.1",
        remote_port=53,
        state=SocketState.ESTABLISHED,
        inode=101,
        uid=1000,
    )
    e_time_wait = SocketEntry(
        protocol=SocketProtocol.TCP,
        local_address="10.0.0.5",
        local_port=44123,
        remote_address="1.1.1.1",
        remote_port=53,
        state=SocketState.TIME_WAIT,
        inode=102,
        uid=1000,
    )

    snapshot = SocketSnapshot(
        host="test-host",
        entries=[e_listen, e_estab, e_time_wait],
    )

    assert snapshot.total_count == 3
    assert len(snapshot.listening_entries) == 1
    assert snapshot.listening_entries[0].local_port == 22
    assert len(snapshot.established_entries) == 1
    assert snapshot.established_entries[0].remote_address == "1.1.1.1"
    assert len(snapshot.outbound_entries) == 1


def test_tcp_hex_states_mapping():
    """Verify mapping of Linux kernel hex states to SocketState enum."""
    assert TCP_HEX_STATES["01"] == SocketState.ESTABLISHED
    assert TCP_HEX_STATES["0A"] == SocketState.LISTEN
    assert TCP_HEX_STATES["06"] == SocketState.TIME_WAIT
    assert TCP_HEX_STATES["07"] == SocketState.CLOSE
