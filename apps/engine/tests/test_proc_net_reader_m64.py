"""Unit tests for ProcNetReader and SocketProcessResolver (Milestone M6.4)."""

import os
from pathlib import Path
import tempfile
import pytest

from logintel.network.models import SocketProtocol, SocketState
from logintel.network.proc_reader import (
    ProcNetReader,
    decode_hex_ipv4,
    decode_hex_ipv6,
    decode_hex_port,
    parse_ip_port,
)
from logintel.network.resolver import SocketProcessResolver


def test_decode_hex_ipv4():
    """Verify little-endian IPv4 hexadecimal decoding."""
    assert decode_hex_ipv4("0100007F") == "127.0.0.1"
    assert decode_hex_ipv4("00000000") == "0.0.0.0"
    # 192.168.1.100 -> C0 A8 01 64 in memory -> 6401A8C0
    assert decode_hex_ipv4("6401A8C0") == "192.168.1.100"
    # 8.8.8.8 -> 08 08 08 08 -> 08080808
    assert decode_hex_ipv4("08080808") == "8.8.8.8"


def test_decode_hex_ipv6():
    """Verify RFC 5952 IPv6 hexadecimal decoding."""
    assert decode_hex_ipv6("00000000000000000000000001000000") == "::1"
    assert decode_hex_ipv6("00000000000000000000000000000000") == "::"


def test_decode_hex_port():
    """Verify hexadecimal port decoding."""
    assert decode_hex_port("0016") == 22
    assert decode_hex_port("0050") == 80
    assert decode_hex_port("01BB") == 443
    assert decode_hex_port("1F90") == 8080


def test_parse_proc_net_tcp_synthetic():
    """Verify parsing of synthetic /proc/net/tcp format."""
    sample_tcp = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 6401A8C0:D431 22D85CE9:01BB 01 00000000:00000000 02:00000215 00000000  1000        0 54321 3 0000000000000000 21 4 21 10 90
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tcp_file = Path(tmpdir) / "tcp"
        tcp_file.write_text(sample_tcp)

        reader = ProcNetReader(base_path=tmpdir)
        entries = reader.read_socket_table(SocketProtocol.TCP)

        assert len(entries) == 2

        # Listener entry
        e1 = entries[0]
        assert e1.local_address == "0.0.0.0"
        assert e1.local_port == 22
        assert e1.state == SocketState.LISTEN
        assert e1.inode == 12345
        assert e1.uid == 0
        assert e1.is_listening

        # Established connection entry
        e2 = entries[1]
        assert e2.local_address == "192.168.1.100"
        assert e2.local_port == 54321
        assert e2.remote_port == 443
        assert e2.state == SocketState.ESTABLISHED
        assert e2.inode == 54321
        assert e2.uid == 1000
        assert e2.is_established
        assert e2.is_outbound


def test_socket_process_resolver_synthetic():
    """Verify SocketProcessResolver inode lookup and process information extraction."""
    with tempfile.TemporaryDirectory() as tmpdir:
        proc_root = Path(tmpdir)
        pid_dir = proc_root / "4321"
        fd_dir = pid_dir / "fd"
        fd_dir.mkdir(parents=True)

        (pid_dir / "comm").write_text("python_srv\n")
        (pid_dir / "cmdline").write_bytes(b"python3\x00-m\x00http.server\x008000\x00")
        (pid_dir / "status").write_text("Name:\tpython_srv\nUid:\t1001\t1001\t1001\t1001\n")

        # Symlink fd 3 -> socket:[98765]
        target_link = fd_dir / "3"
        os.symlink("socket:[98765]", target_link)

        resolver = SocketProcessResolver(proc_path=tmpdir)
        cache = resolver.refresh_cache(force=True)

        assert 98765 in cache
        info = cache[98765]
        assert info.pid == 4321
        assert info.name == "python_srv"
        assert "http.server" in (info.command_line or "")
        assert info.user == "uid:1001"
