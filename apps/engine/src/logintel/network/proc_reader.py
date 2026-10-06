"""Linux kernel procfs network reader for /proc/net/tcp, tcp6, udp, udp6 (M6.4).

Decodes raw kernel socket tables without root privileges:
- Decodes little-endian IPv4 and IPv6 hex addresses to standard IP notation.
- Decodes 16-bit hex port numbers to integers.
- Decodes TCP connection states (LISTEN, ESTABLISHED, etc.).
- Extracts socket inode, UID, rx_queue, and tx_queue.
"""

from __future__ import annotations

import os
from pathlib import Path
import socket
import struct
from typing import List, Optional, Tuple

from logintel.network.models import (
    SocketEntry,
    SocketProtocol,
    SocketState,
    TCP_HEX_STATES,
)

MAX_SOCKETS_PER_READ = 5000


def decode_hex_ipv4(hex_addr: str) -> str:
    """Decode an 8-character little-endian hexadecimal IPv4 address.
    
    Example: '0100007F' -> '127.0.0.1'
    """
    if len(hex_addr) != 8:
        return "0.0.0.0"
    try:
        ip_int = int(hex_addr, 16)
        return socket.inet_ntoa(struct.pack("<I", ip_int))
    except Exception:
        return "0.0.0.0"


def decode_hex_ipv6(hex_addr: str) -> str:
    """Decode a 32-character hexadecimal IPv6 address from /proc/net/tcp6.
    
    Each 8-character chunk represents a 32-bit dword stored in little-endian order.
    Example: '00000000000000000000000001000000' -> '::1'
    """
    if len(hex_addr) != 32:
        return "::"
    try:
        dwords = [int(hex_addr[i : i + 8], 16) for i in range(0, 32, 8)]
        packed = struct.pack("<IIII", *dwords)
        return socket.inet_ntop(socket.AF_INET6, packed)
    except Exception:
        return "::"


def decode_hex_port(hex_port: str) -> int:
    """Decode a 4-character hexadecimal port number to an integer.
    
    Example: '0050' -> 80, '01BB' -> 443
    """
    try:
        return int(hex_port, 16)
    except Exception:
        return 0


def parse_ip_port(endpoint_str: str, is_ipv6: bool = False) -> Tuple[str, int]:
    """Parse an address:port string from /proc/net tables."""
    parts = endpoint_str.strip().split(":")
    if len(parts) != 2:
        return ("::" if is_ipv6 else "0.0.0.0", 0)

    ip_hex, port_hex = parts[0], parts[1]
    if is_ipv6:
        ip = decode_hex_ipv6(ip_hex)
    else:
        ip = decode_hex_ipv4(ip_hex)
    port = decode_hex_port(port_hex)
    return ip, port


class ProcNetReader:
    """Reads and parses Linux kernel network socket tables."""

    def __init__(self, base_path: str = "/proc/net") -> None:
        self.base_path = Path(base_path)

    def read_socket_table(
        self,
        protocol: SocketProtocol,
        filename: Optional[str] = None,
        max_entries: int = MAX_SOCKETS_PER_READ,
    ) -> List[SocketEntry]:
        """Read and parse a specific socket file (e.g. tcp, tcp6, udp, udp6)."""
        file_map = {
            SocketProtocol.TCP: "tcp",
            SocketProtocol.TCP6: "tcp6",
            SocketProtocol.UDP: "udp",
            SocketProtocol.UDP6: "udp6",
        }
        target_name = filename or file_map.get(protocol, "tcp")
        target_file = self.base_path / target_name

        if not target_file.exists():
            return []

        entries: List[SocketEntry] = []
        is_ipv6 = protocol in (SocketProtocol.TCP6, SocketProtocol.UDP6)

        try:
            with open(target_file, "r", encoding="utf-8", errors="replace") as f:
                header = f.readline()  # Skip column headers line
                if not header:
                    return []

                for line in f:
                    if len(entries) >= max_entries:
                        break

                    line = line.strip()
                    if not line:
                        continue

                    parts = line.split()
                    if len(parts) < 10:
                        continue

                    # Column mappings in /proc/net/tcp:
                    # 0: sl
                    # 1: local_address (hex:port)
                    # 2: rem_address (hex:port)
                    # 3: st (hex state)
                    # 4: tx_queue:rx_queue
                    # 5: tr:tm->when
                    # 6: retrnsmt
                    # 7: uid
                    # 8: timeout
                    # 9: inode
                    local_ip, local_port = parse_ip_port(parts[1], is_ipv6=is_ipv6)
                    remote_ip, remote_port = parse_ip_port(parts[2], is_ipv6=is_ipv6)

                    st_hex = parts[3].upper()
                    if protocol in (SocketProtocol.UDP, SocketProtocol.UDP6):
                        # For UDP, state 07 is typical (unconnected), 01 is connected
                        state = SocketState.LISTEN if local_port > 0 and remote_port == 0 else SocketState.ESTABLISHED
                    else:
                        state = TCP_HEX_STATES.get(st_hex, SocketState.UNKNOWN)

                    tx_rx = parts[4].split(":")
                    tx_q = int(tx_rx[0], 16) if len(tx_rx) > 0 and tx_rx[0] else 0
                    rx_q = int(tx_rx[1], 16) if len(tx_rx) > 1 and tx_rx[1] else 0

                    try:
                        uid = int(parts[7])
                    except (ValueError, IndexError):
                        uid = 0

                    try:
                        inode = int(parts[9])
                    except (ValueError, IndexError):
                        inode = 0

                    entry = SocketEntry(
                        protocol=protocol,
                        local_address=local_ip,
                        local_port=local_port,
                        remote_address=remote_ip,
                        remote_port=remote_port,
                        state=state,
                        inode=inode,
                        uid=uid,
                        tx_queue=tx_q,
                        rx_queue=rx_q,
                    )
                    entries.append(entry)

        except (OSError, PermissionError):
            # Gracefully handle permission denials or missing proc entries
            return []

        return entries

    def read_all_sockets(self, max_entries: int = MAX_SOCKETS_PER_READ) -> List[SocketEntry]:
        """Read all available TCP, TCP6, UDP, and UDP6 socket tables."""
        all_entries: List[SocketEntry] = []
        for proto in (SocketProtocol.TCP, SocketProtocol.TCP6, SocketProtocol.UDP, SocketProtocol.UDP6):
            remaining = max_entries - len(all_entries)
            if remaining <= 0:
                break
            all_entries.extend(self.read_socket_table(proto, max_entries=remaining))
        return all_entries
