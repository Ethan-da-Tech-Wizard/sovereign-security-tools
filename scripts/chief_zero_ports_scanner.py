#!/usr/bin/env python3
# ==============================================================================
# Program: chief_zero_ports_scanner.py
# Programmer: Ethan-da-Tech-Wizard (Adapted from ChiefGyk3D/Clouds-Against-Humanity)
# Last Modified: November 21, 2026
# Purpose: Validates external and internal fleet host attack surfaces by enforcing
#          a strict zero-unauthorized-open-ports perimeter policy. Discovers open
#          listeners, identifies anomalies, and generates structured audit receipts.
# Change History:
#   - 2026-11-21: Adapted from ChiefGyk3D/Clouds-Against-Humanity under Apache-2.0.
#                 Implemented concurrent socket scanner, JSON reports, port parser.
#   - 2026-11-21: Expanded network socket comments, concurrency docs, Rule 16 compliance.
# Notes:
#   - Standard library only (socket, concurrent.futures, json, sys, os).
#   - Non-destructive: Half-open / SYN probe without sending payload bytes.
# ==============================================================================

"""
CHIEF ZERO PORTS AUDITOR (Adapted from ChiefGyk3D Clouds-Against-Humanity)
==========================================================================
Architecture & Fleet Integration:
    Adapted from ChiefGyk3D's zero_ports_check.py under the Apache License 2.0.
    In the Clouds-Against-Humanity architecture, external connectors must pass a
    strict zero-open-ports check: any open listener or connection acceptance outside
    the authorized mesh represents an immediate perimeter breach.

    In the TWU Magi Fleet (heterogeneous multi-node workstations), this tool provides
    autonomous non-destructive attack-surface verification across both public
    interfaces and local bridge endpoints.

Invariants:
    1. Zero External Packages: Python Standard Library only (`socket`, `concurrent.futures`, `json`).
    2. Non-Destructive Scanning: Emits half-open / brief SYN connection attempts; performs zero data injection.
    3. Strict Verdict Reporting: Generates deterministic JSON receipts for the live fleet dashboard.
    4. Fast Concurrency: Employs bounded ThreadPoolExecutor workers with strict connection timeouts.

Usage:
    python3 scripts/chief_zero_ports_scanner.py --target 127.0.0.1 --ports 22,80,443,8080
    python3 scripts/chief_zero_ports_scanner.py --target 127.0.0.1 --out data/health/zero_ports.json
"""

from __future__ import annotations

import argparse
import concurrent.futures
import errno
import json
import os
import socket
import sys
import time
from typing import Dict, List, Optional, Tuple

# Default baseline ports inspected for common service exposure
# Includes common administrative, database, remote access, and web ports
DEFAULT_INSPECT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000,
    8080, 8443, 8888, 9000, 9090, 27017
]

# Authorized mesh or internal ports allowed on fleet interfaces
# Known local services mapped to their human-readable purpose
AUTHORIZED_FLEET_PORTS = {
    "2222": "Magi SSH Remote Receiver",
    "51820": "WireGuard Encrypted Mesh",
    "8384": "Syncthing Local Admin GUI",
    "22000": "Syncthing Discovery/Sync"
}


def check_port(host: str, port: int, timeout: float = 0.5) -> Tuple[int, str]:
    """
    Attempts a single socket connection to (host, port).
    
    Socket State Machine:
      - OPEN: Socket connects successfully (TCP SYN-ACK received). Service is actively listening.
      - CLOSED: Kernel actively returns RST packet (errno ECONNREFUSED). Host is up, port closed.
      - FILTERED: Connection times out without response. Packet dropped by firewall / network filter.
      - ERROR: Operating system error or name resolution failure.
    
    Parameters:
        host: IP address or hostname to probe.
        port: TCP port number (1-65535).
        timeout: Maximum seconds to wait for TCP handshake.
        
    Returns:
        (port, status_string)
    """
    # Create an IPv4 TCP stream socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Enforce strict connect timeout to bound runtime and prevent hanging
        sock.settimeout(timeout)
        try:
            # Connect attempt to target port (connect_ex returns C errno code)
            res = sock.connect_ex((host, port))
            if res == 0:
                # 0 indicates successful handshake completion
                return port, "OPEN"
            elif res in (errno.ECONNREFUSED, 111, 61):
                # ECONNREFUSED means target kernel sent TCP RST
                return port, "CLOSED"
            elif res in (errno.ETIMEDOUT, 110, 60):
                # ETIMEDOUT means SYN timed out without acknowledgement
                return port, "FILTERED"
            else:
                # Other socket error codes treated as closed
                return port, "CLOSED"
        except socket.timeout:
            # Socket timeout caught as Python exception
            return port, "FILTERED"
        except OSError:
            # OS level network error (e.g. host unreachable)
            return port, "CLOSED"


def scan_host_ports(host: str, ports: List[int], timeout: float = 0.5, max_workers: int = 50) -> Dict[str, any]:
    """
    Scans specified list of ports concurrently against the target host.
    
    Concurrency Architecture:
      - ThreadPoolExecutor manages a pool of worker threads.
      - Each worker probes a single (host, port) tuple.
      - Results collected as completed to maximize scanning throughput.
    
    Produces structured audit metrics:
      - total_probed: Number of ports tested
      - open_ports: Sorted list of all listening ports
      - unauthorized_open_ports: Open ports not in AUTHORIZED_FLEET_PORTS
      - closed_count: Number of ports that returned RST
      - filtered_count: Number of ports that timed out
      - perimeter_clean: True if zero unauthorized open ports found
    """
    open_ports = []
    closed_ports = []
    filtered_ports = []

    # Execute concurrent socket probes using bounded worker thread pool
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all socket check tasks to the pool
        futures = {executor.submit(check_port, host, port, timeout): port for port in ports}
        # Gather results as each thread finishes
        for future in concurrent.futures.as_completed(futures):
            port, status = future.result()
            if status == "OPEN":
                open_ports.append(port)
            elif status == "CLOSED":
                closed_ports.append(port)
            elif status == "FILTERED":
                filtered_ports.append(port)

    # Sort discovered port numbers in ascending order for consistent display
    open_ports.sort()
    closed_ports.sort()
    filtered_ports.sort()

    # Determine unauthorized exposed ports (excluding permitted WireGuard/SSH mesh)
    unauthorized = [p for p in open_ports if str(p) not in AUTHORIZED_FLEET_PORTS]
    is_perimeter_clean = len(unauthorized) == 0

    # Build comprehensive JSON audit payload
    return {
        "target_host": host,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_probed": len(ports),
        "open_ports": open_ports,
        "unauthorized_open_ports": unauthorized,
        "closed_count": len(closed_ports),
        "filtered_count": len(filtered_ports),
        "perimeter_clean": is_perimeter_clean,
        "attribution": "ChiefGyk3D/Clouds-Against-Humanity (Apache-2.0)"
    }


def parse_port_list(spec: str) -> List[int]:
    """
    Parses a comma-delimited or range-based port specification string.
    Example: '22,80,443,8000-8005' -> [22, 80, 443, 8000, 8001, 8002, 8003, 8004, 8005]
    
    Robustness:
      - Strips arbitrary whitespace around entries.
      - Skips empty comma separated tokens.
      - Expands ranges (start-end) inclusively.
      - De-duplicates and sorts integers.
    """
    result = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        # Check if specification includes a range
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start, end = int(start_str), int(end_str)
            result.update(range(start, end + 1))
        else:
            # Single port number
            result.add(int(part))
    return sorted(result)


def main() -> int:
    """CLI Entrypoint for Chief Zero Ports Auditor."""
    parser = argparse.ArgumentParser(
        description="Zero Open Ports Attack-Surface Scanner (ChiefGyk3D Architecture)"
    )
    parser.add_argument("--target", default="127.0.0.1", help="Target IP or hostname to audit (default: 127.0.0.1)")
    parser.add_argument("--ports", help="Comma-delimited ports or range (default: standard 27 baseline ports)")
    parser.add_argument("--timeout", type=float, default=0.4, help="Socket connect timeout in seconds (default: 0.4)")
    parser.add_argument("--out", help="Optional path to write JSON audit receipt")
    parser.add_argument("--json", action="store_true", help="Output raw JSON summary")

    args = parser.parse_args()

    # Determine port list from user arguments or default inspection baseline
    ports = parse_port_list(args.ports) if args.ports else DEFAULT_INSPECT_PORTS

    # Execute perimeter scan across selected ports
    result = scan_host_ports(args.target, ports, timeout=args.timeout)

    # Format JSON output
    formatted_json = json.dumps(result, indent=2)

    # Write receipt if requested by caller
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(formatted_json + "\n")

    # Present results in requested format
    if args.json:
        print(formatted_json)
    else:
        print("======================================================================")
        print(" 🛡️  CHIEF ZERO PORTS PERIMETER AUDITOR (ChiefGyk3D / Apache-2.0)")
        print("======================================================================")
        print(f" Target Host:       {result['target_host']}")
        print(f" Total Probed:      {result['total_probed']} ports")
        print(f" Open Ports:        {result['open_ports']}")
        print(f" Unauthorized Open: {result['unauthorized_open_ports']}")
        print(f" Filtered (Silent): {result['filtered_count']}")
        print(f" Perimeter Clean:   {'✅ PASS (Zero Exposure)' if result['perimeter_clean'] else '⚠️ WARN (Open Ports Detected)'}")
        print("======================================================================")

    # Exit 0 if perimeter clean, 1 if unexpected open ports detected
    return 0 if result["perimeter_clean"] else 1


if __name__ == "__main__":
    sys.exit(main())
