#!/usr/bin/env python3
# ==============================================================================
# Program: test_chief_zero_ports_scanner.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 21, 2026
# Purpose: Validates functional correctness, port parsing logic, and socket probing
#          behavior of the Chief Zero Ports Scanner under simulated conditions.
# Change History:
#   - 2026-11-21: Initial test suite validating port ranges, mock server listeners,
#                 and clean perimeter assertions.
#   - 2026-11-21: Expanded test documentation and Rule 16 comment compliance.
# Notes:
#   - Standard library only (socket, threading, time, unittest).
#   - Spins up temporary loopback sockets that are guaranteed to cleanly close.
# ==============================================================================

"""
TEST SUITE: Chief Zero Ports Scanner
=====================================
Validates:
1. Port specification parsing:
   - Single port tokens.
   - Comma-delimited port sequences.
   - Inclusive range expansions (e.g. 8080-8082).
   - Empty input handling and whitespace tolerance.
2. Connection states:
   - Live mock TCP server detection (OPEN status).
   - Connection refusal on closed ephemeral ports (CLOSED/FILTERED status).
   - Boundary checks and perimeter clean calculations.
"""

from __future__ import annotations

import socket
import threading
import time
import unittest

from scripts.chief_zero_ports_scanner import (
    DEFAULT_INSPECT_PORTS,
    check_port,
    parse_port_list,
    scan_host_ports
)


class TestChiefZeroPortsScanner(unittest.TestCase):
    """Test suite for chief_zero_ports_scanner.py functions."""

    def test_parse_port_list_single_and_comma(self):
        """Test parsing simple comma-separated port lists into integer lists."""
        spec = "22, 80, 443"
        ports = parse_port_list(spec)
        # Verify exact integer parsing and sorting
        self.assertEqual(ports, [22, 80, 443])

    def test_parse_port_list_ranges(self):
        """Test parsing inclusive port ranges combined with individual numbers."""
        spec = "80, 8080-8082, 9000"
        ports = parse_port_list(spec)
        # 8080-8082 expands into 8080, 8081, 8082
        self.assertEqual(ports, [80, 8080, 8081, 8082, 9000])

    def test_parse_port_list_empty_and_whitespace(self):
        """Test edge cases with empty strings and arbitrary spaces."""
        # Empty string yields empty list
        self.assertEqual(parse_port_list(""), [])
        # Redundant commas and surrounding whitespace are stripped cleanly
        self.assertEqual(parse_port_list("  , 22 , , 80 "), [22, 80])

    def test_check_port_closed(self):
        """Test connecting to a guaranteed closed local port (e.g., 59999)."""
        # Test connecting to an unbound ephemeral port on loopback
        port, status = check_port("127.0.0.1", 59999, timeout=0.2)
        # Port should report CLOSED (or FILTERED if firewall intercepts)
        self.assertIn(status, ["CLOSED", "FILTERED"])
        self.assertEqual(port, 59999)

    def test_check_port_open_mock_server(self):
        """Test connecting to an active local TCP server spawned in background thread."""
        # Spin up a temporary local TCP listener bound to loopback and OS-assigned port
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        mock_port = server.getsockname()[1]

        # Flag to indicate listener state to the background worker thread
        running = True

        def accept_conn():
            """Background listener that accepts and terminates connections."""
            server.settimeout(1.0)
            try:
                while running:
                    try:
                        conn, _ = server.accept()
                        conn.close()
                    except socket.timeout:
                        continue
            except OSError:
                pass

        # Start acceptor thread as daemon
        thread = threading.Thread(target=accept_conn, daemon=True)
        thread.start()

        try:
            # Probe the mock listener port - must report OPEN
            port, status = check_port("127.0.0.1", mock_port, timeout=0.5)
            self.assertEqual(status, "OPEN")
            self.assertEqual(port, mock_port)

            # Test scan_host_ports includes this mock port as open
            scan_res = scan_host_ports("127.0.0.1", [mock_port, 59998], timeout=0.2)
            self.assertIn(mock_port, scan_res["open_ports"])
            self.assertFalse(scan_res["perimeter_clean"])
            self.assertIn(mock_port, scan_res["unauthorized_open_ports"])
        finally:
            # Clean up mock server resources
            running = False
            server.close()
            thread.join(timeout=0.5)


if __name__ == "__main__":
    unittest.main()
