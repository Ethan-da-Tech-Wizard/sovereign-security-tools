#!/usr/bin/env python3
# ==============================================================================
# Program: test_space_weather_telemetry.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 21, 2026
# Purpose: Validates space weather index evaluation, NOAA scale classification,
#          and offline fallback behavior.
# ==============================================================================

"""
TEST SUITE: Space Weather Telemetry
===================================
Validates:
1. Planetary Kp index classification across NOAA G-scales (G0 to G5).
2. Telemetry fetching and offline fallback robustness.
3. Schema compliance and attribution headers.
"""

from __future__ import annotations

import unittest
from scripts.space_weather_telemetry import evaluate_kp_index, fetch_space_weather_telemetry


class TestSpaceWeatherTelemetry(unittest.TestCase):
    """Test cases for the space weather telemetry system."""

    def test_evaluate_kp_quiet(self):
        """Verify Kp < 5 produces G0 Quiet rating."""
        res = evaluate_kp_index(2.3)
        self.assertEqual(res["scale"], "G0")
        self.assertEqual(res["level"], "Quiet")
        self.assertEqual(res["color"], "green")

    def test_evaluate_kp_minor_storm(self):
        """Verify Kp 5.0 to 5.9 produces G1 Minor Storm rating."""
        res = evaluate_kp_index(5.2)
        self.assertEqual(res["scale"], "G1")
        self.assertEqual(res["level"], "Minor Storm")
        self.assertEqual(res["color"], "yellow")

    def test_evaluate_kp_extreme_storm(self):
        """Verify Kp 9.0 produces G5 Extreme Storm rating."""
        res = evaluate_kp_index(9.0)
        self.assertEqual(res["scale"], "G5")
        self.assertEqual(res["level"], "Extreme Storm")
        self.assertEqual(res["color"], "red")

    def test_fetch_space_weather_fallback_or_live(self):
        """Verify fetching returns valid schema even when offline."""
        data = fetch_space_weather_telemetry(timeout=0.2)
        self.assertIn("geomagnetic_g_scale", data)
        self.assertIn("solar_radiation_s_scale", data)
        self.assertIn("radio_blackout_r_scale", data)
        self.assertIn("attribution", data)


if __name__ == "__main__":
    unittest.main()
