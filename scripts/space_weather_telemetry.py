#!/usr/bin/env python3
# ==============================================================================
# Program: space_weather_telemetry.py
# Programmer: Ethan-da-Tech-Wizard (Adapted from ChiefGyk3D/solarstorm_scout)
# Last Modified: November 21, 2026
# Purpose: Gathers NOAA space weather, solar flare flux, and geomagnetic storm
#          telemetry, evaluating risk levels for fleet radio and satellite links.
# Change History:
#   - 2026-11-21: Initial adaptation from ChiefGyk3D/solarstorm_scout under Apache-2.0.
#                 Added offline fallback, structured JSON output, and CLI runner.
#   - 2026-11-21: Expanded telemetry comments, NOAA scale physics, and Rule 16 compliance.
# Notes:
#   - Uses Python standard library only (urllib.request, json, time).
#   - Falls back gracefully to baseline metrics if network is offline or isolated.
# ==============================================================================

"""
SPACE WEATHER TELEMETRY (Adapted from ChiefGyk3D solarstorm_scout)
==================================================================
Architecture & Fleet Integration:
    Adapted from ChiefGyk3D's solarstorm_scout concept (NOAA space weather monitoring).
    In the TWU fleet dashboard, space weather telemetry provides real-time awareness
    of solar flares, geomagnetic storms (Kp index), and high-frequency radio blackouts
    that affect long-range wireless, GPS timing, and satellite telemetry.

NOAA Space Weather Scales:
    1. Geomagnetic Storms (G-Scale):
       - Driven by coronal mass ejections (CMEs) and high-speed solar wind streams.
       - G1 (Minor): Weak power grid fluctuations; aurora visible at high latitudes.
       - G2 (Moderate): High-latitude power systems may experience voltage alarms.
       - G3 (Strong): Voltage corrections required; false alarms on protection devices.
       - G4 (Severe): Possible widespread voltage control problems and grid damage.
       - G5 (Extreme): Complete grid collapse or blackouts; spacecraft charging.
    2. Solar Radiation Storms (S-Scale):
       - Driven by energetic protons accelerated by solar flares.
       - S1 to S5 impact satellite sensors, memory bitflips, and polar HF communication.
    3. Radio Blackouts (R-Scale):
       - Driven by X-ray emissions ionizing the D-region of the ionosphere.
       - R1 to R5 cause temporary degradation to complete loss of HF radio signals.

Invariants:
    1. Zero External Packages: Python Standard Library only (`urllib.request`, `json`, `time`).
    2. Graceful Offline Fallback: If network is offline or isolated, provides cached/synthetic telemetry.
    3. Structured Output: Emits JSON receipts consumed by the OS portal dashboard.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict

# NOAA SWPC (Space Weather Prediction Center) Open API Endpoints
# Public JSON feed containing real-time values for G, S, and R scales
NOAA_SCALING_URL = "https://services.swpc.noaa.gov/products/noaa-scales.json"


def evaluate_kp_index(kp_value: float) -> Dict[str, str]:
    """
    Evaluates planetary Kp index and maps to NOAA G-scale (Geomagnetic Storms).
    
    The Kp-index is a quasi-logarithmic measure of geomagnetic activity ranging
    from 0 to 9, calculated every 3 hours from ground-based magnetometers around the globe.
    
    Thresholds:
      - Kp < 5.0: G0 Quiet / Normal background conditions.
      - 5.0 <= Kp < 6.0: G1 Minor Storm.
      - 6.0 <= Kp < 7.0: G2 Moderate Storm.
      - 7.0 <= Kp < 8.0: G3 Strong Storm.
      - 8.0 <= Kp < 9.0: G4 Severe Storm.
      - Kp >= 9.0: G5 Extreme Storm.
    """
    # Evaluate background quiet state (Kp below storm threshold of 5.0)
    if kp_value < 5.0:
        return {
            "scale": "G0",
            "level": "Quiet",
            "color": "green",
            "impact": "Normal geomagnetic conditions. Fleet wireless channels fully operational."
        }
    # Minor geomagnetic activity
    elif kp_value < 6.0:
        return {
            "scale": "G1",
            "level": "Minor Storm",
            "color": "yellow",
            "impact": "Weak power grid fluctuations; minor aurora visible at high latitudes."
        }
    # Moderate storm activity
    elif kp_value < 7.0:
        return {
            "scale": "G2",
            "level": "Moderate Storm",
            "color": "orange",
            "impact": "High-latitude power systems may experience voltage alarms; minor satellite drag."
        }
    # Strong geomagnetic disturbance
    elif kp_value < 8.0:
        return {
            "scale": "G3",
            "level": "Strong Storm",
            "color": "orange",
            "impact": "Voltage corrections required; false alarms triggered on protection devices."
        }
    # Severe space weather disturbance
    elif kp_value < 9.0:
        return {
            "scale": "G4",
            "level": "Severe Storm",
            "color": "red",
            "impact": "Possible blackouts, spacecraft orientation tracking problems, pipeline currents."
        }
    # Extreme planetary geomagnetic storm
    else:
        return {
            "scale": "G5",
            "level": "Extreme Storm",
            "color": "red",
            "impact": "Widespread voltage control problems; grid systems collapse risks."
        }


def fetch_space_weather_telemetry(timeout: float = 2.0) -> Dict[str, Any]:
    """
    Fetches live NOAA space weather scales or returns clean baseline telemetry
    if the host is running offline or inside an isolated container.
    
    Robustness Policy:
      - Enforces strict timeout on network request so callers are never blocked.
      - Catches all exceptions (network down, HTTP 4xx/5xx, isolation boundary).
      - Returns consistent schema across live and fallback modes.
    """
    now_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    
    # Try querying NOAA open API endpoint
    try:
        # Construct standard request with custom identification header
        req = urllib.request.Request(
            NOAA_SCALING_URL,
            headers={"User-Agent": "TWU-Magi-Telemetry/1.0 (Ethan-da-Tech-Wizard)"}
        )
        # Execute HTTP GET with bounded timeout
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            # Parse current scales (key "0" represents current observation period)
            current = data.get("0", {})
            g_scale = current.get("G", {}).get("Scale", "0")
            r_scale = current.get("R", {}).get("Scale", "0")
            s_scale = current.get("S", {}).get("Scale", "0")
            
            # Return live parsed telemetry
            return {
                "timestamp": now_utc,
                "status": "ONLINE_LIVE",
                "geomagnetic_g_scale": f"G{g_scale}",
                "solar_radiation_s_scale": f"S{s_scale}",
                "radio_blackout_r_scale": f"R{r_scale}",
                "assessment": "LIVE_NOAA_SWPC",
                "attribution": "ChiefGyk3D/solarstorm_scout & NOAA SWPC Open Data"
            }
    except Exception:
        # Graceful fallback: return clean baseline metrics when offline or isolated
        return {
            "timestamp": now_utc,
            "status": "BASELINE_NORMAL",
            "geomagnetic_g_scale": "G0",
            "solar_radiation_s_scale": "S0",
            "radio_blackout_r_scale": "R0",
            "assessment": "Quiet background conditions (Offline/Isolated mode)",
            "attribution": "ChiefGyk3D/solarstorm_scout & NOAA SWPC Open Data"
        }


def write_telemetry_receipt(telemetry: Dict[str, Any], target_dir: str = "data/health") -> str:
    """
    Writes telemetry receipt to disk for dashboard integration.
    Saves to target_dir/space_weather.json if directory exists.
    """
    if os.path.isdir(target_dir):
        out_path = os.path.join(target_dir, "space_weather.json")
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(telemetry, f, indent=2)
            return out_path
        except OSError:
            pass
    return ""


def main() -> int:
    """CLI runner for space weather telemetry."""
    parser = argparse.ArgumentParser(description="Space Weather Telemetry Collector")
    parser.add_argument("--json", action="store_true", help="Print JSON formatted telemetry")
    parser.add_argument("--save", action="store_true", help="Save receipt to data/health/space_weather.json")
    args = parser.parse_args()

    telemetry = fetch_space_weather_telemetry()
    telemetry_json = json.dumps(telemetry, indent=2)

    if args.save:
        write_telemetry_receipt(telemetry)

    if args.json:
        print(telemetry_json)
    else:
        print("======================================================================")
        print(" 🛰️  NOAA SPACE WEATHER & SOLAR STORM TELEMETRY (ChiefGyk3D Inspired)")
        print("======================================================================")
        print(f" Timestamp:           {telemetry['timestamp']}")
        print(f" Status:              {telemetry['status']}")
        print(f" Geomagnetic Scale:   {telemetry['geomagnetic_g_scale']} (G0 = Quiet, G5 = Extreme)")
        print(f" Solar Radiation:     {telemetry['solar_radiation_s_scale']}")
        print(f" Radio Blackout:      {telemetry['radio_blackout_r_scale']}")
        print(f" Assessment:          {telemetry['assessment']}")
        print("======================================================================")

    return 0


if __name__ == "__main__":
    sys.exit(main())
