# Sovereign Security Tools 🛡️

A lightweight, zero-dependency, local-first security toolkit built for sovereign developers, AI coding agents, and homelab defense.

I love building real things with AI to solve practical security problems and have fun with code. This repository gathers hardened, single-purpose defensive tools that anyone can run on their machine in seconds without paying for cloud subscriptions or installing heavy packages.

## Highlights

* **100% Python Standard Library:** No `pip install`, no virtual environments required, $0.00 spend.
* **Heavily Documented & Commented:** Every tool contains comprehensive step-by-step documentation ($\ge 25\%$ comment density) to make learning cybersecurity fun and accessible.
* **Battle-Tested Security:** Adapted from real-world open-source patterns by [ChiefGyk3D](https://github.com/ChiefGyk3D) under Apache-2.0.
* **Deterministic Receipts:** Outputs structured JSON telemetry receipts for easy integration into custom dashboards and terminals.

---

## The Toolkit

### 1. Zero Open Ports Perimeter Auditor (`scripts/chief_zero_ports_scanner.py`)
Scans external-facing and loopback network interfaces to verify that zero unauthenticated listening ports are exposed to the local network or internet.
```bash
python3 scripts/chief_zero_ports_scanner.py
# Audit a specific target interface or custom timeout
python3 scripts/chief_zero_ports_scanner.py --target 127.0.0.1 --timeout 0.3
```

### 2. STRIDE & MITRE ATLAS Threat Modeler (`scripts/chief_stride_modeler.py`)
Generates deterministic STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) and MITRE ATLAS matrices for AI coding assistants and system components.
```bash
python3 scripts/chief_stride_modeler.py
# Emit raw JSON for pipeline or dashboard consumption
python3 scripts/chief_stride_modeler.py --json
```

### 3. Adversarial Code Reviewer (`scripts/chief_adversarial_reviewer.py`)
*"The best thing a second agent can do for the first one is disagree with it."*
Performs static AST inspections to catch bugs, missing timeout boundaries in subprocesses, bare `except:` catch blocks, and under-commented files.
```bash
python3 scripts/chief_adversarial_reviewer.py scripts/
```

### 4. NOAA Space Weather Telemetry Collector (`scripts/space_weather_telemetry.py`)
Fetches real-time planetary geomagnetic storm indices (Kp index), solar flare flux, and radio blackout alerts directly from the NOAA Space Weather Prediction Center.
```bash
python3 scripts/space_weather_telemetry.py
```

---

## Running the Unit Tests

All tools come with comprehensive unit tests:
```bash
python3 -m unittest discover -s tests
```

---

## License & Attribution

This project is licensed under the [Apache License 2.0](LICENSE).  
See [NOTICE](NOTICE) for upstream attributions to ChiefGyk3D and public domain data providers.
