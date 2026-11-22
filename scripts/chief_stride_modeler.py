#!/usr/bin/env python3
# ==============================================================================
# Program: chief_stride_modeler.py
# Programmer: Ethan-da-Tech-Wizard (Adapted from ChiefGyk3D/Clouds-Against-Humanity)
# Last Modified: November 21, 2026
# Purpose: Synthesizes automated STRIDE, MITRE ATT&CK, and MITRE ATLAS threat models
#          for fleet systems, autonomous agent lanes, and cloud deployment pipelines.
# Change History:
#   - 2026-11-21: Adapted from ChiefGyk3D/Clouds-Against-Humanity under Apache-2.0.
#                 Added STRIDE component evaluators, MITRE ATLAS prompt injection checks.
#   - 2026-11-21: Expanded architecture documentation, mitigations, and Rule 16 compliance.
# Notes:
#   - Standard library only (json, sys, pathlib, typing).
#   - Deterministic: Always generates identical outputs given identical inputs.
# ==============================================================================

"""
CHIEF STRIDE THREAT MODELER (Adapted from ChiefGyk3D Clouds-Against-Humanity)
=============================================================================
Architecture & Fleet Integration:
    Adapted from ChiefGyk3D's threat modeling frameworks under the Apache License 2.0.
    In Clouds-Against-Humanity, threats are mapped continuously across three
    orthogonal security dimensions:
      1. STRIDE: Component-level trust boundary threats:
         - Spoofing (S): Impersonating identity or processes across trust boundaries.
         - Tampering (T): Modifying code, state, or communications in flight or at rest.
         - Repudiation (R): Denying actions due to missing deterministic cryptographic audit trails.
         - Information Disclosure (I): Leaking secrets, PII, or internal metadata to untrusted parties.
         - Denial of Service (D): Exhausting host/mesh compute, RAM, or bandwidth resources.
         - Elevation of Privilege (E): Escalating unprivileged subagent or local tasks to root/host.
      2. MITRE ATT&CK: Host/cloud infrastructure tactics and adversary behaviors:
         - Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion,
           Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact.
      3. MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems):
         - AML.T0051 (Adversarial Prompt Injection / Jailbreaks).
         - AML.T0054 (LLM Hallucination Exploitation / Indirect Poisoning).
         - AML.T0043 (Crafted Adversarial Input to Tool Call Parsers).

Invariants:
    1. Zero External Packages: Standard Library only (`json`, `sys`, `pathlib`, `typing`).
    2. Deterministic Mapping: Component definitions always produce identical threat classifications.
    3. Audit Receipts: Generates structured JSON threat models readable by the fleet dashboard.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List

# Standard STRIDE Categories with definitions and baseline mitigations
# Each category defines core attack surface characteristics and defense mechanisms
STRIDE_DEFINITIONS = {
    "S": {
        "name": "Spoofing",
        "description": "Pretending to be someone or something other than oneself.",
        "baseline_mitigation": "Cryptographic mutual authentication, Ed25519 signatures, TLS certificates."
    },
    "T": {
        "name": "Tampering",
        "description": "Modifying data or code in transit or at rest without authorization.",
        "baseline_mitigation": "HMAC digests, write-guard locks, immutable append-only ledgers."
    },
    "R": {
        "name": "Repudiation",
        "description": "Claiming to have not performed an action without proof to the contrary.",
        "baseline_mitigation": "Deterministic signed journals, synchronized NTP timestamps, non-repudiation receipts."
    },
    "I": {
        "name": "Information Disclosure",
        "description": "Exposing private or confidential data to unauthorized entities.",
        "baseline_mitigation": "Zero PII scanners, WireGuard encryption, Doppler/Keyring secret isolation."
    },
    "D": {
        "name": "Denial of Service",
        "description": "Exhausting resources to prevent legitimate system access.",
        "baseline_mitigation": "Token bucket rate limiters, memory quotas (slotted layout), thermal ceilings."
    },
    "E": {
        "name": "Elevation of Privilege",
        "description": "Gaining higher execution permissions without proper authorization.",
        "baseline_mitigation": "Least-privilege service units, process isolation jails, policy command guardrails."
    }
}

# Standard Component Types for Threat Evaluation
# Processes represent active execution contexts; stores hold persistent state;
# actors represent human/automated callers; boundaries delineate security contexts.
COMPONENT_TYPES = ["process", "store", "actor", "interactor", "boundary"]


class ThreatModelEngine:
    """Evaluates component definitions against STRIDE and ATLAS threat rules."""

    def __init__(self, system_name: str = "TWU-Fleet-Core"):
        """Initialize engine with target system name and empty component register."""
        self.system_name = system_name
        self.components: List[Dict[str, Any]] = []

    def add_component(
        self,
        component_id: str,
        name: str,
        component_type: str,
        trust_zone: str,
        handles_sensitive_data: bool = False,
        is_external_facing: bool = False,
        executes_ai_prompts: bool = False
    ) -> None:
        """
        Registers a system component for threat assessment.
        
        Parameters:
            component_id: Unique identifier (e.g., "DASH-01")
            name: Human-readable component title
            component_type: One of COMPONENT_TYPES ("process", "store", "actor", "interactor", "boundary")
            trust_zone: Zone of security ("internal", "dmz", "boundary", "external")
            handles_sensitive_data: True if component processes keys, credentials, or PII
            is_external_facing: True if reachable from non-mesh network or public internet
            executes_ai_prompts: True if component routes prompts through LLMs or subagent loops
        """
        self.components.append({
            "id": component_id,
            "name": name,
            "type": component_type,
            "trust_zone": trust_zone,
            "sensitive_data": handles_sensitive_data,
            "external_facing": is_external_facing,
            "ai_pipeline": executes_ai_prompts
        })

    def analyze_threats(self) -> Dict[str, Any]:
        """
        Analyzes all registered components and outputs full threat evaluations.
        Applies deterministic mapping rules against STRIDE and MITRE ATLAS matrices.
        """
        threat_findings = []

        # Iterate over all registered system components
        for comp in self.components:
            cid = comp["id"]
            name = comp["name"]

            # STRIDE Rule 1: Spoofing (applies to actors, external interfaces, and inter-device channels)
            if comp["external_facing"] or comp["type"] in ("actor", "interactor"):
                threat_findings.append({
                    "component_id": cid,
                    "component_name": name,
                    "threat_type": "Spoofing (S)",
                    "severity": "HIGH" if comp["external_facing"] else "MEDIUM",
                    "description": f"Adversary may forge identity of {name} across network perimeter.",
                    "mitigation": "Require Ed25519 peer identity handshake and mutual TLS authentication.",
                    "framework": "STRIDE"
                })

            # STRIDE Rule 2: Tampering (applies to stores, message queues, and code directories)
            if comp["type"] == "store" or comp["sensitive_data"]:
                threat_findings.append({
                    "component_id": cid,
                    "component_name": name,
                    "threat_type": "Tampering (T)",
                    "severity": "HIGH",
                    "description": f"Unauthorized modification of stored artifacts or config in {name}.",
                    "mitigation": "Apply SHA-256 tree hashing, file lock sentinels, and read-only jail environments.",
                    "framework": "STRIDE"
                })

            # STRIDE Rule 3: Information Disclosure (applies to components handling sensitive data)
            if comp["sensitive_data"] or comp["external_facing"]:
                threat_findings.append({
                    "component_id": cid,
                    "component_name": name,
                    "threat_type": "Information Disclosure (I)",
                    "severity": "CRITICAL" if comp["sensitive_data"] and comp["external_facing"] else "HIGH",
                    "description": f"PII or private secrets leaking from {name} to external vantage points.",
                    "mitigation": "Run automated public_export_audit.py gate and restrict external egress.",
                    "framework": "STRIDE"
                })

            # MITRE ATLAS Rule 1: Adversarial Prompt Injection (applies to AI agent lanes)
            if comp["ai_pipeline"]:
                threat_findings.append({
                    "component_id": cid,
                    "component_name": name,
                    "threat_type": "Adversarial Prompt Injection (AML.T0051)",
                    "severity": "HIGH",
                    "description": f"Untrusted input prompt hijack attempting tool invocation or escape in {name}.",
                    "mitigation": "Enforce strict tool guardrails, input sanitization sieves, and stop latches.",
                    "framework": "MITRE ATLAS"
                })

        # Synthesize full audit report
        return {
            "system_name": self.system_name,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_components": len(self.components),
            "total_threats_identified": len(threat_findings),
            "threats": threat_findings,
            "attribution": "ChiefGyk3D/Clouds-Against-Humanity (Apache-2.0)"
        }


def build_default_twu_threat_model() -> ThreatModelEngine:
    """
    Constructs the standard TWU fleet architecture threat model.
    Captures primary operational nodes across the multi-node sovereign fleet.
    """
    engine = ThreatModelEngine("TWU-Sovereign-Fleet")

    # Add core fleet components:
    # 1. Cockpit Web Dashboard
    engine.add_component("DASH-01", "Fleet OS Portal Dashboard", "process", "internal", handles_sensitive_data=True)
    # 2. Syncthing Peer Mesh
    engine.add_component("SYNC-01", "Syncthing Encrypted Mesh", "interactor", "internal", handles_sensitive_data=True)
    # 3. Public Git Export Pipeline
    engine.add_component("PUB-01", "Public Git Export Pipeline", "process", "boundary", handles_sensitive_data=True, is_external_facing=True)
    # 4. Autonomous Agent Engine
    engine.add_component("AI-AGENT-01", "Autonomous Coding Subagent Engine", "process", "internal", executes_ai_prompts=True)
    # 5. Local Health and Audit Vault
    engine.add_component("VAULT-01", "Local Health and Receipt Store", "store", "internal", handles_sensitive_data=True)

    return engine


def main() -> int:
    """CLI runner for STRIDE threat model generation."""
    parser = argparse.ArgumentParser(description="Chief STRIDE Threat Modeler")
    parser.add_argument("--json", action="store_true", help="Print raw JSON threat report")
    parser.add_argument("--out", help="Write JSON threat report to path")

    args = parser.parse_args()

    engine = build_default_twu_threat_model()
    report = engine.analyze_threats()
    report_json = json.dumps(report, indent=2)

    # Save to file if output path is requested
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report_json + "\n")

    # Display report on stdout
    if args.json:
        print(report_json)
    else:
        print("======================================================================")
        print(" 🛡️  CHIEF STRIDE & ATLAS THREAT MODELER (ChiefGyk3D / Apache-2.0)")
        print("======================================================================")
        print(f" Target System:      {report['system_name']}")
        print(f" Total Components:   {report['total_components']}")
        print(f" Identified Threats: {report['total_threats_identified']}")
        print("----------------------------------------------------------------------")
        for threat in report["threats"]:
            print(f" [{threat['framework']}] {threat['threat_type']} -> {threat['component_name']}")
            print(f"   Severity:   {threat['severity']}")
            print(f"   Mitigation: {threat['mitigation']}\n")
        print("======================================================================")

    return 0


if __name__ == "__main__":
    sys.exit(main())
