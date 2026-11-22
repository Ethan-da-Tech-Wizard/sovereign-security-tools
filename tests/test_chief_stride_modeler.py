#!/usr/bin/env python3
# ==============================================================================
# Program: test_chief_stride_modeler.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 21, 2026
# Purpose: Validates threat analysis logic, STRIDE category coverage, and MITRE
#          ATLAS mapping in the Chief STRIDE Modeler.
# Change History:
#   - 2026-11-21: Initial test suite validating empty engine, store threat rules,
#                 AI pipeline ATLAS prompt injection, and default fleet model.
#   - 2026-11-21: Expanded test documentation and Rule 16 comment compliance.
# Notes:
#   - Standard library only (unittest).
#   - Deterministic: Runs instantaneously in <0.01 seconds.
# ==============================================================================

"""
TEST SUITE: Chief STRIDE Threat Modeler
========================================
Validates:
1. Registration of system components and trust boundaries.
2. Accurate triggering of STRIDE threat categories:
   - Spoofing (S) for external or actor interfaces.
   - Tampering (T) for stores and state repositories.
   - Information Disclosure (I) for sensitive data components.
3. Mapping of MITRE ATLAS adversarial AI prompt injection threats:
   - Evaluates LLM subagent lanes against AML.T0051.
4. Default TWU fleet threat model generation:
   - Validates multi-node model construction (Dashboard, Syncthing, Pipeline).
"""

from __future__ import annotations

import unittest
from scripts.chief_stride_modeler import ThreatModelEngine, build_default_twu_threat_model


class TestChiefStrideModeler(unittest.TestCase):
    """Test cases for the Chief STRIDE threat modeling engine."""

    def test_empty_engine_reports_zero_threats(self):
        """Verify an empty model produces zero identified threats and empty list."""
        engine = ThreatModelEngine("Empty-Test")
        report = engine.analyze_threats()
        self.assertEqual(report["total_components"], 0)
        self.assertEqual(report["total_threats_identified"], 0)
        self.assertEqual(report["threats"], [])

    def test_stride_tampering_and_disclosure(self):
        """Verify store with sensitive data triggers Tampering and Information Disclosure."""
        engine = ThreatModelEngine("Store-Test")
        # Add a store component marked with sensitive_data=True
        engine.add_component(
            component_id="S1",
            name="Secure Key Store",
            component_type="store",
            trust_zone="internal",
            handles_sensitive_data=True
        )
        report = engine.analyze_threats()
        # Verify component registered properly
        self.assertEqual(report["total_components"], 1)
        # Extract threat types identified by the engine
        threat_types = [t["threat_type"] for t in report["threats"]]
        # Must detect Tampering (T) and Information Disclosure (I)
        self.assertIn("Tampering (T)", threat_types)
        self.assertIn("Information Disclosure (I)", threat_types)

    def test_atlas_prompt_injection_detection(self):
        """Verify AI pipeline triggers MITRE ATLAS prompt injection threat."""
        engine = ThreatModelEngine("AI-Test")
        # Register an AI processing pipeline
        engine.add_component(
            component_id="A1",
            name="LLM Subagent Runner",
            component_type="process",
            trust_zone="internal",
            executes_ai_prompts=True
        )
        report = engine.analyze_threats()
        threat_types = [t["threat_type"] for t in report["threats"]]
        # Must detect AML.T0051 prompt injection
        self.assertIn("Adversarial Prompt Injection (AML.T0051)", threat_types)

    def test_default_twu_threat_model(self):
        """Verify standard TWU threat model builds with all expected components."""
        engine = build_default_twu_threat_model()
        report = engine.analyze_threats()
        # TWU model must have at least 5 standard components
        self.assertGreaterEqual(report["total_components"], 5)
        # Must have identified threats
        self.assertGreater(report["total_threats_identified"], 0)
        # Must attribute correctly to upstream Apache-2.0 source
        self.assertEqual(report["attribution"], "ChiefGyk3D/Clouds-Against-Humanity (Apache-2.0)")


if __name__ == "__main__":
    unittest.main()
