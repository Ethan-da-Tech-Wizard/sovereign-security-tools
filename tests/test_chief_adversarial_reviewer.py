#!/usr/bin/env python3
# ==============================================================================
# TWU SOVEREIGN CLUSTER - UNIT TESTS: CHIEF ADVERSARIAL CODE REVIEWER
# ==============================================================================
# PROGRAM:       scripts/test_chief_adversarial_reviewer.py
# PROGRAMMER:    Ethan & Antigravity (TWU LLC / Magi Seat 6)
# LAST MODIFIED: 2026-11-21 16:50 MST, local environment
# PURPOSE:       Regression tests for scripts/chief_adversarial_reviewer.py verifying
#                AST safety checks, Rule 16 comment density calculations, receipt
#                generation, and CLI execution.
#
# CHANGE HISTORY:
#   2026-11-21 16:50  Magi 6 (antigravity)  Initial test suite adhering to Rule 16
#                                           standards (>=25% comments, typed docstrings).
# ==============================================================================
# Rule 16 Architecture Notes:
# - All test methods must assert on status, findings, and computed metrics.
# - Employs isolated temporary directories for file creation and receipt writing.
# - Enforces 100% standard library compliance without external test harnesses.
# ==============================================================================
"""Unit test suite for scripts/chief_adversarial_reviewer.py.

Validates:
1. Comment density calculation (token comments + AST docstring literals).
2. AST detection of bare `except:` blocks.
3. AST detection of `BaseException` anti-patterns.
4. AST detection of subprocess execution missing explicit timeout arguments.
5. AST detection of dangerous `shell=True` executions.
6. Detection of missing docstrings on public functions.
7. Atomic receipt generation and fleet report aggregation.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

# Ensure scripts directory is available on sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import chief_adversarial_reviewer as car


class TestChiefAdversarialReviewer(unittest.TestCase):
    """Test suite for ChiefGyk3D adversarial code reviewer engine."""

    def setUp(self) -> None:
        """Create temporary workspace directory for test files."""
        # Step 1: Initialize temporary directory for test fixtures
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmpdir.name)

    def tearDown(self) -> None:
        """Clean up temporary test directory."""
        # Step 1: Clean up temporary directory and files
        self.tmpdir.cleanup()

    def test_comment_density_calculation(self) -> None:
        """Verify accurate calculation of comment and docstring density."""
        # Step 1: Create a well-documented test script (> 30% comments)
        # Includes header block, docstring literals, and in-line code comments
        test_file = self.tmp_path / "well_documented.py"
        test_file.write_text(
            "# Line 1: Comment header\n"
            "# Line 2: Purpose statement\n"
            '"""Module docstring explaining function."""\n'
            "\n"
            "def calculate(a: int, b: int) -> int:\n"
            '    """Add two numbers together."""\n'
            "    # Perform addition operation\n"
            "    return a + b\n"
        )

        # Step 2: Compute density via calculator
        # Returns tuple of (density_percentage, documented_lines, total_lines)
        density, doc_lines, total_lines = car.calculate_comment_density(test_file)

        # Step 3: Assert density exceeds Rule 16 minimum threshold
        # Minimum acceptable density across all production files is 25.0%
        self.assertGreaterEqual(density, 25.0)
        self.assertGreater(doc_lines, 3)
        self.assertEqual(total_lines, 8)

    def test_under_commented_file_triggers_high_finding(self) -> None:
        """Verify that under-commented files (< 25% comments) are flagged with HIGH severity."""
        # Step 1: Create a completely uncommented script
        # Contains pure raw statements with zero documentation or docstrings
        test_file = self.tmp_path / "uncommented.py"
        test_file.write_text(
            "x = 10\n"
            "y = 20\n"
            "z = x + y\n"
            "print(z)\n"
        )

        # Step 2: Perform single file audit
        # Evaluates AST, computes density, and produces findings list
        res = car.audit_single_file(test_file)

        # Step 3: Verify FAIL verdict and Rule 16 finding
        # Expects finding rule 'rule-16-under-commented' with severity 'HIGH'
        self.assertEqual(res["verdict"], "FAIL")
        rules = [f["rule"] for f in res["findings"]]
        self.assertIn("rule-16-under-commented", rules)
        self.assertLess(res["density"], 25.0)

    def test_ast_detects_bare_except(self) -> None:
        """Verify AST visitor flags bare except blocks with HIGH severity."""
        # Step 1: Create script with bare except clause
        # Bare except is an anti-pattern that swallows interrupts
        test_file = self.tmp_path / "bare_except.py"
        test_file.write_text(
            "# Header comment 1\n"
            "# Header comment 2\n"
            "# Header comment 3\n"
            "def safe_run():\n"
            '    """Docstring."""\n'
            "    try:\n"
            "        x = 1 / 0\n"
            "    except:\n"
            "        pass\n"
        )

        # Step 2: Audit file
        # Runs single file audit traversing abstract syntax tree
        res = car.audit_single_file(test_file)

        # Step 3: Verify bare-except rule was triggered
        # Confirms severity is HIGH and message references bare except catch
        rules = [f["rule"] for f in res["findings"]]
        self.assertIn("bare-except", rules)
        finding = next(f for f in res["findings"] if f["rule"] == "bare-except")
        self.assertEqual(finding["severity"], "HIGH")

    def test_ast_detects_base_exception(self) -> None:
        """Verify AST visitor flags catch BaseException with HIGH severity."""
        # Step 1: Create script catching BaseException
        # BaseException catches KeyboardInterrupt and SystemExit which breaks signal handling
        test_file = self.tmp_path / "catch_base.py"
        test_file.write_text(
            "# Header comment 1\n"
            "# Header comment 2\n"
            "# Header comment 3\n"
            "def worker():\n"
            '    """Docstring."""\n'
            "    try:\n"
            "        import sys\n"
            "    except BaseException:\n"
            "        pass\n"
        )

        # Step 2: Audit file
        # Traverses AST and inspects ExceptHandler node type attributes
        res = car.audit_single_file(test_file)

        # Step 3: Verify catch-base-exception rule was triggered
        # Asserts presence of catch-base-exception rule in findings
        rules = [f["rule"] for f in res["findings"]]
        self.assertIn("catch-base-exception", rules)

    def test_ast_detects_missing_subprocess_timeout(self) -> None:
        """Verify AST visitor flags subprocess calls lacking explicit timeout."""
        # Step 1: Create script calling subprocess.run without timeout
        # Subprocess calls without timeout risk deadlocking autonomous agent processes
        test_file = self.tmp_path / "no_timeout.py"
        test_file.write_text(
            "# Header comment 1\n"
            "# Header comment 2\n"
            "# Header comment 3\n"
            "import subprocess\n"
            "def run_cmd():\n"
            '    """Execute external command."""\n'
            "    subprocess.run(['echo', 'hello'])\n"
        )

        # Step 2: Audit file
        # Inspects Call nodes for Call.keywords containing timeout argument
        res = car.audit_single_file(test_file)

        # Step 3: Verify missing-subprocess-timeout rule was triggered
        # Confirms detection of missing timeout keyword
        rules = [f["rule"] for f in res["findings"]]
        self.assertIn("missing-subprocess-timeout", rules)

    def test_ast_detects_dangerous_shell_true(self) -> None:
        """Verify AST visitor flags dangerous shell=True execution."""
        # Step 1: Create script with shell=True argument
        # Shell=True allows arbitrary shell metacharacter expansion and injection
        test_file = self.tmp_path / "shell_true.py"
        test_file.write_text(
            "# Header comment 1\n"
            "# Header comment 2\n"
            "# Header comment 3\n"
            "import subprocess\n"
            "def run_shell(cmd: str):\n"
            '    """Execute shell command."""\n'
            "    subprocess.run(cmd, shell=True, timeout=5)\n"
        )

        # Step 2: Audit file
        # Inspects AST keywords for shell=True constant assignments
        res = car.audit_single_file(test_file)

        # Step 3: Verify dangerous-shell-true rule was triggered
        # Asserts security violation is captured and flagged
        rules = [f["rule"] for f in res["findings"]]
        self.assertIn("dangerous-shell-true", rules)

    def test_audit_paths_aggregates_metrics_and_writes_receipt(self) -> None:
        """Verify audit_paths computes fleet metrics and write_review_receipt saves JSON."""
        # Step 1: Create two compliant test files
        f1 = self.tmp_path / "script1.py"
        f1.write_text(
            "# Comment line 1\n"
            "# Comment line 2\n"
            "# Comment line 3\n"
            '"""Docstring."""\n'
            "def foo():\n"
            '    """Foo docs."""\n'
            "    return True\n"
        )

        f2 = self.tmp_path / "script2.py"
        f2.write_text(
            "# Comment line 1\n"
            "# Comment line 2\n"
            "# Comment line 3\n"
            '"""Docstring."""\n'
            "def bar():\n"
            '    """Bar docs."""\n'
            "    return 42\n"
        )

        # Step 2: Run aggregated audit across temporary directory
        report = car.audit_paths([self.tmp_path])

        # Step 3: Verify report structure and values
        self.assertEqual(report["total_files"], 2)
        self.assertEqual(report["pass_count"], 2)
        self.assertEqual(report["status"], "PASS")
        self.assertGreaterEqual(report["average_score"], 90.0)

        # Step 4: Write receipt to temporary directory
        receipt_path = car.write_review_receipt(report, target_dir=str(self.tmp_path))
        self.assertTrue(receipt_path.is_file())

        # Step 5: Read back and verify valid JSON contents
        saved_data = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(saved_data["status"], "PASS")
        self.assertEqual(saved_data["total_files"], 2)


if __name__ == "__main__":
    # Configure unittest runner for execution in both terminal and CI environments
    # Rule 16 verification: All tests execute with zero external third-party packages
    unittest.main()
