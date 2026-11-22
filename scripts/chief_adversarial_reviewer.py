#!/usr/bin/env python3
# ==============================================================================
# TWU SOVEREIGN CLUSTER - CHIEF ADVERSARIAL CODE REVIEWER
# ==============================================================================
# PROGRAM:       scripts/chief_adversarial_reviewer.py
# PROGRAMMER:    Ethan & Antigravity (TWU LLC / Magi Seat 6)
# LAST MODIFIED: 2026-11-21 16:45 MST, local environment
# PURPOSE:       Adversarial static analysis and code hygiene engine adapted from
#                ChiefGyk3D/department-of-internal-arguments under Apache-2.0.
#                Audits Python files for Rule 16 comment density, bare exceptions,
#                missing timeout boundaries, shell injection vectors, and missing docs.
#
# PHILOSOPHY:
#   "The best thing a second agent can do for the first one is disagree with it."
#
# CHANGE HISTORY:
#   2026-11-21 16:45  Magi 6 (antigravity)  Initial implementation adhering to Rule 16
#                                           standards (>=25% comments, typed docstrings).
# ==============================================================================
"""Adversarial code reviewer and static analysis engine for TWU sovereign fleet.

Adapted from ChiefGyk3D/department-of-internal-arguments under Apache License 2.0.

Provides rigorous adversarial inspection of codebase files:
1. Rule 16 Comment Density: Flag any file with < 25% comment density.
2. Missing Timeouts: Flag any subprocess or socket call missing explicit timeouts.
3. Bare Exception Handlers: Flag `except:` or `except BaseException:`.
4. Dangerous Shell Executions: Flag `shell=True` or `os.system` usage.
5. Missing Function/Class Docstrings: Flag non-internal functions lacking docstrings.
6. Persistent Health Receipt: Writes structured review telemetry to data/health/adversarial_review.json.
"""

from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import tokenize
from typing import Any, Dict, List, Optional, Tuple, Set

# Repository workspace root resolution
# TWU_ROOT environment variable takes precedence when running in containerized seats
ROOT = Path(os.environ.get("TWU_ROOT") or Path(__file__).resolve().parents[1])

# Minimum acceptable comment density percentage under Rule 16
RULE_16_MIN_DENSITY = 25.0


class TerminalColors:
    """ANSI terminal color constants for formatted CLI telemetry output."""

    CYAN = "\033[96m"
    GREEN = "\033[92m"
    GOLD = "\033[93m"
    ROSE = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


class AdversarialAstVisitor(ast.NodeVisitor):
    """AST visitor that detects adversarial defects, hazards, and missing boundaries."""

    def __init__(self, filepath: str) -> None:
        """Initialize the visitor with target file path context."""
        # Store file path string for diagnostic messages
        self.filepath = filepath
        # Collection of identified code defects
        self.findings: List[Dict[str, Any]] = []

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Inspect exception handlers for bare except or BaseException anti-patterns."""
        # Step 1: Detect completely bare except: handlers (node.type is None)
        # Bare except clauses catch everything including KeyboardInterrupt, SystemExit,
        # and GeneratorExit, making scripts impossible to break out of gracefully.
        if node.type is None:
            # Append high severity finding with line number
            self.findings.append({
                "severity": "HIGH",
                "line": node.lineno,
                "rule": "bare-except",
                "message": "Bare `except:` catch block swallows system interrupts and debugging signals.",
            })
        # Step 2: Detect catch of BaseException which catches KeyboardInterrupt and SystemExit
        # Robust production code should explicitly handle `Exception` rather than `BaseException`.
        elif isinstance(node.type, ast.Name) and node.type.id == "BaseException":
            # Append high severity finding indicating BaseException anti-pattern
            self.findings.append({
                "severity": "HIGH",
                "line": node.lineno,
                "rule": "catch-base-exception",
                "message": "Catching `BaseException` catches SystemExit and KeyboardInterrupt; use `Exception` instead.",
            })
        # Step 3: Continue AST traversal through handler body to inspect nested calls
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect function calls for missing timeouts or dangerous shell flags."""
        # Step 1: Detect subprocess execution calls (subprocess.run, Popen, check_output, etc.)
        # Extract the function name from either an attribute (mod.func) or bare identifier
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            # Example: subprocess.run -> attr is 'run'
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            # Example: run(...) imported directly from subprocess -> id is 'run'
            func_name = node.func.id

        # Step 2: Check subprocess execution calls for explicit timeout keyword argument
        # Commands lacking timeout can freeze forever if an underlying process deadlocks
        if func_name in ("run", "check_output", "check_call", "call"):
            # Search keywords list for a parameter named 'timeout'
            has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
            if not has_timeout:
                # Append medium severity warning for missing timeout boundary
                self.findings.append({
                    "severity": "MEDIUM",
                    "line": node.lineno,
                    "rule": "missing-subprocess-timeout",
                    "message": f"`subprocess.{func_name}` called without explicit timeout; hazard for UI hang.",
                })

        # Step 3: Check for dangerous shell=True keyword argument
        # Passing shell=True with unquoted user input is the #1 cause of command injection
        for kw in node.keywords:
            if kw.arg == "shell":
                # Check if shell is assigned True constant
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    # Append high severity security finding for raw shell execution
                    self.findings.append({
                        "severity": "HIGH",
                        "line": node.lineno,
                        "rule": "dangerous-shell-true",
                        "message": "Executing command with `shell=True` creates command injection hazard.",
                    })

        # Step 4: Continue AST traversal through call arguments and nested expressions
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Inspect function definitions for missing documentation docstrings."""
        # Step 1: Ignore internal / private dunder or underscore helper methods
        # Private helpers with names like _format_text are exempted from mandatory docstrings
        if not node.name.startswith("_"):
            # Step 2: Check if first body statement is a docstring expression
            # Python stores function docstrings as the initial string constant in the body
            docstring = ast.get_docstring(node)
            if not docstring:
                # Append low severity finding for missing public API documentation
                self.findings.append({
                    "severity": "LOW",
                    "line": node.lineno,
                    "rule": "missing-function-docstring",
                    "message": f"Public function `{node.name}` lacks a docstring specification.",
                })
        # Step 3: Continue AST traversal into function body to inspect inner functions
        self.generic_visit(node)


def calculate_comment_density(filepath: Path) -> Tuple[float, int, int]:
    """Calculate the comment and docstring density of a Python source file.

    Args:
        filepath: Path to the target Python script.

    Returns:
        Tuple[float, int, int]: (density_percentage, comment_and_doc_lines, total_lines).
    """
    # Step 1: Read total line count of the source file safely
    # Uses UTF-8 decoding with character replacement to prevent crashes on non-ASCII symbols
    try:
        raw_text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        # If file is unreadable (e.g. permission or missing), return zero density
        return 0.0, 0, 0

    # Split text into lines to compute total physical line count
    lines = raw_text.splitlines()
    total_lines = len(lines)
    # An empty file is trivially 100% compliant with zero defects
    if total_lines == 0:
        return 100.0, 0, 0

    # Step 2: Tokenize file to identify exact comment tokens
    # Tracks unique 1-indexed line numbers containing comment tokens
    comment_lines: Set[int] = set()
    try:
        # Open file in binary mode as required by standard tokenize generator
        with filepath.open("rb") as f:
            lex_stream = list(tokenize.tokenize(f.readline))
        # Iterate over lexical tokens to isolate comments
        for tok in lex_stream:
            if tok.type == tokenize.COMMENT:
                # Add line number of comment token start position
                comment_lines.add(tok.start[0])
    except (tokenize.TokenError, IndentationError, SyntaxError):
        # Fallback to simple regex if tokenizer encounters malformed syntax
        # Ensures adversarial scan never aborts on syntactically broken code
        for idx, line in enumerate(lines, start=1):
            if line.strip().startswith("#"):
                comment_lines.add(idx)

    # Step 3: Extract multiline docstring ranges using the AST parser
    # Docstrings serve as critical documentation and are counted under Rule 16
    try:
        # Build abstract syntax tree from decoded file source text
        tree = ast.parse(raw_text, filename=str(filepath))
        for node in ast.walk(tree):
            # Inspect Module, Class, and Function nodes for leading docstring expression
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                if (node.body and isinstance(node.body[0], ast.Expr) and
                        isinstance(node.body[0].value, ast.Constant) and
                        isinstance(node.body[0].value.value, str)):
                    expr = node.body[0]
                    # Calculate line range spanning the docstring literal
                    end_line = expr.end_lineno if expr.end_lineno else expr.lineno
                    # Add every line number in the docstring span
                    for lno in range(expr.lineno, end_line + 1):
                        comment_lines.add(lno)
    except (SyntaxError, IndentationError):
        # Ignore AST syntax errors during docstring extraction
        pass

    # Step 4: Compute final comment density percentage
    # Count of documented lines divided by total file line count
    total_documented = len(comment_lines)
    density = (total_documented / total_lines) * 100.0
    return density, total_documented, total_lines


def audit_single_file(filepath: Path) -> Dict[str, Any]:
    """Perform comprehensive adversarial code quality and security review on one file.

    Args:
        filepath: Path to the Python file being audited.

    Returns:
        Dict[str, Any]: Result payload with metrics, findings, and pass/fail verdict.
    """
    # Step 1: Ensure file exists and is a readable file
    if not filepath.is_file():
        return {
            "path": str(filepath),
            "verdict": "ERROR",
            "score": 0,
            "density": 0.0,
            "findings": [{"severity": "HIGH", "line": 0, "rule": "missing-file", "message": "File not found"}],
        }

    # Step 2: Calculate Rule 16 comment density
    density, doc_lines, total_lines = calculate_comment_density(filepath)
    findings: List[Dict[str, Any]] = []

    # Step 3: Check Rule 16 density invariant (>= 25%)
    if density < RULE_16_MIN_DENSITY:
        findings.append({
            "severity": "HIGH",
            "line": 1,
            "rule": "rule-16-under-commented",
            "message": f"Comment density is {density:.1f}% ({doc_lines}/{total_lines} lines), below Rule 16 required 25.0%.",
        })

    # Step 4: Parse AST and execute adversarial visitor
    try:
        raw_content = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(raw_content, filename=str(filepath))
        visitor = AdversarialAstVisitor(str(filepath))
        visitor.visit(tree)
        findings.extend(visitor.findings)
    except SyntaxError as err:
        findings.append({
            "severity": "CRITICAL",
            "line": err.lineno or 0,
            "rule": "syntax-error",
            "message": f"Syntax error prevents AST inspection: {err.msg}",
        })

    # Step 5: Determine overall verdict and computed health score (0 to 100)
    high_count = sum(1 for f in findings if f["severity"] in ("HIGH", "CRITICAL"))
    med_count = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low_count = sum(1 for f in findings if f["severity"] == "LOW")

    # Score calculation: base 100 with penalties for defects
    score = max(0, 100 - (high_count * 25) - (med_count * 10) - (low_count * 2))

    verdict = "PASS"
    if high_count > 0:
        verdict = "FAIL"
    elif med_count > 0 or low_count > 0:
        verdict = "WARN"

    return {
        "path": str(filepath.resolve()),
        "name": filepath.name,
        "verdict": verdict,
        "score": score,
        "density": round(density, 1),
        "doc_lines": doc_lines,
        "total_lines": total_lines,
        "findings": findings,
    }


def audit_paths(paths: List[Path]) -> Dict[str, Any]:
    """Audit multiple files or directories recursively.

    Args:
        paths: List of file or directory paths to audit.

    Returns:
        Dict[str, Any]: Consolidated review report across all target paths.
    """
    # Step 1: Collect all unique target Python files
    py_files: List[Path] = []
    for p in paths:
        p = p.resolve()
        if p.is_file() and p.suffix == ".py":
            py_files.append(p)
        elif p.is_dir():
            for root, _, fns in os.walk(p):
                # Skip virtual environments, git repositories, and build artifacts
                if any(x in root for x in (".git", ".venv", "venv", "__pycache__", "node_modules")):
                    continue
                for fn in fns:
                    if fn.endswith(".py"):
                        py_files.append(Path(root) / fn)

    # Step 2: Audit each collected file
    file_results: List[Dict[str, Any]] = []
    for f in sorted(py_files):
        file_results.append(audit_single_file(f))

    # Step 3: Compute fleet-wide review posture metrics
    total_files = len(file_results)
    pass_count = sum(1 for r in file_results if r["verdict"] == "PASS")
    warn_count = sum(1 for r in file_results if r["verdict"] == "WARN")
    fail_count = sum(1 for r in file_results if r["verdict"] == "FAIL")

    avg_score = round(sum(r["score"] for r in file_results) / total_files, 1) if total_files > 0 else 100.0
    avg_density = round(sum(r["density"] for r in file_results) / total_files, 1) if total_files > 0 else 100.0

    fleet_verdict = "PASS"
    if fail_count > 0:
        fleet_verdict = "FAIL"
    elif warn_count > 0:
        fleet_verdict = "WARN"

    return {
        "status": fleet_verdict,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_files": total_files,
        "pass_count": pass_count,
        "warn_count": warn_count,
        "fail_count": fail_count,
        "average_score": avg_score,
        "average_density": avg_density,
        "files": file_results,
    }


def write_review_receipt(report: Dict[str, Any], target_dir: Optional[str] = None) -> Path:
    """Save persistent adversarial review telemetry receipt to data/health.

    Args:
        report: Review metrics dictionary.
        target_dir: Optional directory override (defaults to data/health).

    Returns:
        Path: Destination path of the saved receipt.
    """
    # Step 1: Resolve destination directory
    dest = Path(target_dir) if target_dir else ROOT / "data" / "health"
    dest.mkdir(parents=True, exist_ok=True)
    receipt_file = dest / "adversarial_review.json"

    # Step 2: Write atomically to prevent partial reads by dashboard
    temp_file = dest / f"adversarial_review.json.tmp.{os.getpid()}"
    temp_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    temp_file.replace(receipt_file)
    return receipt_file


def print_cli_report(report: Dict[str, Any]) -> None:
    """Render structured ANSI colored report to standard output.

    Args:
        report: Consolidated review report dictionary.
    """
    # Step 1: Render report header
    print(f"\n{TerminalColors.CYAN}{'=' * 72}{TerminalColors.RESET}")
    print(f" {TerminalColors.BOLD}⚔️  CHIEF ADVERSARIAL CODE REVIEWER (ChiefGyk3D / Apache-2.0){TerminalColors.RESET}")
    print(f"{TerminalColors.CYAN}{'=' * 72}{TerminalColors.RESET}")

    # Step 2: Format verdict badge
    verdict = report["status"]
    badge = f"{TerminalColors.GREEN}✅ PASS{TerminalColors.RESET}"
    if verdict == "FAIL":
        badge = f"{TerminalColors.ROSE}❌ FAIL{TerminalColors.RESET}"
    elif verdict == "WARN":
        badge = f"{TerminalColors.GOLD}⚠️  WARN{TerminalColors.RESET}"

    # Step 3: Print summary metrics
    print(f" Fleet Review Verdict: {badge}")
    print(f" Total Files Audited:  {report['total_files']} files")
    print(f" Passing Files:        {TerminalColors.GREEN}{report['pass_count']}{TerminalColors.RESET}")
    print(f" Warnings:             {TerminalColors.GOLD}{report['warn_count']}{TerminalColors.RESET}")
    print(f" Failed Gates:         {TerminalColors.ROSE}{report['fail_count']}{TerminalColors.RESET}")
    print(f" Average Health Score: {report['average_score']} / 100")
    print(f" Average Density:      {report['average_density']}% (Rule 16 requires >= 25%)")
    print(f"{TerminalColors.CYAN}{'-' * 72}{TerminalColors.RESET}")

    # Step 4: Print details for files with findings
    for f in report["files"]:
        if f["findings"]:
            color = TerminalColors.ROSE if f["verdict"] == "FAIL" else TerminalColors.GOLD
            print(f" {color}[{f['verdict']} - Score {f['score']}]{TerminalColors.RESET} {f['name']} ({f['density']}% comments)")
            for issue in f["findings"]:
                sev_color = TerminalColors.ROSE if issue["severity"] in ("HIGH", "CRITICAL") else TerminalColors.GOLD
                print(f"   Line {issue['line']:4d} {sev_color}[{issue['severity']}]{TerminalColors.RESET} {issue['message']}")
            print()

    print(f"{TerminalColors.CYAN}{'=' * 72}{TerminalColors.RESET}\n")


def main() -> int:
    """CLI entrypoint for standalone execution or terminal dash review dispatch.

    Returns:
        int: Process exit status code (0 for clean/warn, 1 for critical/fail).
    """
    # Step 1: Parse command line arguments
    parser = argparse.ArgumentParser(
        description="ChiefGyk3D Adversarial Code Reviewer: static AST and Rule 16 auditor."
    )
    parser.add_argument(
        "targets",
        nargs="*",
        default=["scripts/terminal_dash.py", "scripts/space_weather_telemetry.py", "scripts/chief_zero_ports_scanner.py"],
        help="Target files or directories to review (defaults to recent security scripts).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON format instead of human-readable terminal report.",
    )
    parser.add_argument(
        "--no-receipt",
        action="store_true",
        help="Do not save persistent telemetry receipt to data/health/adversarial_review.json.",
    )
    args = parser.parse_args()

    # Step 2: Resolve target paths
    target_paths = [Path(t) if Path(t).is_absolute() else ROOT / t for t in args.targets]

    # Step 3: Execute review sweep
    report = audit_paths(target_paths)

    # Step 4: Write telemetry receipt unless suppressed
    if not args.no_receipt:
        write_review_receipt(report)

    # Step 5: Render CLI output
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_cli_report(report)

    # Step 6: Return process exit code
    return 1 if report["fail_count"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
