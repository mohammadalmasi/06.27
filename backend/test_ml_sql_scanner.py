#!/usr/bin/env python3
# =============================================================================
# Test runner for ML SQL Injection Scanner
# =============================================================================
# Run from backend directory:
#   python test_ml_sql_scanner.py
#   python test_ml_sql_scanner.py test_sql_injection_vulnerabilities.py
#   python test_ml_sql_scanner.py --verbose
# =============================================================================

import os
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
VENV_PYTHON = BACKEND_DIR / "venv" / "bin" / "python3"

# If numpy is missing, re-run with venv Python so "python3 test_ml_sql_scanner.py" works without activating
if not getattr(sys, "_ml_scanner_reexec", False):
    try:
        import numpy  # noqa: F401
    except ModuleNotFoundError:
        if VENV_PYTHON.is_file():
            os.chdir(BACKEND_DIR)
            # Pass only real user args (strip script path so "python3 test_ml_sql_scanner.py" doesn't scan itself)
            script_path = Path(__file__).resolve()
            user_args = [a for a in sys.argv[1:] if Path(a).resolve() != script_path and a != __file__]
            os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), __file__] + user_args)
        print("numpy not found. Activate the venv first: source venv/bin/activate", file=sys.stderr)
        print("Or install deps: pip install -r requirements.txt", file=sys.stderr)
        sys.exit(1)

sys._ml_scanner_reexec = True

import json

# Ensure backend is on path so scanners and models resolve
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
os.chdir(BACKEND_DIR)

from scanners.sql_injection.ml_sql_injection_scanner import (
    MLSQLInjectionDetector,
    scan_code_content_for_sql_injection_ml,
)


def test_with_file(file_path: str, verbose: bool = False) -> None:
    """Run ML scanner on a file and print results."""
    path = Path(file_path)
    if not path.is_file():
        print(json.dumps({"error": f"File not found: {file_path}"}, indent=2))
        return
    detector = MLSQLInjectionDetector(verbose=verbose)
    vulns = detector.scan_file(str(path))
    out = {
        "file": str(path),
        "vulnerabilities_found": len(vulns),
        "vulnerabilities": [
            {
                "line_number": v.line_number,
                "description": v.description,
                "severity": v.severity,
                "confidence": v.confidence,
                "code_snippet": (v.code_snippet or "")[:80],
            }
            for v in vulns
        ],
    }
    print(json.dumps(out, indent=2))


def test_with_string(code: str, source_name: str = "inline", verbose: bool = False) -> None:
    """Run ML scanner on a string of code (API-style)."""
    result = scan_code_content_for_sql_injection_ml(
        code_content=code,
        source_name=source_name,
        verbose=verbose,
    )
    # Remove large fields for concise debug output; keep structure
    out = {
        "source": result.get("source"),
        "scan_type": result.get("scan_type"),
        "total_vulnerabilities": result.get("total_vulnerabilities"),
        "summary": result.get("summary"),
        "vulnerabilities": [
            {
                "line_number": v.get("line_number"),
                "description": v.get("description"),
                "severity": v.get("severity"),
                "confidence": v.get("confidence"),
            }
            for v in result.get("vulnerabilities", [])
        ],
    }
    if "error" in result:
        out["error"] = result["error"]
    print(json.dumps(out, indent=2))


def main() -> None:
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    default_test_file = BACKEND_DIR / "test_sql_injection_vulnerabilities.py"

    if not args:
        # 1) Scan default test file if it exists
        if default_test_file.is_file():
            print("Scanning:", default_test_file)
            test_with_file(str(default_test_file), verbose=verbose)
        else:
            # 2) Otherwise run inline code test
            code = '''
def bad():
    user_id = request.form["user_id"]
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
'''
            print("No file given; scanning inline code.")
            test_with_string(code, source_name="inline", verbose=verbose)
    elif len(args) == 1:
        test_with_file(args[0], verbose=verbose)
    else:
        for f in args:
            print("Scanning:", f)
            test_with_file(f, verbose=verbose)
            print()


if __name__ == "__main__":
    main()
