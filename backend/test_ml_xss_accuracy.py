"""
Test ML XSS scanner against test_xss_vulnerabilities.py with known vulnerable lines.
Run from backend: venv/bin/python test_ml_xss_accuracy.py
"""
import sys
from pathlib import Path

# Expected vulnerable line numbers in test_xss_vulnerabilities.py (1-based)
# Line 9:  return f"<h1>Welcome {user_name}!</h1>"
# Line 14: script = f"document.getElementById('content').innerHTML = '{content}'"
# Line 19: result = eval("calculate_" + user_code)
# Line 27: user_html = "{{ user_content|safe }}"
# Line 32: safe_html = Markup(user_input)
# Line 37: search_term = URLSearchParams(window.location.search)
# Line 41: script = "$('#result').append('<div>' + data + '</div>')"
# Line 50: greeting = user_name + " welcome"
# Line 54: message_template = "Hello " + username
EXPECTED_VULNERABLE_LINES = {9, 14, 19, 27, 32, 37, 41, 50, 54}

# Allow reported line to be within this many lines of expected (window can map nearby)
LINE_TOLERANCE = 2


def _covered(expected_line: int, reported_lines: set) -> bool:
    for L in reported_lines:
        if abs(L - expected_line) <= LINE_TOLERANCE:
            return True
    return False


def main():
    test_file = Path(__file__).parent / "test_xss_vulnerabilities.py"
    if not test_file.is_file():
        print(f"Missing {test_file}")
        sys.exit(1)

    from scanners.xss.ml_xss_scanner import MLXSSDetector

    detector = MLXSSDetector(verbose=False)
    vulns = detector.scan_file(str(test_file))
    reported_lines = {v.line_number for v in vulns}

    missing = [E for E in EXPECTED_VULNERABLE_LINES if not _covered(E, reported_lines)]
    extra = reported_lines.copy()
    for E in EXPECTED_VULNERABLE_LINES:
        for L in reported_lines:
            if abs(L - E) <= LINE_TOLERANCE:
                extra.discard(L)
    for E in EXPECTED_VULNERABLE_LINES:
        for L in list(extra):
            if abs(L - E) <= LINE_TOLERANCE:
                extra.discard(L)

    recall_ok = len(missing) == 0
    n_expected = len(EXPECTED_VULNERABLE_LINES)
    n_reported = len(reported_lines)
    # Allow some extra reports (ML model has many windows; we report all relevant lines in window)
    precision_ok = n_reported <= max(n_expected + 30, 40)

    print("ML XSS accuracy test (test_xss_vulnerabilities.py)")
    print(f"  Expected vulnerable lines: {sorted(EXPECTED_VULNERABLE_LINES)}")
    print(f"  Reported lines:            {sorted(reported_lines)}")
    print(f"  Total reported:            {n_reported}")
    if missing:
        print(f"  MISSING (expected but not covered): {missing}")
    if extra:
        print(f"  EXTRA (reported, not near expected): {sorted(extra)}")
    print(f"  Recall:   {'PASS' if recall_ok else 'FAIL'} (all expected covered)")
    print(f"  Precision: {'PASS' if precision_ok else 'FAIL'} (not too many reports)")

    if recall_ok and precision_ok:
        print("Result: PASS")
        sys.exit(0)
    print("Result: FAIL")
    sys.exit(1)


if __name__ == "__main__":
    main()
