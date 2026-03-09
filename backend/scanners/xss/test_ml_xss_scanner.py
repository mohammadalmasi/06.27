import sys
from pathlib import Path

from ml_xss_scanner import MLXSSDetector


def _print_results(label: str, vulnerabilities: list) -> None:
    print(f"{label}")
    print(f"Total vulnerabilities: {len(vulnerabilities)}")
    for v in vulnerabilities:
        print(
            f"[line {v.line_number}] {v.severity} "
            f"confidence={v.confidence}: {v.description}"
        )


if __name__ == "__main__":
    mode = sys.argv[1]
    argument = sys.argv[2]
    detector = MLXSSDetector()

    try:
        if mode == "0":
            vulns = detector.scan_source(argument)
            _print_results("", vulns)
        elif mode == "1":
            path = Path(argument)
            vulns = detector.scan_file(str(path))
            _print_results(f"File: {path}\n", vulns)
        elif mode == "2":
            vulns = detector.scan_url(argument)
            _print_results(f"URL: {argument}\n", vulns)
        else:
            print("Unknown mode. Use 0 for source, 1 for file, 2 for URL.")
            sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


# Run: mode 0 → scan source code string
# venv/bin/python scanners/xss/test_ml_xss_scanner.py 0 "$(cat scanners/xss/xss_dataset.py)"
#
# Run: mode 1 → scan a file
# venv/bin/python scanners/xss/test_ml_xss_scanner.py 1 scanners/xss/xss_dataset.py
#
# Run: mode 2 → scan from URL (GitHub blob or raw)
# venv/bin/python scanners/xss/test_ml_xss_scanner.py 2 "https://github.com/mohammadalmasi/06.27/blob/main/backend/scanners/xss/ml_xss_scanner.py"
