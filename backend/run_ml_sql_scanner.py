import os
import sys
from pathlib import Path
from scanners.sql_injection.ml_sql_injection_scanner import MLSQLInjectionDetector

def scan_source(source_code: str) -> None:
    detector = MLSQLInjectionDetector()
    vulnerabilities = detector.scan_source(source_code)

    print(f"Total vulnerabilities: {len(vulnerabilities)}")
    for v in vulnerabilities:
        print(
            f"[line {v.line_number}] {v.severity} "
            f"confidence={v.confidence}: {v.description}"
        )

def scan_file(file_path: str) -> None:
    path = Path(file_path)
    detector = MLSQLInjectionDetector()
    vulnerabilities = detector.scan_file(str(path))

    print(f"File: {path}")
    print(f"Total vulnerabilities: {len(vulnerabilities)}")
    for v in vulnerabilities:
        print(
            f"[line {v.line_number}] {v.severity} "
            f"confidence={v.confidence}: {v.description}"
        )

if __name__ == "__main__":
    mode = sys.argv[1]
    argument = sys.argv[2]

    if mode == "0":
        scan_source(argument)
    elif mode == "1":
        scan_file(argument)
    else:
        print("Unknown mode. Use 0 for file, 1 for source code.")
        sys.exit(1)


# Run: mode 0 → scan source code string
# cd /Users/mohammadalmasi/thesis/06.27/backend
# venv/bin/python run_ml_sql_scanner.py 0 "$(cat test_sql_injection_vulnerabilities.py)"


# Run: mode 1 → scan a file
# cd /Users/mohammadalmasi/thesis/06.27/backend
# venv/bin/python run_ml_sql_scanner.py 1 test_sql_injection_vulnerabilities.py