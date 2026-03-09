import os
import sys
from pathlib import Path
from scanners.sql_injection.ml_sql_injection_scanner import MLSQLInjectionDetector

def run_ml_sql_scanner(file_path: str) -> None:
    path = Path(file_path)
    detector = MLSQLInjectionDetector()
    vulnerabilities = detector.scan_file(str(path))

    print(f"Total vulnerabilities: {len(vulnerabilities)}")
    for v in vulnerabilities:
        print(
            f"[line {v['line_number']}] {v.get('severity', '')} "
            f"confidence={v.get('confidence')}: {v.get('description', '')}"
        )


if __name__ == "__main__":
    file_path = os.path.join(os.path.dirname(__file__), "test_sql_injection_vulnerabilities.py")
    run_ml_sql_scanner(file_path)

# cd /Users/mohammadalmasi/thesis/06.27/backend
# venv/bin/python test_ml_sql_scanner.py test_sql_injection_vulnerabilities.py