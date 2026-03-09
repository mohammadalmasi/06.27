import sys
from pathlib import Path

from ml_command_injection_scanner import MLCommandInjectionDetector


def _print_results(label: str, vulnerabilities: list) -> None:
    print(f"{label}")
    print(f"Total vulnerabilities: {len(vulnerabilities)}")
    for v in vulnerabilities:
        print(
            f"[line {v.line_number}] {v.severity} "
            f"confidence={v.confidence}: {v.code_snippet}"
        )


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python test_ml_command_scanner.py <mode> <argument>")
        sys.exit(1)
        
    mode = sys.argv[1]
    argument = sys.argv[2]
    detector = MLCommandInjectionDetector()

    try:
        if mode == "1":
            vulns = detector.scan_source(argument)
            _print_results("", vulns)
        elif mode == "2":
            path = Path(argument)
            vulns = detector.scan_file(str(path))
            _print_results(f"File: {path}\n", vulns)
        elif mode == "3":
            vulns = detector.scan_url(argument)
            _print_results(f"URL: {argument}\n", vulns)
        else:
            print("Unknown mode. Use 1 for source, 2 for file, 3 for URL.")
            sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


# Run: mode 1 → scan source code string
# venv/bin/python scanners/command_injection/test_ml_command_scanner.py 1 "$(cat scanners/command_injection/command_dataset.py)"
#
# Run: mode 2 → scan a file
# venv/bin/python scanners/command_injection/test_ml_command_scanner.py 2 scanners/command_injection/command_dataset.py
#
# Run: mode 3 → scan from URL (GitHub blob or raw)
# venv/bin/python scanners/command_injection/test_ml_command_scanner.py 3 "https://github.com/mohammadalmasi/06.27/blob/main/backend/scanners/command_injection/ml_command_injection_scanner.py"