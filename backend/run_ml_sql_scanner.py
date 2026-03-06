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
# venv/bin/python run_ml_sql_scanner.py 0 "
# ============================================================================
# SQL INJECTION VULNERABILITIES (HIGH SEVERITY)
# ============================================================================
#
# def vulnerable_sql_high_1():
#     user_id = request.form[\"user_id\"]
#     query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"
#     cursor.execute(query)
#
# def vulnerable_sql_high_2():
#     name = request.args.get(\"name\")
#     query = f\"SELECT * FROM users WHERE name = '{name}'\"
#     cursor.execute(query)
#
# ============================================================================
# SQL INJECTION VULNERABILITIES (MEDIUM SEVERITY)
# ============================================================================
#
# def vulnerable_sql_medium_1():
#     sort_column = request.args.get(\"sort\", \"name\")
#     query = \"ORDER BY \" + sort_column
#
# def vulnerable_sql_medium_2():
#     limit_value = request.form.get(\"limit\", \"10\")
#     query = \"LIMIT \" + limit_value
#
# def vulnerable_sql_medium_3():
#     comment_input = admin_user + \"' --\"
#
# ============================================================================
# SQL INJECTION VULNERABILITIES (LOW SEVERITY)
# ============================================================================
#
# def vulnerable_sql_low_1():
#     prefix_name = user_prefix + suffix
#
# def vulnerable_sql_low_2():
#     table_name = \"user_\" + table_id
# "



# Run: mode 1 → scan a file
# cd /Users/mohammadalmasi/thesis/06.27/backend
# venv/bin/python run_ml_sql_scanner.py 1 test_sql_injection_vulnerabilities.py