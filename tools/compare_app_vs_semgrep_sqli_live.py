import json
import sys
from pathlib import Path


def _safe_div(n: float, d: float) -> float | None:
    if d == 0:
        return None
    return n / d


def _confusion_matrix(rows: list[dict], tool_total_key: str) -> dict:
    """
    Compute TP/FP/TN/FN for a tool, where:
      - actual positive: expected_vulnerable == True
      - predicted positive: rows[*][tool_total_key] > 0
    Also compute precision/recall/f1/accuracy (as floats in [0,1] or null if undefined).
    """
    tp = fp = tn = fn = 0

    for r in rows:
        actual_pos = bool(r.get("expected_vulnerable"))
        predicted_pos = int(r.get(tool_total_key) or 0) > 0

        if actual_pos and predicted_pos:
            tp += 1
        elif actual_pos and not predicted_pos:
            fn += 1
        elif (not actual_pos) and predicted_pos:
            fp += 1
        else:
            tn += 1

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None:
        f1 = _safe_div(2 * precision * recall, precision + recall)
    accuracy = _safe_div(tp + tn, tp + tn + fp + fn)

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
    }


def _parse_semgrep_results(semgrep_report: dict, target_path: str) -> dict[int, list[dict]]:
    """
    Map dataset case id -> list of semgrep findings (check_id, message, severity, start_line).
    The scanned file contains blocks like:
      # id=<N> type=... label=... cwe=...
      def case_<N>():
        ...
    So we map findings to the nearest preceding "id=" comment/def case_N using line numbers.
    """
    results = semgrep_report.get("results") or []
    findings = [r for r in results if (r.get("path") == target_path)]
    if not findings:
        return {}

    repo_root = Path(__file__).resolve().parents[1]
    scanned_file = repo_root / target_path
    lines = scanned_file.read_text(encoding="utf-8").splitlines()

    line_to_case_id: dict[int, int] = {}
    current_id: int | None = None
    for idx, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("# id="):
            try:
                current_id = int(s.split("id=")[1].split()[0])
            except Exception:
                current_id = None
        if s.startswith("def case_"):
            try:
                current_id = int(s.split("def case_")[1].split("(")[0])
            except Exception:
                pass
        if current_id is not None:
            line_to_case_id[idx] = current_id

    by_case: dict[int, list[dict]] = {}
    for r in findings:
        start_line = int(((r.get("start") or {}).get("line")) or 1)
        case_id: int | None = None
        for l in range(start_line, 0, -1):
            if l in line_to_case_id:
                case_id = line_to_case_id[l]
                break
        if case_id is None:
            continue

        extra = r.get("extra") or {}
        by_case.setdefault(case_id, []).append(
            {
                "check_id": r.get("check_id"),
                "severity": extra.get("severity"),
                "message": extra.get("message"),
                "start_line": start_line,
            }
        )

    return by_case


def _run_app_scanner_on_dataset(dataset_items: list[dict]) -> dict[int, dict]:
    """
    Map dataset case id -> {total_vulnerabilities, high, medium, low} using the app scanner.
    """
    repo_root = Path(__file__).resolve().parents[1]
    backend_dir = str(repo_root / "backend")
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)

    from scanners.sql_injection.sql_injection_scanner import scan_code_content_for_sql_injection

    by_case: dict[int, dict] = {}
    for item in dataset_items:
        case_id = int(item.get("id"))
        code = item.get("code") or ""
        source = f"dataset/sql_injection.json#id={case_id}:{item.get('sqli_type')}"
        res = scan_code_content_for_sql_injection(code, source)
        if res.get("error"):
            by_case[case_id] = {"error": res["error"]}
            continue

        summary = res.get("summary") or {}
        by_case[case_id] = {
            "total_vulnerabilities": int(res.get("total_vulnerabilities") or 0),
            "high": int(summary.get("high") or 0),
            "medium": int(summary.get("medium") or 0),
            "low": int(summary.get("low") or 0),
        }

    return by_case


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]

    dataset_path = repo_root / "backend" / "datasets" / "sql_injection.json"
    semgrep_report_path = repo_root / "reports" / "semgrep_dataset_sql_live.json"
    semgrep_target_path = "sonar_samples/sql_injection_from_dataset.py"

    dataset_items = json.loads(dataset_path.read_text(encoding="utf-8"))
    semgrep_report = json.loads(semgrep_report_path.read_text(encoding="utf-8"))

    semgrep_by_case = _parse_semgrep_results(semgrep_report, semgrep_target_path)
    app_by_case = _run_app_scanner_on_dataset(dataset_items)

    rows: list[dict] = []
    for item in dataset_items:
        case_id = int(item.get("id"))
        label = (item.get("label") or "").strip().lower()
        expected_vulnerable = (label == "vulnerable")

        app = app_by_case.get(case_id) or {}
        app_total = int(app.get("total_vulnerabilities") or 0) if not app.get("error") else 0

        sem = semgrep_by_case.get(case_id) or []
        sem_total = len(sem)

        rows.append(
            {
                "id": case_id,
                "sqli_type": item.get("sqli_type"),
                "expected_vulnerable": expected_vulnerable,
                "app_total": app_total,
                "app_error": app.get("error"),
                "semgrep_total": sem_total,
                "semgrep_check_ids": sorted({x.get("check_id") for x in sem if x.get("check_id")}),
            }
        )

    app_metrics = _confusion_matrix(rows, "app_total")
    semgrep_metrics = _confusion_matrix(rows, "semgrep_total")

    summary = {
        "dataset_total": len(rows),
        "expected_vulnerable": sum(1 for r in rows if r["expected_vulnerable"]),
        "app_detected": sum(1 for r in rows if r["expected_vulnerable"] and (r["app_total"] > 0)),
        "app_missed": sum(1 for r in rows if r["expected_vulnerable"] and (r["app_total"] == 0)),
        "semgrep_flagged": sum(1 for r in rows if r["expected_vulnerable"] and (r["semgrep_total"] > 0)),
        "semgrep_missed": sum(1 for r in rows if r["expected_vulnerable"] and (r["semgrep_total"] == 0)),
        "app_only": [r["id"] for r in rows if r["expected_vulnerable"] and (r["app_total"] > 0) and (r["semgrep_total"] == 0)],
        "semgrep_only": [r["id"] for r in rows if r["expected_vulnerable"] and (r["app_total"] == 0) and (r["semgrep_total"] > 0)],
        "both": [r["id"] for r in rows if r["expected_vulnerable"] and (r["app_total"] > 0) and (r["semgrep_total"] > 0)],
        "neither": [r["id"] for r in rows if r["expected_vulnerable"] and (r["app_total"] == 0) and (r["semgrep_total"] == 0)],
        "metrics": {
            "app": app_metrics,
            "semgrep": semgrep_metrics,
        },
    }

    out = {"summary": summary, "rows": rows}

    out_path = repo_root / "reports" / "compare_app_vs_semgrep_sqli_live.json"
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()


