import ast
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import List

from ml_sql_injection_scanner import MLSQLInjectionDetector  # kept for consistency, not used here
from static_sql_injection_scanner import StaticSqlInjectionScanner


DATASET_PATH = Path(__file__).resolve().parent / "sql_injection_dataset.py"
SEMGREP_CONFIG = Path(__file__).resolve().parent / "semgrep_sql_injection.yml"


@dataclass
class FuncInfo:
    name: str
    start: int
    end: int
    is_vulnerable: bool
    semgrep_hit: bool = False
    static_hit: bool = False


def _load_functions(path: Path) -> List[FuncInfo]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))

    funcs: List[FuncInfo] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            start = node.lineno
            end = getattr(node, "end_lineno", node.lineno)
            is_vuln = node.name.startswith("vulnerable_code")
            funcs.append(
                FuncInfo(
                    name=node.name,
                    start=start,
                    end=end,
                    is_vulnerable=is_vuln,
                )
            )
    return funcs


def _run_semgrep(path: Path) -> list:
    """
    Run Semgrep on the given file and return the JSON results["results"] list.
    """
    import subprocess

    cmd = [
        "semgrep",
        "--config",
        str(SEMGREP_CONFIG),
        str(path),
        "--json",
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    if proc.returncode not in (0, 1):
        raise RuntimeError(f"Semgrep failed with code {proc.returncode}: {proc.stderr}")

    if not proc.stdout.strip():
        return []

    data = json.loads(proc.stdout)
    return data.get("results", [])


def _map_hits_to_functions(funcs: List[FuncInfo], hits: list, attr: str) -> None:
    for hit in hits:
        start_line = hit.get("start", {}).get("line")
        if start_line is None:
            continue
        for fn in funcs:
            if fn.start <= start_line <= fn.end:
                setattr(fn, attr, True)
                break


def _run_static_scanner(path: Path, scanner: StaticSqlInjectionScanner) -> list:
    source = path.read_text(encoding="utf-8")
    result = scanner.scan_source(source, source_name=str(path))
    return result.get("vulnerabilities", [])


def _summarize(label: str, funcs: List[FuncInfo], attr: str) -> dict:
    tp = fp = tn = fn = 0
    for fn_info in funcs:
        predicted = getattr(fn_info, attr)
        actual = fn_info.is_vulnerable

        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    accuracy = (tp + tn) / max(1, len(funcs))

    summary = {
        "tool": label,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "total": len(funcs),
        "precision": precision,
        "recall": recall,
        "accuracy": accuracy,
    }

    print(
        f"\n=== {label} ===\n"
        f"TP={tp}, FP={fp}, FN={fn}, TN={tn}, total={len(funcs)}\n"
        f"Precision={precision:.3f}, Recall={recall:.3f}, Accuracy={accuracy:.3f}"
    )
    return summary


def _write_csv(funcs: List[FuncInfo], path: Path) -> None:
    fieldnames = [
        "function",
        "start_line",
        "end_line",
        "ground_truth_vulnerable",
        "semgrep_hit",
        "static_hit",
    ]
    with path.open("w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for fn in funcs:
            writer.writerow(
                {
                    "function": fn.name,
                    "start_line": fn.start,
                    "end_line": fn.end,
                    "ground_truth_vulnerable": int(fn.is_vulnerable),
                    "semgrep_hit": int(fn.semgrep_hit),
                    "static_hit": int(fn.static_hit),
                }
            )


def main() -> None:
    funcs = _load_functions(DATASET_PATH)

    print(f"Loaded {len(funcs)} functions from {DATASET_PATH}")
    print("Ground truth (all vulnerabilities are treated as high severity):")
    for f in funcs:
        label = "VULN" if f.is_vulnerable else "SAFE"
        print(f"  {f.name}: {label} (lines {f.start}-{f.end})")

    # Run Semgrep
    print("\nRunning Semgrep...")
    semgrep_results = _run_semgrep(DATASET_PATH)
    _map_hits_to_functions(funcs, semgrep_results, "semgrep_hit")

    # Run static SQL injection detector
    print("\nRunning static SQL injection detector...")
    static_scanner = StaticSqlInjectionScanner()
    static_results = _run_static_scanner(DATASET_PATH, static_scanner)
    static_hits = [
        {"start": {"line": v.get("line_number")}}
        for v in static_results
        if v.get("line_number") is not None
    ]
    _map_hits_to_functions(funcs, static_hits, "static_hit")

    # Per-function report
    print("\nPer-function results (1 = hit, 0 = no hit):")
    for f in funcs:
        gt = 1 if f.is_vulnerable else 0
        print(
            f"  {f.name:25} "
            f"GT={gt}  Semgrep={int(f.semgrep_hit)}  Static={int(f.static_hit)}"
        )

    # Summaries
    _summarize("Semgrep", funcs, "semgrep_hit")
    _summarize("Static SQL detector", funcs, "static_hit")

    out_dir = Path(__file__).resolve().parent
    csv_path = out_dir / "comparison_semgrep_vs_static_sql.csv"
    _write_csv(funcs, csv_path)

    print(f"\nWrote CSV per-function results to: {csv_path}")


if __name__ == "__main__":
    main()

# cd /Users/mohammadalmasi/thesis/06.27/backend
# python scanners/sql_injection/compare_semgrep_vs_static_sql.py