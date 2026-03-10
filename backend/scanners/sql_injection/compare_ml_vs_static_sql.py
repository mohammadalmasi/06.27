import ast
import csv
from dataclasses import dataclass
from pathlib import Path
from typing import List

from scanners.sql_injection.ml_sql_injection_scanner import MLSQLInjectionDetector
from scanners.sql_injection.static_sql_injection_scanner import StaticSqlInjectionScanner


DATASET_PATH = Path(__file__).resolve().parent / "sql_injection_dataset.py"


@dataclass
class FuncInfo:
    name: str
    start: int
    end: int
    is_vulnerable: bool
    ml_hit: bool = False
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


def _map_hits_to_functions(funcs: List[FuncInfo], hits: list, attr: str) -> None:
    for hit in hits:
        line_number = hit.get("line_number")
        if line_number is None:
            continue
        for fn in funcs:
            if fn.start <= line_number <= fn.end:
                setattr(fn, attr, True)
                break


def _summarize(label: str, funcs: List[FuncInfo], attr: str) -> None:
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

    print(
        f"\n=== {label} ===\n"
        f"TP={tp}, FP={fp}, FN={fn}, TN={tn}, total={len(funcs)}\n"
        f"Precision={precision:.3f}, Recall={recall:.3f}, Accuracy={accuracy:.3f}"
    )


def _write_csv(funcs: List[FuncInfo], path: Path) -> None:
    fieldnames = [
        "function",
        "start_line",
        "end_line",
        "ground_truth_vulnerable",
        "ml_hit",
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
                    "ml_hit": int(fn.ml_hit),
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

    # ML scanner
    print("\nRunning ML SQL injection detector...")
    detector = MLSQLInjectionDetector(verbose=False)
    ml_results = detector.scan_file(str(DATASET_PATH))
    # ml_results is a list of dicts with "line_number"
    ml_hits = [v for v in ml_results if v.get("line_number") is not None]
    _map_hits_to_functions(funcs, ml_hits, "ml_hit")

    # Static scanner
    print("\nRunning static SQL injection detector...")
    static_scanner = StaticSqlInjectionScanner()
    static_result = static_scanner.scan_file(str(DATASET_PATH))
    static_hits = [
        v for v in static_result.get("vulnerabilities", []) if v.get("line_number") is not None
    ]
    _map_hits_to_functions(funcs, static_hits, "static_hit")

    # Per-function report
    print("\nPer-function results (1 = hit, 0 = no hit):")
    for f in funcs:
        gt = 1 if f.is_vulnerable else 0
        print(
            f"  {f.name:25} "
            f"GT={gt}  ML={int(f.ml_hit)}  Static={int(f.static_hit)}"
        )

    # Summaries
    _summarize("ML SQL detector", funcs, "ml_hit")
    _summarize("Static SQL detector", funcs, "static_hit")

    out_dir = Path(__file__).resolve().parent
    csv_path = out_dir / "comparison_ml_vs_static_sql.csv"
    _write_csv(funcs, csv_path)

    print(f"\nWrote CSV per-function results to: {csv_path}")


if __name__ == "__main__":
    main()

# cd /Users/mohammadalmasi/thesis/06.27/backend
# python scanners/sql_injection/compare_ml_vs_static_sql.py