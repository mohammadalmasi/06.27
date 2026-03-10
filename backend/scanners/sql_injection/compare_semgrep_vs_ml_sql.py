import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List

from ml_sql_injection_scanner import MLSQLInjectionDetector


DATASET_PATH = Path(__file__).resolve().parent / "sql_injection_dataset.py"
SEMGREP_CONFIG = Path(__file__).resolve().parent / "semgrep_sql_injection.yml"


@dataclass
class FuncInfo:
    name: str
    start: int
    end: int
    is_vulnerable: bool
    semgrep_hit: bool = False
    ml_hit: bool = False


def _load_functions(path: Path) -> List[FuncInfo]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))

    funcs: List[FuncInfo] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            start = node.lineno
            end = getattr(node, "end_lineno", node.lineno)
            # In this dataset, vulnerable functions are named like "vulnerable_codeX"
            # and safe functions are named like "safe_codeX".
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


def _run_ml_scanner(path: Path, detector: MLSQLInjectionDetector) -> list:
    source = path.read_text(encoding="utf-8")
    vulnerabilities = detector.scan_source(source, source_name=str(path))
    return vulnerabilities


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


def _write_markdown(funcs: List[FuncInfo], path: Path) -> None:
    """
    Write per-function comparison results as a Markdown table.
    """
    lines: List[str] = []
    lines.append("| Function | Start line | End line | Ground truth vulnerable | Semgrep hit | ML hit |")
    lines.append("|---------|------------|----------|-------------------------|------------|--------|")
    for fn in funcs:
        gt = "1" if fn.is_vulnerable else "0"
        semgrep_val = "1" if fn.semgrep_hit else "0"
        ml_val = "1" if fn.ml_hit else "0"
        lines.append(
            f"| {fn.name} | {fn.start} | {fn.end} | {gt} | {semgrep_val} | {ml_val} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


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

    # Run ML SQL injection detector
    print("\nRunning ML SQL injection detector...")
    detector = MLSQLInjectionDetector(verbose=False)
    ml_results = _run_ml_scanner(DATASET_PATH, detector)
    ml_hits = [
        {"start": {"line": v.get("line_number")}}
        for v in ml_results
        if v.get("line_number") is not None
    ]
    _map_hits_to_functions(funcs, ml_hits, "ml_hit")

    # Per-function report
    print("\nPer-function results (1 = hit, 0 = no hit):")
    for f in funcs:
        gt = 1 if f.is_vulnerable else 0
        print(
            f"  {f.name:25} "
            f"GT={gt}  Semgrep={int(f.semgrep_hit)}  ML={int(f.ml_hit)}"
        )

    # Summaries
    _summarize("Semgrep", funcs, "semgrep_hit")
    _summarize("ML SQL detector", funcs, "ml_hit")

    # Export artifacts next to this script
    out_dir = Path(__file__).resolve().parent
    md_path = out_dir / "comparison_semgrep_vs_ml_sql.md"

    _write_markdown(funcs, md_path)

    print(f"\nWrote Markdown per-function results to: {md_path}")


if __name__ == "__main__":
    main()

# cd /Users/mohammadalmasi/thesis/06.27/backend
# python scanners/sql_injection/compare_semgrep_vs_ml_sql.py