import ast
import csv
from dataclasses import dataclass
from pathlib import Path
from typing import List

from ml_xss_scanner import MLXSSDetector


DATASET_PATH = Path(__file__).resolve().parent / "xss_dataset.py"


@dataclass
class FuncInfo:
    name: str
    start: int
    end: int
    is_vulnerable: bool
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
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / max(1, len(funcs))

    print(
        f"\n=== {label} ===\n"
        f"TP={tp}, FP={fp}, FN={fn}, TN={tn}, total={len(funcs)}\n"
        f"Precision={precision:.3f}, Recall={recall:.3f}, F1={f1:.3f}, Accuracy={accuracy:.3f}"
    )


def _write_csv(funcs: List[FuncInfo], path: Path) -> None:
    fieldnames = [
        "index",
        "function",
        "start_line",
        "end_line",
        "ground_truth_vulnerable",
        "ml_hit",
    ]
    with path.open("w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for idx, fn in enumerate(funcs, start=1):
            writer.writerow(
                {
                    "index": idx,
                    "function": fn.name,
                    "start_line": fn.start,
                    "end_line": fn.end,
                    "ground_truth_vulnerable": int(fn.is_vulnerable),
                    "ml_hit": int(fn.ml_hit),
                }
            )


def main() -> None:
    funcs = _load_functions(DATASET_PATH)

    print(f"Loaded {len(funcs)} functions from {DATASET_PATH}")
    print("Ground truth (all vulnerabilities are treated as high severity):")
    for f in funcs:
        label = "VULN" if f.is_vulnerable else "SAFE"
        print(f"  {f.name}: {label} (lines {f.start}-{f.end})")

    # ML XSS scanner
    print("\nRunning ML XSS detector...")
    detector = MLXSSDetector(verbose=False)
    ml_results = detector.scan_file(str(DATASET_PATH))
    ml_hits = [v for v in ml_results if v.get("line_number") is not None]
    _map_hits_to_functions(funcs, ml_hits, "ml_hit")

    # Per-function report
    print("\nPer-function results (1 = hit, 0 = no hit):")
    for f in funcs:
        gt = 1 if f.is_vulnerable else 0
        print(
            f"  {f.name:25} "
            f"GT={gt}  ML={int(f.ml_hit)}"
        )

    # Summary
    _summarize("ML XSS detector", funcs, "ml_hit")

    out_dir = Path(__file__).resolve().parent
    csv_path = out_dir / "comparison_ml_xss.csv"
    _write_csv(funcs, csv_path)

    print(f"\nWrote CSV per-function results to: {csv_path}")


if __name__ == "__main__":
    main()

import ast
import csv
from dataclasses import dataclass
from pathlib import Path
from typing import List

from ml_xss_scanner import MLXSSDetector


DATASET_PATH = Path(__file__).resolve().parent / "xss_dataset.py"


@dataclass
class FuncInfo:
    name: str
    start: int
    end: int
    is_vulnerable: bool
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
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / max(1, len(funcs))

    print(
        f"\n=== {label} ===\n"
        f"TP={tp}, FP={fp}, FN={fn}, TN={tn}, total={len(funcs)}\n"
        f"Precision={precision:.3f}, Recall={recall:.3f}, F1={f1:.3f}, Accuracy={accuracy:.3f}"
    )


def _write_csv(funcs: List[FuncInfo], path: Path) -> None:
    fieldnames = [
        "index",
        "function",
        "start_line",
        "end_line",
        "ground_truth_vulnerable",
        "ml_hit",
    ]
    with path.open("w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for idx, fn in enumerate(funcs, start=1):
            writer.writerow(
                {
                    "index": idx,
                    "function": fn.name,
                    "start_line": fn.start,
                    "end_line": fn.end,
                    "ground_truth_vulnerable": int(fn.is_vulnerable),
                    "ml_hit": int(fn.ml_hit),
                }
            )


def main() -> None:
    funcs = _load_functions(DATASET_PATH)

    print(f"Loaded {len(funcs)} functions from {DATASET_PATH}")
    print("Ground truth (all vulnerabilities are treated as high severity):")
    for f in funcs:
        label = "VULN" if f.is_vulnerable else "SAFE"
        print(f"  {f.name}: {label} (lines {f.start}-{f.end})")

    # ML XSS scanner
    print("\nRunning ML XSS detector...")
    detector = MLXSSDetector(verbose=False)
    ml_results = detector.scan_file(str(DATASET_PATH))
    ml_hits = [v for v in ml_results if v.get("line_number") is not None]
    _map_hits_to_functions(funcs, ml_hits, "ml_hit")

    # Per-function report
    print("\nPer-function results (1 = hit, 0 = no hit):")
    for f in funcs:
        gt = 1 if f.is_vulnerable else 0
        print(
            f"  {f.name:25} "
            f"GT={gt}  ML={int(f.ml_hit)}"
        )

    # Summary
    _summarize("ML XSS detector", funcs, "ml_hit")

    out_dir = Path(__file__).resolve().parent
    csv_path = out_dir / "comparison_ml_xss.csv"
    _write_csv(funcs, csv_path)

    print(f"\nWrote CSV per-function results to: {csv_path}")


if __name__ == "__main__":
    main()

