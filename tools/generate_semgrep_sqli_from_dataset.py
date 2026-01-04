import json
from pathlib import Path


def _sanitize_var_names(code: str) -> str:
    """
    The dataset snippets use variables like user_id/name/username/user_input.
    We define them once so the generated file is valid Python.
    """
    prelude = [
        "# Auto-generated from backend/datasets/sql_injection.json for Semgrep comparison",
        "cursor = None  # placeholder for semgrep; not executed",
        "user_id = '1'",
        "name = 'test'",
        "username = 'alice'",
        "order_id = '123'",
        "user_input = '1'",
        "admin = 'admin'",
        "email = 'a@b.com'",
        "token = 'tok'",
        "start_date = '2025-01-01'",
        "role = 'user'",
        "category = 'books'",
        "status = 'active'",
        "min_amount = 10",
        "search = 'abc'",
        "ids_csv = '1,2,3'",
        "sort_by = 'name'",
        "limit = '10'",
        "offset = '0'",
        "id1 = 1",
        "id2 = 2",
        "id3 = 3",
        "customer = 'bob'",
        "actor = 'alice'",
        "action = 'login'",
        "level = 'INFO'",
        "db = None",
        "text = lambda s: s  # placeholder for SQLAlchemy text()",
        "session = None",
        "User = None",
        "Order = None",
        "",
    ]
    return "\n".join(prelude) + code


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    dataset_path = repo_root / "backend" / "datasets" / "sql_injection.json"
    out_path = repo_root / "sonar_samples" / "sql_injection_from_dataset.py"

    data = json.loads(dataset_path.read_text(encoding="utf-8"))

    blocks = []
    for item in data:
        if item.get("language") != "python":
            continue
        code = (item.get("code") or "").rstrip()
        blocks.append(
            "\n".join(
                [
                    "",
                    f"# id={item.get('id')} type={item.get('sqli_type')} label={item.get('label')} cwe={item.get('cwe')}",
                    "def case_%s():" % item.get("id"),
                    "    cursor = None  # placeholder for semgrep; not executed",
                    "    " + "\n    ".join(code.splitlines()),
                ]
            )
        )

    file_text = _sanitize_var_names("\n".join(blocks) + "\n")
    out_path.write_text(file_text, encoding="utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()


