import argparse
import json
import random
from pathlib import Path


def _make_item(
    *,
    item_id: int,
    sqli_type: str,
    code: str,
    label: str,
    cwe: str | None,
) -> dict:
    # Keep key order consistent with existing dataset style.
    return {
        "id": item_id,
        "language": "python",
        "sqli_type": sqli_type,
        "code": code,
        "label": label,
        "cwe": cwe,
    }


def _vulnerable_templates(rng: random.Random) -> list[tuple[str, str]]:
    # Templates must be valid Python syntax (not executed), and use variable names
    # that the Semgrep dataset generator prelude defines.
    return [
        ("String Concatenation", "sql = \"SELECT * FROM users WHERE id=\" + user_id\ncursor.execute(sql)"),
        ("String Concatenation", "sql = \"SELECT * FROM users WHERE email='\" + email + \"'\"\ncursor.execute(sql)"),
        ("String Concatenation", "sql = \"SELECT * FROM sessions WHERE token='\" + token + \"'\"\ncursor.execute(sql)"),
        ("String Concatenation", "sql = \"DELETE FROM users WHERE username='\" + username + \"'\"\ncursor.execute(sql)"),
        ("String Concatenation", "sql = \"UPDATE users SET role='\" + role + \"' WHERE id=\" + user_id\ncursor.execute(sql)"),
        ("F-String Formatting", "sql = f\"SELECT * FROM users WHERE username='{username}'\"\ncursor.execute(sql)"),
        ("F-String Formatting", "sql = f\"SELECT * FROM orders WHERE order_id={order_id} AND customer='{customer}'\"\ncursor.execute(sql)"),
        ("F-String Formatting", "sql = f\"SELECT * FROM invoices WHERE amount > {min_amount}\"\ncursor.execute(sql)"),
        ("Format()", "sql = \"SELECT * FROM users WHERE username='{}'\".format(username)\ncursor.execute(sql)"),
        ("Percent Formatting", "sql = \"SELECT * FROM users WHERE username='%s'\" % username\ncursor.execute(sql)"),
        ("LIKE Concatenation", "sql = \"SELECT * FROM products WHERE name LIKE '%\" + search + \"%'\"\ncursor.execute(sql)"),
        ("IN Clause Built", "sql = \"SELECT * FROM users WHERE id IN (\" + ids_csv + \")\"\ncursor.execute(sql)"),
        ("ORDER BY Concatenation", "sql = \"SELECT * FROM users ORDER BY \" + sort_by\ncursor.execute(sql)"),
        ("LIMIT/OFFSET Concatenation", "sql = \"SELECT * FROM users LIMIT \" + limit + \" OFFSET \" + offset\ncursor.execute(sql)"),
        ("Union-based", "sql = \"SELECT name FROM products WHERE id=\" + user_input + \" UNION SELECT password FROM users\"\ncursor.execute(sql)"),
        ("Stacked Queries", "sql = \"SELECT * FROM users WHERE id=\" + user_id + \"; DROP TABLE users; --\"\ncursor.execute(sql)"),
        # A small number of “payload-pattern” cases to compare against Semgrep’s constant-pattern rule.
        ("Error-based", "sql = \"SELECT * FROM users WHERE id=1 AND (SELECT 1/0)\"\ncursor.execute(sql)"),
        ("Time-based blind", "sql = \"SELECT * FROM users WHERE id=1 AND IF(1=1,SLEEP(3),0)\"\ncursor.execute(sql)"),
        ("Time-based blind", "sql = \"SELECT * FROM users WHERE id=1 AND BENCHMARK(5000000,MD5('A'))\"\ncursor.execute(sql)"),
    ]


def _safe_templates(rng: random.Random) -> list[tuple[str, str]]:
    return [
        ("Parameterized Query (sqlite3 '?')", "sql = \"SELECT * FROM users WHERE id = ?\"\ncursor.execute(sql, (user_id,))"),
        ("Parameterized Query (sqlite3 '?')", "sql = \"SELECT * FROM users WHERE email = ?\"\ncursor.execute(sql, (email,))"),
        ("Parameterized Query (psycopg2 '%s')", "sql = \"SELECT * FROM users WHERE username = %s\"\ncursor.execute(sql, (username,))"),
        ("Named Parameters", "sql = \"SELECT * FROM users WHERE username = :username\"\ncursor.execute(sql, {\"username\": username})"),
        ("Named Parameters", "sql = \"SELECT * FROM invoices WHERE amount > :min_amount\"\ncursor.execute(sql, {\"min_amount\": min_amount})"),
        ("SQLAlchemy text() Bind", "query = text(\"SELECT * FROM users WHERE id = :user_id\")\nresult = db.execute(query, {\"user_id\": user_id})"),
        ("SQLAlchemy text() Bind", "query = text(\"SELECT * FROM products WHERE category = :category\")\nresult = db.execute(query, {\"category\": category})"),
        ("Django ORM Filter", "qs = User.objects.filter(username=username)"),
        ("Django ORM Filter", "qs = Order.objects.filter(order_id=order_id, customer=customer)"),
        ("Constant Query", "sql = \"SELECT 1\"\ncursor.execute(sql)"),
        ("Constant Query", "sql = \"SELECT * FROM users\"\ncursor.execute(sql)"),
        ("Parameterized IN Clause", "sql = \"SELECT * FROM users WHERE id IN (?, ?, ?)\"\ncursor.execute(sql, (id1, id2, id3))"),
        ("LIKE Parameterized", "sql = \"SELECT * FROM products WHERE name LIKE ?\"\ncursor.execute(sql, (\"%\" + search + \"%\",))"),
        ("LIMIT/OFFSET Parameterized", "sql = \"SELECT * FROM users LIMIT ? OFFSET ?\"\ncursor.execute(sql, (int(limit), int(offset)))"),
        ("Insert Parameterized", "sql = \"INSERT INTO audit(actor, action) VALUES(?, ?)\"\ncursor.execute(sql, (actor, action))"),
        ("Update Parameterized", "sql = \"UPDATE users SET role = ? WHERE id = ?\"\ncursor.execute(sql, (role, user_id))"),
    ]


def _vary_snippet(rng: random.Random, code: str) -> str:
    """
    Create lightweight, deterministic variety while keeping code readable and syntactically valid.
    """
    tweaks = [
        (lambda s: s),
        (lambda s: s.replace("users", "accounts", 1) if "users" in s else s),
        (lambda s: s.replace("SELECT *", "SELECT id, name", 1) if "SELECT *" in s else s),
        (lambda s: s.replace("products", "items", 1) if "products" in s else s),
        (lambda s: s.replace("orders", "purchases", 1) if "orders" in s else s),
    ]
    return rng.choice(tweaks)(code)


def main() -> None:
    parser = argparse.ArgumentParser(description="Expand SQL injection dataset to a target size.")
    parser.add_argument("--input", default="backend/datasets/sql_injection.json")
    parser.add_argument("--output", default=None)
    parser.add_argument("--total", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--balance", type=float, default=0.5, help="Fraction of dataset labeled vulnerable (0..1).")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    in_path = repo_root / args.input
    out_path = repo_root / (args.output or args.input)

    rng = random.Random(args.seed)

    data: list[dict] = json.loads(in_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Dataset must be a JSON array")

    current_total = len(data)
    if current_total > args.total:
        raise ValueError(f"Dataset already has {current_total} rows, which is > target {args.total}")

    # Count current labels.
    current_vuln = sum(1 for x in data if (x.get("label") or "").strip().lower() == "vulnerable")
    current_safe = sum(1 for x in data if (x.get("label") or "").strip().lower() == "safe")

    target_vuln = int(round(args.total * args.balance))
    target_safe = args.total - target_vuln

    add_vuln = max(0, target_vuln - current_vuln)
    add_safe = max(0, target_safe - current_safe)

    # If existing dataset is imbalanced, fill remaining rows with the minority class until total is reached.
    remaining = args.total - current_total
    if add_vuln + add_safe < remaining:
        # Put extras into whichever class is below its target.
        extra = remaining - (add_vuln + add_safe)
        if current_vuln < target_vuln:
            add_vuln += extra
        else:
            add_safe += extra
    elif add_vuln + add_safe > remaining:
        # Trim (should be rare; happens due to rounding).
        over = (add_vuln + add_safe) - remaining
        if add_safe >= over:
            add_safe -= over
        else:
            add_vuln -= (over - add_safe)
            add_safe = 0

    next_id = max(int(x.get("id")) for x in data) + 1 if data else 1

    v_templates = _vulnerable_templates(rng)
    s_templates = _safe_templates(rng)

    for _ in range(add_vuln):
        sqli_type, code = rng.choice(v_templates)
        code = _vary_snippet(rng, code)
        data.append(_make_item(item_id=next_id, sqli_type=sqli_type, code=code, label="vulnerable", cwe="CWE-89"))
        next_id += 1

    for _ in range(add_safe):
        sqli_type, code = rng.choice(s_templates)
        code = _vary_snippet(rng, code)
        data.append(_make_item(item_id=next_id, sqli_type=sqli_type, code=code, label="safe", cwe=None))
        next_id += 1

    # Write expanded dataset.
    out_path.write_text(json.dumps(data, indent=4, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(out_path), "total": len(data), "added_vulnerable": add_vuln, "added_safe": add_safe}, indent=2))


if __name__ == "__main__":
    main()


