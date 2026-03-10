from pathlib import Path
from typing import List


DATASET_PATH = Path(__file__).resolve().parent / "sql_injection_dataset.py"
GENERATED_MARKER = "# GENERATED SQL INJECTION FUNCTIONS BELOW\n"


def _build_vulnerable_functions(count: int) -> str:
    """
    Generate 'count' vulnerable functions following the same style as
    the existing vulnerable_code* functions in sql_injection_dataset.py.
    """
    lines: List[str] = []

    concat_templates = [
        # Simple WHERE concatenation
        (
            'def {name}():\n'
            '    """Auto-generated vulnerable: direct string concatenation in WHERE clause"""\n'
            '    {user_var} = request.args.get("user_{idx}", "guest")\n'
            '    query = "SELECT * FROM users WHERE username = \'" + {user_var} + "\'"\n'
            '    cursor.execute(query)\n'
            '\n'
        ),
        # Multiple parameters
        (
            'def {name}():\n'
            '    """Auto-generated vulnerable: username and password concatenation"""\n'
            '    {user_var} = request.form.get("user_{idx}", "guest")\n'
            '    {pwd_var} = request.form.get("pwd_{idx}", "password")\n'
            '    query = (\n'
            '        "SELECT * FROM users WHERE username = \'" + {user_var} + "\' "\n'
            '        "AND password = \'" + {pwd_var} + "\'"\n'
            '    )\n'
            '    cursor.execute(query)\n'
            '\n'
        ),
        # ORDER BY / LIMIT variations
        (
            'def {name}():\n'
            '    """Auto-generated vulnerable: ORDER BY concatenation"""\n'
            '    {sort_var} = request.args.get("sort_{idx}", "name")\n'
            '    query = "SELECT * FROM users ORDER BY " + {sort_var}\n'
            '    cursor.execute(query)\n'
            '\n'
        ),
        (
            'def {name}():\n'
            '    """Auto-generated vulnerable: LIMIT concatenation"""\n'
            '    {limit_var} = request.args.get("limit_{idx}", "10")\n'
            '    query = "SELECT * FROM logs LIMIT " + {limit_var}\n'
            '    cursor.execute(query)\n'
            '\n'
        ),
        # Comment injection
        (
            'def {name}():\n'
            '    """Auto-generated vulnerable: SQL comment injection pattern"""\n'
            '    {comment_var} = request.args.get("comment_{idx}", "") + "\' --"\n'
            '    query = "SELECT * FROM logs WHERE id = \'" + {comment_var} + "\'"\n'
            '    cursor.execute(query)\n'
            '\n'
        ),
        # .format and % formatting
        (
            'def {name}():\n'
            '    """Auto-generated vulnerable: string .format() in query"""\n'
            '    {user_var} = request.args.get("user_{idx}", "guest")\n'
            '    query = "SELECT * FROM users WHERE username = \'{{}}\'".format({user_var})\n'
            '    cursor.execute(query)\n'
            '\n'
        ),
        (
            'def {name}():\n'
            '    """Auto-generated vulnerable: percent formatting in query"""\n'
            '    {item_var} = request.form.get("item_{idx}", "1")\n'
            '    query = "DELETE FROM items WHERE id = \'%s\'" % {item_var}\n'
            '    cursor.execute(query)\n'
            '\n'
        ),
    ]

    for i in range(1, count + 1):
        template = concat_templates[(i - 1) % len(concat_templates)]
        func_name = f"vulnerable_code_auto_{i}"
        lines.append(
            template.format(
                name=func_name,
                idx=i,
                user_var=f"user_{i}",
                pwd_var=f"pwd_{i}",
                sort_var=f"sort_{i}",
                limit_var=f"limit_{i}",
                comment_var=f"comment_{i}",
                item_var=f"item_{i}",
            )
        )

    return "".join(lines)


def _build_safe_functions(count: int) -> str:
    """
    Generate 'count' safe functions with parameterized queries and whitelisting,
    following the same style as the existing safe_code* functions.
    """
    lines: List[str] = []

    safe_templates = [
        (
            'def {name}():\n'
            '    """Auto-generated safe: parameterized query with ? placeholder"""\n'
            '    {user_var} = request.form.get("user_{idx}")\n'
            '    query = "SELECT * FROM users WHERE id = ?"\n'
            '    cursor.execute(query, ({user_var},))\n'
            '\n'
        ),
        (
            'def {name}():\n'
            '    """Auto-generated safe: named parameter in query"""\n'
            '    {name_var} = request.args.get("name_{idx}")\n'
            '    query = "SELECT * FROM users WHERE name = :name"\n'
            '    cursor.execute(query, {{"name": {name_var}}})\n'
            '\n'
        ),
        (
            'def {name}():\n'
            '    """Auto-generated safe: %s placeholder in query"""\n'
            '    {email_var} = request.args.get("email_{idx}")\n'
            '    query = "SELECT * FROM users WHERE email = %s"\n'
            '    cursor.execute(query, ({email_var},))\n'
            '\n'
        ),
        (
            'def {name}():\n'
            '    """Auto-generated safe: integer casting before concatenation"""\n'
            '    {id_var}_raw = request.form.get("id_{idx}")\n'
            '    try:\n'
            '        {id_var} = int({id_var}_raw)\n'
            '        query = f"SELECT * FROM users WHERE id = {{{id_var}}}"\n'
            '        cursor.execute(query)\n'
            '    except ValueError:\n'
            '        pass\n'
            '\n'
        ),
        (
            'def {name}():\n'
            '    """Auto-generated safe: table name allowlist"""\n'
            '    {type_var} = request.args.get("type_{idx}")\n'
            '    allowed = {{"users", "admins", "guests"}}\n'
            '    if {type_var} in allowed:\n'
            '        query = f"SELECT * FROM {{{type_var}}}"\n'
            '        cursor.execute(query)\n'
            '\n'
        ),
        (
            'def {name}():\n'
            '    """Auto-generated safe: named placeholder in UPDATE"""\n'
            '    {email_var} = request.form.get("email_{idx}")\n'
            '    query = "UPDATE users SET verified = 1 WHERE email = :email"\n'
            '    cursor.execute(query, {{"email": {email_var}}})\n'
            '\n'
        ),
    ]

    for i in range(1, count + 1):
        template = safe_templates[(i - 1) % len(safe_templates)]
        func_name = f"safe_code_auto_{i}"
        id_var = f"user_id_{i}"
        lines.append(
            template.format(
                name=func_name,
                idx=i,
                user_var=f"user_{i}",
                name_var=f"name_{i}",
                email_var=f"email_{i}",
                id_var=id_var,
                type_var=f"type_{i}",
            )
        )

    return "".join(lines)


def main() -> None:
    """
    Append 200 vulnerable and 200 safe auto-generated examples to sql_injection_dataset.py.
    Existing hand-written examples are kept untouched above a marker comment.
    """
    if not DATASET_PATH.is_file():
        raise FileNotFoundError(f"Dataset file not found: {DATASET_PATH}")

    original = DATASET_PATH.read_text(encoding="utf-8")

    if GENERATED_MARKER in original:
        prefix = original.split(GENERATED_MARKER, 1)[0] + GENERATED_MARKER + "\n"
    else:
        prefix = original.rstrip() + "\n\n" + GENERATED_MARKER + "\n"

    vulnerable_block = _build_vulnerable_functions(200)
    safe_block = _build_safe_functions(200)

    new_content = prefix + vulnerable_block + safe_block
    DATASET_PATH.write_text(new_content, encoding="utf-8")


if __name__ == "__main__":
    main()

