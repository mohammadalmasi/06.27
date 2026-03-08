# How the Static SQL Injection Scanner Works (Step by Step)

This document explains how the **static** SQL injection scanner finds vulnerabilities using **taint analysis** on the Python AST. It does not use ML; it uses a generic taint + sink analyzer.

---

## Example source code

```python
def vulnerable_sql_high_1():
    """Direct string concatenation in SELECT"""
    user_id = request.form["user_id"]
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
```

---

## Overview

The static scanner:

1. Parses the source code into a **Python AST** (abstract syntax tree).
2. Uses a **TaintAnalyzer** configured with **taint sources** (where user input enters) and **sinks** (where SQL is executed).
3. Collects all assignments and all sink calls.
4. Computes which variable names are **tainted** (may hold user input) by a fixpoint over assignments.
5. For each sink call, checks if the argument that becomes the SQL string is tainted; if yes, reports a vulnerability.

So: **if untrusted data can flow into a call like `cursor.execute(...)` or `.raw(...)`, the scanner reports SQL injection.**

---

## Step 1: Parse source to AST

The scanner calls `ast.parse(source_code)` and gets a tree of AST nodes (functions, assignments, calls, etc.). No tokenization for ML—just the standard Python AST.

---

## Step 2: Create the taint analyzer

`StaticSqlInjectionScanner` builds a `TaintAnalyzer` (from `scanners.taint_analyzer`) with:

**Taint sources** (where untrusted data is considered to enter):

- **Request-like names:** `request`, `req`, `flask_request`, `environ`
- **Attributes on those:** `args`, `form`, `cookies`, `headers`, `json`, `data`, `values`, `get`, `getlist`, `get_json`, `get_data`
- **Standalone call:** `input(...)` (name `"input"`)

So for example:

- `request.form["user_id"]` → taint source
- `request.args.get("name")` → taint source
- `input()` → taint source

**Sinks** (dangerous operations that use a string as SQL):

- **Attribute sinks:** `execute`, `executemany`, `raw` (e.g. `cursor.execute(query)`, `cursor.raw(query)`)
- **Name sink:** `text` (e.g. `text("SELECT ...")` in SQLAlchemy-style)

The analyzer is told that the **first argument** (index 0) of these calls is the one that must not be tainted (the SQL string).

---

## Step 3: Collect assignments and sink calls

The analyzer walks the AST and:

1. **Assignments:** For each `x = ...` or `x += ...`, it records `(line, [target names], value expression)`.
   - Example: `user_id = request.form["user_id"]` → line 2, targets `["user_id"]`, value = the `request.form["user_id"]` node.
   - Example: `query = "SELECT ..." + user_id + "..."` → line 4, targets `["query"]`, value = the BinOp (string + user_id + string).

2. **Sink calls:** For each call like `cursor.execute(...)` or `text(...)`, it records `(line, call_node, arg_index=0)`.
   - Example: `cursor.execute(query)` → line 5, the Call node, and we care about argument 0 (the `query` expression).

So after this step we have:

- A list of assignments: who gets what value.
- A list of sink calls: where the “SQL” argument is used.

---

## Step 4: Compute tainted variables (fixpoint)

The analyzer determines which **variable names** may hold tainted (untrusted) data:

- Any expression that is a **taint source** (e.g. `request.form["user_id"]`) is tainted.
- If an expression is tainted, any variable assigned from it becomes tainted (e.g. `user_id`).
- If an expression uses `+` (string concatenation) or f-strings and any operand is tainted, the whole expression is tainted.
- So any variable assigned from that is tainted (e.g. `query = "..." + user_id + "..."` → `query` is tainted).

The algorithm runs a **fixpoint**: repeatedly sweep over all assignments; if the right-hand side is tainted, mark the left-hand side names as tainted. Stop when nothing new becomes tainted.

For our example:

1. `user_id = request.form["user_id"]` → RHS is a taint source → **user_id** is tainted.
2. `query = "SELECT ..." + user_id + "..."` → RHS is tainted (user_id is tainted) → **query** is tainted.

So at the end: `user_id` and `query` are in the tainted set.

---

## Step 5: Report tainted sinks

For each recorded sink call, the analyzer:

1. Takes the argument at the sink arg index (0): e.g. the `query` in `cursor.execute(query)`.
2. Checks if that **expression** is tainted. For a simple name like `query`, that means: is the name `query` in the tainted set?
3. If yes, it calls the **vulnerability factory** and appends one vulnerability to the result.

The factory (in the static SQL scanner) produces a dict with:

- `line_number`, `vulnerability_type`: `"sql_injection"`, `description`, `severity`: `"high"`, `code_snippet` (unparsed line), `remediation`, `confidence`, `file_path`, CWE/OWASP refs, etc.

So for our example:

- Sink: `cursor.execute(query)` at line 5, argument 0 = `query`.
- `query` is tainted → **one vulnerability** at line 5, e.g. description: *"Tainted data (user input) flows to SQL sink (execute) - SQL injection risk"*.

---

## Step 6: Return value

- **scan_source** (and **scan_file** / **scan_url**) return a dict:  
  `{"vulnerabilities": [...], "source_name": "..."}`.

- **scan_code_content** uses that and builds the full API result: summary counts, `lines_to_highlight`, `highlighted_code` (HTML-escaped), etc.

No deduplication step is needed: each sink is visited once, and we report at most one finding per sink call where the SQL argument is tainted.

---

## Short summary for the example code

| Step | What happens |
|------|----------------|
| 1 | Source → Python AST. |
| 2 | TaintAnalyzer created with request/form/args/… as sources, execute/executemany/raw/text as sinks. |
| 3 | Collect assignments (e.g. user_id, query) and sink calls (cursor.execute(query)). |
| 4 | Fixpoint: user_id tainted (from request.form); query tainted (from string + user_id). |
| 5 | cursor.execute(query): arg 0 is query → tainted → report one vulnerability at line 5. |
| 6 | Return `{ "vulnerabilities": [ {...} ], "source_name": "..." }`. |

**In one sentence:** The static scanner finds variables that depend on user input (taint) and reports a vulnerability whenever such data is passed into an SQL execution sink (e.g. `cursor.execute`).

---

## Modes and entry points

- **scan_source(code, source_name)** — scan a string of Python code (e.g. mode `"0"` in the CLI).
- **scan_file(path)** — read file and scan (mode `"1"`).
- **scan_url(url)** — fetch URL (GitHub raw supported) and scan (mode `"2"`).
- **scan_code_content(code, source_name)** — same as scan_source but returns the full API-shaped dict (summary, lines_to_highlight, highlighted_code, etc.) used by the web API.

---

## Word report highlighting

For Word export, the scanner also has **highlight_word(code)** (and **highlight_sql_injection_vulnerabilities_word**), which uses **regex patterns** to mark suspicious snippets in the code (e.g. `.execute(` with string concatenation, `request.args.get`, f-strings in SQL, etc.). That is for display only; the actual findings come from the taint analysis above.
