# How the Static SQL Injection Scanner Works

This section describes how the **static analysis** SQL injection scanner works. It is suitable for inclusion in a thesis or technical report. The scanner does **not** use machine learning; it uses **data-flow analysis** (often called *taint analysis*) on the source code to find places where user input can reach the database.

---

## 1. Main Idea (In Simple Terms)

**SQL injection** happens when code builds an SQL command using **user input** (e.g. from a web form) without proper safety checks. An attacker can then change the SQL by typing special characters in the form.

The static scanner answers one question:

> **“Can any user-controlled data end up inside an SQL execution call?”**

To do that, it:

1. Finds **where user input enters** the program (e.g. `request.form["user_id"]`, `request.args.get("name")`, `input()`).
2. Finds **where SQL is executed** (e.g. `cursor.execute(...)`, `cursor.raw(...)`).
3. **Tracks how data moves** from (1) into variables and then into (2).
4. If user input can reach an SQL execution call, it **reports a vulnerability** at that line.

So: **user input** = “tainted” data; **SQL execution** = “sink”. The scanner reports when tainted data flows into a sink.

---

## 2. Key Terms (Short Glossary)

| Term | Meaning |
|------|--------|
| **Static analysis** | Analyzing the source code without running it. |
| **Taint / tainted data** | Data that comes from the user (or other untrusted source) and is not yet sanitized. |
| **Taint source** | A place in the code where user input is read (e.g. `request.form`, `request.args.get`, `input()`). |
| **Sink** | A place where a string is used as SQL (e.g. `cursor.execute(query)`). |
| **Data flow** | How values move from one variable to another through assignments and operations. |

---

## 3. Example: One Vulnerable Snippet

Consider this small Python function:

```python
def get_user():
    user_id = request.form["user_id"]           # Line 2: user input is read
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"   # Line 3: user_id is put into a string
    cursor.execute(query)                       # Line 4: that string is sent to the database
```

- **Line 2:** The program reads `user_id` from the web request. This is a **taint source**: the value is controlled by the user.
- **Line 3:** The program builds an SQL string by concatenating `user_id` into it. So the variable `query` now may contain whatever the user typed.
- **Line 4:** The program runs that string as SQL with `cursor.execute(query)`. This is a **sink**: the first argument is the SQL string.

Because **user input** flows into **the argument of `cursor.execute`**, this is a SQL injection vulnerability. The static scanner is designed to find exactly this kind of pattern.

---

## 4. How the Scanner Works (Step by Step)

### Step 1: Parse the source code

The scanner turns the Python source code into a **syntax tree** (AST: Abstract Syntax Tree). This is a structured representation of the program (assignments, function calls, etc.) that the analyzer can walk through. No execution is needed.

### Step 2: Define “sources” and “sinks”

The analyzer is configured with two lists:

- **Taint sources** — expressions that are treated as user input, for example:
  - `request.form`, `request.args`, `request.args.get(...)`, `request.json`, etc.
  - `input(...)`
- **Sinks** — calls that execute SQL, for example:
  - `cursor.execute(...)`, `cursor.executemany(...)`, `cursor.raw(...)`
  - In some setups, `text(...)` (e.g. SQLAlchemy)

For sinks, the analyzer only cares about the **first argument** of the call, because that is the SQL string.

### Step 3: Collect assignments and sink calls

The analyzer goes through the syntax tree and records:

- **Every assignment:** e.g. `user_id = request.form["user_id"]`, `query = "SELECT ..." + user_id + "..."`. So we know “which variable gets which value.”
- **Every sink call:** e.g. `cursor.execute(query)` at line 4. So we know “where the SQL string is used.”

### Step 4: Mark which variables hold user input (taint propagation)

The analyzer determines which variables can hold **user input**:

- If the right-hand side of an assignment is a **taint source** (e.g. `request.form["user_id"]`), then the variable on the left (`user_id`) is marked as **tainted**.
- If the right-hand side uses **string concatenation** (`+`) or **f-strings** and any part of it is tainted, then the result is tainted. So if `user_id` is tainted and `query = "SELECT ..." + user_id + "'"`, then `query` is also tainted.
- This is repeated over all assignments until no new variable becomes tainted (a so-called *fixpoint*).

In our example:

- `user_id` is tainted (it comes from `request.form`).
- `query` is tainted (it is built from a string plus `user_id`).

### Step 5: Check each sink and report vulnerabilities

For each sink call (e.g. `cursor.execute(query)`), the analyzer checks:

- Is the **first argument** (here, `query`) tainted?

If **yes**, it reports one SQL injection vulnerability at that line, with a description such as: *“Tainted data (user input) flows to SQL sink (execute) – SQL injection risk.”*

In our example, `query` is tainted and is passed to `cursor.execute(query)`, so the scanner reports **one vulnerability at line 4**.

### Step 6: Return the results

The scanner returns a list of such findings (line number, description, severity, code snippet, remediation advice, etc.). The rest of the system uses this list to show results in the UI or to generate reports (e.g. Word export).

---

## 5. Summary (For Your Report)

You can summarize the static SQL injection scanner as follows:

- **Goal:** Find places where **user-controlled data** can reach an **SQL execution call** (e.g. `cursor.execute`), which indicates a possible SQL injection vulnerability.
- **Method:** Static **taint analysis**: identify taint sources (user input), identify sinks (SQL execution), track data flow through assignments and string operations, and report when tainted data reaches a sink.
- **Output:** A list of vulnerabilities, each with a line number, description, severity, and remediation (e.g. “Use parameterized queries”).

This approach is **rule-based and deterministic**: it does not use machine learning, and the same code always produces the same set of reported issues (within the limits of the implemented source/sink and data-flow rules).

---

## 6. How You Can Run the Scanner

- **Direct code (string):** `scan_source(code, source_name)` — e.g. when the user pastes code in the UI or when using CLI mode `"0"`.
- **File:** `scan_file(path)` — scan a Python file on disk (e.g. CLI mode `"1"`).
- **URL:** `scan_url(url)` — download code from a URL (e.g. a GitHub raw link) and scan it (e.g. CLI mode `"2"`).
- **Web API:** `scan_code_content(code, source_name)` — same analysis as above, but returns a full result structure (summary counts, lines to highlight, etc.) used by the web API and report generation.

---

## 7. Word Report Highlighting (Optional Detail)

For the Word export, the scanner also has a separate function that uses **regular expressions** to mark suspicious patterns in the code (e.g. `.execute(` with concatenation, `request.args.get`, f-strings in SQL). That is only for **visual highlighting** in the report; the **actual vulnerabilities** are those found by the taint analysis described above.
