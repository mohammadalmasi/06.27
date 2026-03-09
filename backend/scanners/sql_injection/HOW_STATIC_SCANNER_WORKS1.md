# How the Static Scanners Work

This document describes how the **static analysis** scanners work. It is suitable for inclusion in a thesis or technical report. The scanners do **not** use machine learning; instead, they rely on source code parsing techniques like **data-flow analysis** (often called *taint analysis*) for injection vulnerabilities, and **structural Abstract Syntax Tree (AST) analysis** for configuration vulnerabilities like CSRF.

---

## Part 1: Injection Vulnerabilities (Taint Analysis)

For most vulnerabilities (such as SQL Injection, Cross-Site Scripting (XSS), and Command Injection), the scanner uses "Taint Analysis". Taint analysis tracks the flow of untrusted user data (the **Source**) through the code until it hits a dangerous function (the **Sink**). 

If tainted data touches a sink without being sanitized, the scanner flags it as a vulnerability.

### 1.1 Key Terms (Short Glossary)

| Term | Meaning |
|------|--------|
| **Static analysis** | Analyzing the source code without running it. |
| **Taint / tainted data** | Data that comes from the user (or other untrusted source) and is not yet sanitized. |
| **Taint source** | A place in the code where user input is read (e.g. `request.form`, `request.args.get`, `input()`). |
| **Sink** | A place where data is executed dangerously (e.g. `cursor.execute(query)` for SQLi). |
| **Sanitizer** | A function that cleans or safely casts tainted data (e.g., `int()`, `escape()`), removing the taint. |
| **Data flow** | How values move from one variable to another through assignments and operations. |

### 1.2 Example: SQL Injection Vulnerability

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

Because **user input** flows into **the argument of `cursor.execute`**, this is a SQL injection vulnerability. The generic `TaintAnalyzer` is designed to find exactly this kind of pattern by mapping variables from Source to Sink.

### 1.3 How the Taint Analyzer Works (Step by Step)

#### Step 1: Parse the source code and build Symbol Tables

The scanner turns the Python source code into a **syntax tree** (AST: Abstract Syntax Tree). This is a structured representation of the program (assignments, function calls, etc.) that the analyzer can walk through. 

Alongside the AST, the scanner uses Python's built-in `symtable` library to build a **Symbol Table**. This is crucial for *scoping*. It allows the scanner to understand that a variable named `query` inside `Function A` is completely separate from a variable named `query` inside `Function B`. This prevents false positives where tainted data in one function incorrectly flags safe code in another function.

#### Step 2: Define "sources" and "sinks"

The analyzer is configured with two lists (using SQLi as an example):

- **Taint sources** — expressions that are treated as user input, for example:
  - `request.form`, `request.args`, `request.args.get(...)`, `request.json`, etc.
  - `input(...)`
- **Sinks** — calls that execute SQL, for example:
  - `cursor.execute(...)`, `cursor.executemany(...)`, `cursor.raw(...)`
  - In some setups, `text(...)` (e.g. SQLAlchemy)

#### Step 3: Collect assignments and sink calls (with Scope Context)

The analyzer goes through the syntax tree and records:

- **Every assignment:** e.g. `user_id = request.form["user_id"]`, `query = "SELECT ..." + user_id + "..."`. It records the variable name, its value, and **the unique scope ID** where the assignment occurred.
- **Every sink call:** e.g. `cursor.execute(query)` at line 4, also recording the scope ID.

#### Step 4: Mark which variables hold user input (taint propagation)

The analyzer determines which variables can hold **user input** within their specific scopes:

- If the right-hand side of an assignment is a **taint source** (e.g. `request.form["user_id"]`), then the variable on the left (`user_id`) is marked as **tainted** for that specific function scope.
- If the right-hand side uses **string concatenation** (`+`) or **f-strings** and any part of it is tainted within that scope, then the result is tainted.
- **Sanitization:** If a tainted variable is passed through a known safe function (e.g., `int()`, `escape()`), the analyzer removes the taint tag. This prevents false positives when data has been properly sanitized before being used.
- This is repeated over all assignments until no new variable becomes tainted (a so-called *fixpoint*).

#### Step 5: Check each sink and report vulnerabilities

For each sink call, the analyzer checks:
- Is the **argument** marked as tainted **within the current function's scope**?

If **yes**, it reports a vulnerability at that line, with a description such as: *“Tainted data (user input) flows to SQL sink (execute) – SQL injection risk.”*

#### Step 6: Return the results

The scanner returns a list of such findings (line number, description, severity, code snippet, remediation advice, etc.). The rest of the system uses this list to show results in the UI or to generate reports (e.g. Word export).

---

## Part 2: Cross-Site Request Forgery (CSRF) Analysis

While taint analysis works perfectly for injection attacks, CSRF vulnerabilities are **fundamentally different**. There is no "untrusted user input" flowing into a "dangerous function". 

Instead, CSRF vulnerabilities are caused by **Configuration Flaws** and **Architectural Mistakes**.

### 2.1 Why Taint Analysis is Impossible for CSRF

#### Scenario A: Disabling CSRF Protections
Most web frameworks (like Django) have CSRF protection enabled by default. A vulnerability occurs when a developer explicitly turns it off using a decorator.

```python
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt  # <-- THE VULNERABILITY IS HERE!
def update_password(request):
    new_pass = request.POST.get("password")
    request.user.set_password(new_pass)
    request.user.save()
```
**Why Taint Analysis Fails here:**
There is no data flowing from a source to a sink. The vulnerability is the presence of the `@csrf_exempt` decorator on the function itself. A generic taint analyzer cannot detect this because it only tracks variables.

#### Scenario B: State Changes on a GET Request
By standard web conventions, `GET` requests should only retrieve data. Frameworks typically only check for CSRF tokens on `POST`, `PUT`, `DELETE`, etc. If a developer modifies a database during a `GET` request, they bypass CSRF protections completely.

```python
@app.route('/transfer', methods=['GET']) # <-- Only allows GET
def transfer_money():
    amount = request.args.get('amount')
    user = get_current_user()
    
    user.balance -= int(amount)
    user.save() # <-- THE VULNERABILITY IS HERE! State change on a GET request.
```
**Why Taint Analysis Fails here:**
The data flow here (`amount` to `user.balance`) isn't inherently dangerous. What makes it dangerous is the **context**: calling a state-changing method (`.save()`) inside a route restricted to `GET` requests. Taint analysis does not understand HTTP verb contexts.

### 2.2 How the Custom CSRF AST Visitor Solves This

To catch CSRF flaws, the scanner uses a custom Abstract Syntax Tree (AST) Visitor. An AST visitor reads the Python code as a structural tree rather than tracking variable data flows.

When the scanner reads a function definition, it performs two specific structural checks:

#### Check 1: Decorator Analysis
It looks at the decorators attached to the function.
```python
for dec in node.decorator_list:
    if isinstance(dec, ast.Name):
        # If the decorator is named 'csrf_exempt' or 'disable_csrf', flag it!
        if dec.id in ('csrf_exempt', 'disable_csrf'):
            self.vulnerabilities.append(...)
```

#### Check 2: Context-Aware State Change Analysis
It checks the route definitions to see if the function is restricted strictly to `GET` requests. If it is, it scans the body of the function for database commits or saves.
```python
# If the route is restricted to GET:
if 'GET' in methods and 'POST' not in methods:
    has_route_get = True

# Scan the inner code of the function
if has_route_get:
    for child in ast.walk(node):
        # If we see a method call like .save(), .delete(), or .commit(), flag it!
        if isinstance(child.func, ast.Attribute) and child.func.attr in ('save', 'delete', 'update', 'commit'):
            self.vulnerabilities.append(...)
```

---

## Part 3: Running the Scanners

Both taint analyzers and AST visitors share the same API for execution:

- **Direct code (string):** `scan_source(code, source_name)` — e.g. when the user pastes code in the UI or when using CLI mode `"0"`.
- **File:** `scan_file(path)` — scan a Python file on disk (e.g. CLI mode `"1"`).
- **URL:** `scan_url(url)` — download code from a URL (e.g. a GitHub raw link) and scan it (e.g. CLI mode `"2"`).
- **Web API:** `scan_code_content(code, source_name)` — same analysis as above, but returns a full result structure (summary counts, lines to highlight, etc.) used by the web API and report generation.

---

## Part 4: Limitations and Future Work

While the current AST and `symtable`-based scanners are highly effective for intra-procedural analysis (tracking vulnerabilities within the boundaries of a single function or class) and structural checks, building a compiler-grade static analysis tool from scratch in Python carries inherent limitations. 

To scale these scanners for enterprise-grade, full-codebase analysis, future iterations of this project will involve the following architectural improvements:

### 4.1 Current Limitations
1. **Inter-procedural Analysis:** Currently, if tainted data is passed from one function into a separate helper function (e.g., `execute_query(tainted_data)`), the analyzer may lose the taint trace. Building a global Call Graph is required to track data across multiple files and function calls.
2. **External Library Reflection:** When tainted data interacts with third-party libraries or dynamic execution (e.g., `getattr()`, `eval()`), a static AST parser struggles to predict the runtime behavior, which can lead to false negatives.

### 4.2 Proposed Future Architecture: Integrating Industry-Standard Engines
Rather than rewriting a Python interpreter from scratch, the future roadmap involves delegating the heavy lifting of AST parsing and global Call Graph generation to an established static analysis engine. 

**Semgrep** is the primary candidate for this upgrade. Semgrep is an industry-standard, lightweight static analysis framework that natively understands Python's semantics, cross-file tracking, and deep taint propagation. 

By integrating Semgrep:
- The core logic of **Sources** (e.g., `request.args`), **Sinks** (e.g., `cursor.execute()`), and **Structural checks** (e.g., `@csrf_exempt`) defined in this thesis can be ported into lightweight YAML rules.
- The Python backend will execute the Semgrep CLI programmatically to perform deep, whole-codebase analysis.
- The backend will parse the structured JSON output from Semgrep to seamlessly feed into the existing frontend UI, Machine Learning pipeline, and Word reporting modules developed in this project. 

Other viable alternatives for the analysis engine include **Bandit** (the PyCQA standard pattern-matcher) or Meta’s **Pysa/Pyre** (for highly advanced, compiled data-flow tracking). Integrating these tools would allow the scanner to handle complex architectural patterns while maintaining the custom vulnerability definitions established in this research.
