# How the CSRF Static Scanner Works

This document explains why Cross-Site Request Forgery (CSRF) scanning requires a **custom AST (Abstract Syntax Tree) Visitor** instead of the generic **Taint Analyzer** that we use for SQL Injection, XSS, and Command Injection.

---

## 1. How the Generic Taint Analyzer Works (SQLi, XSS, Command Injection)

For most vulnerabilities, we use "Taint Analysis". Taint analysis tracks the flow of untrusted user data (the **Source**) through the code until it hits a dangerous function (the **Sink**). 

If tainted data touches a sink without being sanitized, the scanner flags it as a vulnerability.

**Example: SQL Injection (Taint Tracking works perfectly here)**
```python
def get_user():
    # 1. SOURCE: user_id is tainted because it comes from request.args
    user_id = request.args.get("id") 
    
    # 2. DATA FLOW: query is now also tainted
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    # 3. SINK: execute() is a known dangerous sink. 
    # Because 'query' is tainted, this is flagged as SQL Injection!
    cursor.execute(query) 
```
In this scenario, the generic `TaintAnalyzer` is highly effective because it simply maps variables from Source -> Sink.

---

## 2. Why Taint Analysis is Impossible for CSRF

CSRF vulnerabilities are **fundamentally different** from injection attacks. There is no "untrusted user input" flowing into a "dangerous function".

Instead, CSRF vulnerabilities are caused by **Configuration Flaws** and **Architectural Mistakes**.

### Scenario A: Disabling CSRF Protections
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

### Scenario B: State Changes on a GET Request
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

---

## 3. How the Custom CSRF AST Visitor Solves This

To catch CSRF flaws, we wrote a custom AST (Abstract Syntax Tree) Visitor in `StaticCSRFScanner`. An AST visitor reads the Python code as a structural tree rather than tracking variable data flows.

When the scanner reads a function definition (`visit_FunctionDef`), it performs two specific checks:

### Check 1: Decorator Analysis
It looks at the decorators attached to the function.
```python
for dec in node.decorator_list:
    if isinstance(dec, ast.Name):
        # If the decorator is named 'csrf_exempt' or 'disable_csrf', flag it!
        if dec.id in ('csrf_exempt', 'disable_csrf'):
            self.vulnerabilities.append(...)
```

### Check 2: Context-Aware State Change Analysis
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

### Summary
- **SQLi, XSS, Command Injection:** Taint Analysis (Tracking bad data to bad functions).
- **CSRF:** Structural AST Analysis (Finding bad configurations and bad architectural patterns).