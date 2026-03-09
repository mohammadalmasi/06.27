# False Positives in Static Taint Analysis

Currently, our `TaintAnalyzer` has a limitation regarding **variable scoping** which can lead to False Positives (FP) during static analysis.

## The Issue
The static analyzer tracks tainted data globally across an entire file. It uses a simple Python `set()` to remember the *names* of tainted variables:

```python
self._tainted.add(name) # Variable name is added globally!
```

This means the analyzer does not respect function boundaries or local scope.

## Example Scenario

### 1. The Vulnerable Function (Causes the taint)
In the dataset, we have a vulnerable function where untrusted data flows into a variable named `query`.
```python
def vulnerable_sql_high_1():
    user_id = request.form["user_id"]
    # 'query' is marked as tainted globally
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
```
At this point, the analyzer remembers: `"query" = TAINTED`.

### 2. The Safe Function (The False Positive)
Later in the same file, we have safe code that uses parameterized queries.
```python
def safe_sql_1():
    user_id = request.form.get("user_id")
    query = "SELECT * FROM users WHERE id = ?" # Safe string
    
    # Fails! The scanner sees 'query' and remembers it was tainted earlier
    cursor.execute(query, (user_id,))
```
Because the safe code reuses the variable name `query`, the static analyzer assumes it is still carrying the dangerous, tainted data from the first function. This results in the safe code being incorrectly flagged as a vulnerability.

## Workaround
To test safe code without triggering this bug, you must use unique variable names that have not been tainted elsewhere in the file:

```python
def safe_sql_1():
    user_id = request.form.get("user_id")
    safe_query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(safe_query, (user_id,)) # Will not be flagged
```

## Long-term Fix
To fix this permanently, the `TaintAnalyzer` AST parsing logic needs to be refactored to implement **Scope Tracking**. Variables inside `FunctionDef A` must be evaluated independently from variables inside `FunctionDef B`.