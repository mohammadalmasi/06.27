# SQL Injection Detection in Python

## How SonarQube Detects SQL Injection in Python

### 1. **Pattern-Based Detection**
SonarQube looks for these vulnerable patterns in Python:

```python
# Pattern 1: String concatenation with user input
query = "SELECT * FROM users WHERE id = " + user_id  # VULNERABLE

# Pattern 2: String formatting
query = "SELECT * FROM users WHERE name = '%s'" % user_name  # VULNERABLE

# Pattern 3: f-strings with user input
query = f"SELECT * FROM users WHERE email = '{user_email}'"  # VULNERABLE

# Pattern 4: .format() with user input
query = "SELECT * FROM users WHERE id = {}".format(user_id)  # VULNERABLE
```

### 2. **Database Library Detection**
SonarQube analyzes specific Python database libraries:

```python
# SQLite3 - vulnerable patterns
import sqlite3
cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # VULNERABLE
cursor.execute(f"SELECT * FROM users WHERE name = '{user_name}'")  # VULNERABLE

# MySQL Connector - vulnerable patterns
import mysql.connector
cursor.execute("SELECT * FROM users WHERE email = %s" % user_email)  # VULNERABLE

# PostgreSQL - vulnerable patterns
import psycopg2
cursor.execute("SELECT * FROM users WHERE id = " + str(user_id))  # VULNERABLE
```

### 3. **ORM Framework Analysis**
SonarQube checks ORM usage patterns:

```python
# SQLAlchemy - vulnerable patterns
from sqlalchemy import text
query = text("SELECT * FROM users WHERE id = " + user_id)  # VULNERABLE
session.execute(f"SELECT * FROM users WHERE name = '{user_name}'")  # VULNERABLE

# Django ORM - vulnerable patterns
from django.db import connection
with connection.cursor() as cursor:
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # VULNERABLE
```

## What Other Tools Are Doing

### 1. **Bandit (Python Security Linter)**
```bash
pip install bandit
bandit -r your_project/ -f json -o bandit-report.json
```

Bandit detects:
- `B608: hardcoded_sql_expressions`
- `B601: paramiko_calls`
- `B602: subprocess_popen_with_shell_equals_true`

### 2. **Semgrep**
```yaml
# semgrep-rules/sql-injection.yaml
rules:
  - id: python.sql-injection
    pattern: |
      cursor.execute("SELECT ... $X ...")
    message: "Potential SQL injection detected"
    severity: ERROR
```

### 3. **CodeQL (GitHub)**
```ql
import python

from SqlInjectionFlow::Configuration config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select source, sink
```

### 4. **Snyk Code**
- Real-time analysis during development
- IDE integration
- Custom rule creation

## Precise Detection Methods

### 1. **AST (Abstract Syntax Tree) Analysis**
```python
import ast

class SQLInjectionDetector(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []
    
    def visit_Call(self, node):
        # Check for cursor.execute() calls
        if (isinstance(node.func, ast.Attribute) and 
            node.func.attr == 'execute'):
            self.analyze_execute_call(node)
        self.generic_visit(node)
    
    def analyze_execute_call(self, node):
        if node.args and isinstance(node.args[0], ast.BinOp):
            # String concatenation detected
            self.vulnerabilities.append({
                'line': node.lineno,
                'type': 'string_concatenation',
                'description': 'SQL query uses string concatenation'
            })
```

### 2. **Regex-Based Detection**
```python
import re

def detect_sql_injection_patterns(code):
    patterns = [
        # String concatenation in SQL
        r'cursor\.execute\s*\(\s*["\'][^"\']*["\']\s*\+\s*\w+',
        # f-strings in SQL
        r'cursor\.execute\s*\(\s*f["\'][^"\']*["\']',
        # String formatting in SQL
        r'cursor\.execute\s*\(\s*["\'][^"\']*%[^"\']*["\']\s*%\s*\w+',
        # .format() in SQL
        r'cursor\.execute\s*\(\s*["\'][^"\']*\{[^"\']*["\']\.format\(',
    ]
    
    vulnerabilities = []
    for pattern in patterns:
        matches = re.finditer(pattern, code, re.MULTILINE)
        for match in matches:
            vulnerabilities.append({
                'line': code.count('\n', 0, match.start()) + 1,
                'pattern': pattern,
                'match': match.group()
            })
    
    return vulnerabilities
```

### 3. **Data Flow Analysis**
```python
class DataFlowAnalyzer:
    def __init__(self):
        self.sources = set()  # User input sources
        self.sinks = set()    # SQL execution points
        self.flows = []       # Data flow paths
    
    def identify_sources(self, ast_tree):
        """Identify user input sources"""
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                # Flask request parameters
                if (isinstance(node.func, ast.Attribute) and
                    node.func.attr in ['args', 'form', 'json']):
                    self.sources.add(node)
    
    def identify_sinks(self, ast_tree):
        """Identify SQL execution sinks"""
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                # Database execution methods
                if (isinstance(node.func, ast.Attribute) and
                    node.func.attr in ['execute', 'executemany']):
                    self.sinks.add(node)
```

## Practical Implementation

### 1. **Simple Detection Script**
```python
#!/usr/bin/env python3
import ast
import re
import sys
from pathlib import Path

class SQLInjectionScanner:
    def __init__(self):
        self.vulnerabilities = []
    
    def scan_file(self, file_path):
        """Scan a single Python file for SQL injection vulnerabilities"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # AST-based detection
            tree = ast.parse(content)
            self.scan_ast(tree, file_path)
            
            # Regex-based detection
            self.scan_regex(content, file_path)
            
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
    
    def scan_ast(self, tree, file_path):
        """AST-based vulnerability detection"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self.check_execute_call(node, file_path)
    
    def check_execute_call(self, node, file_path):
        """Check if execute call is vulnerable"""
        if (isinstance(node.func, ast.Attribute) and 
            node.func.attr == 'execute'):
            
            if node.args and self.is_vulnerable_sql(node.args[0]):
                self.vulnerabilities.append({
                    'file': file_path,
                    'line': node.lineno,
                    'type': 'sql_injection',
                    'description': 'SQL query uses unsafe string operations',
                    'severity': 'HIGH'
                })
    
    def is_vulnerable_sql(self, node):
        """Check if SQL node is vulnerable"""
        # Check for string concatenation
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return True
        
        # Check for f-strings
        if isinstance(node, ast.JoinedStr):
            return True
        
        # Check for string formatting
        if isinstance(node, ast.Call):
            if (isinstance(node.func, ast.Attribute) and 
                node.func.attr == 'format'):
                return True
        
        return False
    
    def scan_regex(self, content, file_path):
        """Regex-based vulnerability detection"""
        patterns = [
            (r'cursor\.execute\s*\(\s*["\'][^"\']*["\']\s*\+\s*\w+', 'String concatenation'),
            (r'cursor\.execute\s*\(\s*f["\'][^"\']*["\']', 'F-string usage'),
            (r'cursor\.execute\s*\(\s*["\'][^"\']*%[^"\']*["\']\s*%\s*\w+', 'String formatting'),
        ]
        
        for pattern, description in patterns:
            for match in re.finditer(pattern, content, re.MULTILINE):
                line_num = content.count('\n', 0, match.start()) + 1
                self.vulnerabilities.append({
                    'file': file_path,
                    'line': line_num,
                    'type': 'sql_injection',
                    'description': description,
                    'severity': 'HIGH'
                })
    
    def scan_directory(self, directory):
        """Scan all Python files in directory"""
        for py_file in Path(directory).rglob('*.py'):
            self.scan_file(py_file)
    
    def print_report(self):
        """Print vulnerability report"""
        if not self.vulnerabilities:
            print("✅ No SQL injection vulnerabilities found!")
            return
        
        print(f"🚨 Found {len(self.vulnerabilities)} SQL injection vulnerabilities:\n")
        
        for vuln in self.vulnerabilities:
            print(f"File: {vuln['file']}")
            print(f"Line: {vuln['line']}")
            print(f"Type: {vuln['type']}")
            print(f"Description: {vuln['description']}")
            print(f"Severity: {vuln['severity']}")
            print("-" * 50)

def main():
    if len(sys.argv) != 2:
        print("Usage: python sql_scanner.py <directory_or_file>")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = SQLInjectionScanner()
    
    if Path(target).is_file():
        scanner.scan_file(target)
    else:
        scanner.scan_directory(target)
    
    scanner.print_report()

if __name__ == "__main__":
    main()
```

### 2. **Usage Examples**
```bash
# Scan a single file
python sql_scanner.py app.py

# Scan entire project
python sql_scanner.py /path/to/your/project
```

## Safe Patterns (What SonarQube Accepts)

```python
# ✅ Safe: Parameterized queries
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# ✅ Safe: Named parameters
cursor.execute("SELECT * FROM users WHERE name = %(name)s", {'name': user_name})

# ✅ Safe: SQLAlchemy ORM
user = session.query(User).filter(User.id == user_id).first()

# ✅ Safe: Django ORM
user = User.objects.get(id=user_id)
```

## Key Differences Between Tools

| Tool | Detection Method | Precision | Speed | Integration |
|------|-----------------|-----------|-------|-------------|
| **SonarQube** | AST + Data Flow | High | Medium | CI/CD, IDE |
| **Bandit** | Pattern Matching | Medium | Fast | CLI, CI/CD |
| **Semgrep** | AST + Rules | High | Fast | CLI, IDE, CI/CD |
| **CodeQL** | Data Flow | Very High | Slow | GitHub |
| **Snyk** | Multiple | High | Fast | IDE, CI/CD |

## Best Practices for Detection

1. **Combine multiple approaches**: AST + Regex + Data Flow
2. **Focus on high-risk patterns**: String concatenation, f-strings, .format()
3. **Check specific libraries**: sqlite3, mysql.connector, psycopg2, SQLAlchemy
4. **Validate findings**: Reduce false positives
5. **Provide remediation**: Show safe alternatives

This approach gives you precise SQL injection detection specifically for Python, similar to what SonarQube and other tools are doing, but focused and practical for your needs. 