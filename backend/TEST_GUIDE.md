# Test Guide for Enhanced SQL Injection Detection

This guide provides comprehensive source code and test files for testing the enhanced SQL injection detection system with SonarQube security standards integration.

## 📁 Test Files Overview

### 1. `test_vulnerable_code.py` - Comprehensive Test Suite
**Purpose**: Contains 30 test cases covering various SQL injection vulnerability patterns
**Coverage**:
- ✅ **24 vulnerable patterns** (should be detected)
- ✅ **3 safe patterns** (should NOT be detected)
- ✅ **3 edge cases** (complex scenarios)

**Categories**:
- Basic string concatenation vulnerabilities
- F-string interpolation vulnerabilities
- String formatting vulnerabilities (%, .format())
- INSERT/UPDATE/DELETE vulnerabilities
- Database-specific vulnerabilities (MySQL, PostgreSQL, MongoDB)
- Framework-specific vulnerabilities (Django, Flask-SQLAlchemy)
- Advanced patterns (dynamic table names, ORDER BY injection)
- Input source variations (cookies, headers, environment variables)
- NoSQL injection vulnerabilities
- Safe code examples

### 2. `simple_test.py` - Quick Verification Test
**Purpose**: Simple test to verify the enhanced detector is working correctly
**Usage**: Run this first to ensure your setup is correct

### 3. `run_tests.py` - Comprehensive Test Runner
**Purpose**: Complete test suite runner with multiple test phases
**Features**:
- File scanning tests
- Pattern-specific testing
- Result export functionality
- Security standards validation

## 🚀 How to Run Tests

### Quick Test
```bash
python3 simple_test.py
```

### Comprehensive Test Suite
```bash
python3 run_tests.py
```

### Test Individual Files
```bash
python3 -c "
from enhanced_sql_injection_detector import EnhancedSQLInjectionDetector
detector = EnhancedSQLInjectionDetector()
vulnerabilities = detector.scan_file('test_vulnerable_code.py')
print(f'Found {len(vulnerabilities)} vulnerabilities')
for vuln in vulnerabilities:
    print(f'- {vuln.description} (Line {vuln.line_number})')
"
```

## 🔍 Expected Detection Results

### High-Risk Patterns (Should Always Be Detected)
- **String Concatenation**: `query = "SELECT * FROM users WHERE id = " + user_id`
- **F-String Interpolation**: `query = f"SELECT * FROM users WHERE id = {user_id}"`
- **Percent Formatting**: `query = "SELECT * FROM users WHERE id = %s" % user_id`
- **Format Method**: `query = "SELECT * FROM users WHERE id = {}".format(user_id)`
- **Dynamic SQL Construction**: Any SQL query built with user input

### Medium-Risk Patterns (Should Be Detected)
- **SQL Execution**: `cursor.execute(query)` with dynamic queries
- **NoSQL Eval**: `db.eval(user_input)` with user input
- **Raw SQL in Frameworks**: Django's `connection.cursor().execute(query)`

### Safe Patterns (Should NOT Be Detected)
- **Parameterized Queries**: `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`
- **Static Queries**: `cursor.execute("SELECT COUNT(*) FROM users")`
- **Proper ORM Usage**: Using framework ORMs correctly

## 🛡️ Security Standards Integration

### SonarQube Rule Keys
- **python:S2077**: SQL queries vulnerable to injection attacks
- **python:S2078**: NoSQL queries vulnerable to injection attacks
- **python:S2079**: Dynamic SQL construction should be avoided

### Compliance Mappings
- **CWE**: 89 (SQL Injection), 564, 943
- **OWASP Top 10 2021**: A03:2021-Injection
- **SANS Top 25**: Rank 1 (Improper Neutralization of Special Elements)

### Severity Levels
- **CRITICAL**: High-confidence SQL injection vulnerabilities
- **MAJOR**: Medium-confidence vulnerabilities
- **LOW**: Low-confidence or potential false positives

## 📊 Sample Test Results

### Expected Output from `simple_test.py`:
```
🔍 Simple SQL Injection Detection Test
==================================================
📂 Created test file: simple_test_file.py
🔍 Scanning for vulnerabilities...
🚨 Found 5 vulnerabilities:

1. High-risk SQL injection pattern detected: string_concat
   📍 Line 11: simple_test_file.py
   🏷️  Rule: python:S2077
   🎯 Confidence: 90.0%
   🔴 Severity: CRITICAL
   📋 CWE: 89, 564, 943
   🛡️  OWASP: A03

[... additional vulnerabilities ...]

✅ Test completed successfully!
```

### Expected Output from `test_vulnerable_code.py`:
Should detect approximately **24-27 vulnerabilities** across 30 test cases.

## 🧪 Test Case Categories

### 1. String Concatenation Tests
```python
# Test Case 1: Basic concatenation
user_id = request.form['user_id']
query = "SELECT * FROM users WHERE id = " + user_id  # ← Should detect
```

### 2. F-String Tests
```python
# Test Case 4: F-string interpolation
user_id = request.form['user_id']
query = f"SELECT * FROM users WHERE id = {user_id}"  # ← Should detect
```

### 3. Format Method Tests
```python
# Test Case 7: Percent formatting
username = request.form['username']
query = "SELECT * FROM users WHERE username = '%s'" % username  # ← Should detect
```

### 4. Safe Pattern Tests
```python
# Test Case 25: Parameterized query
user_id = request.form['user_id']
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))  # ← Should NOT detect
```

## 🔧 Customizing Tests

### Add New Test Cases
1. Edit `test_vulnerable_code.py`
2. Add new test function following the pattern:
```python
def test_your_new_case():
    """Test Case N: Description - Should detect CWE-89"""
    user_input = request.form['input']
    
    # VULNERABLE: Your vulnerable code here
    query = "SELECT * FROM table WHERE col = " + user_input
    
    cursor.execute(query)
    return cursor.fetchall()
```

### Modify Test Runner
1. Edit `run_tests.py`
2. Add your test file to the `test_files` list
3. Customize the test patterns in `test_specific_patterns()`

## 📤 Export Test Results

### JSON Export
```python
detector = EnhancedSQLInjectionDetector()
vulnerabilities = detector.scan_file('test_vulnerable_code.py')
json_output = detector.export_sonarqube_format(vulnerabilities)

with open('test_results.json', 'w') as f:
    json.dump(json_output, f, indent=2)
```

### SonarQube Compatible Format
The exported JSON follows SonarQube's issue format:
```json
{
  "issues": [
    {
      "engineId": "enhanced-sql-injection-detector",
      "ruleId": "python:S2077",
      "severity": "CRITICAL",
      "type": "VULNERABILITY",
      "primaryLocation": {
        "message": "High-risk SQL injection pattern detected",
        "filePath": "test_vulnerable_code.py",
        "textRange": {
          "startLine": 30,
          "startColumn": 1,
          "endLine": 30,
          "endColumn": 50
        }
      },
      "cwe": ["89", "564", "943"],
      "owasp": ["A03"]
    }
  ]
}
```

## 🎯 Performance Benchmarks

### Expected Performance
- **Small files** (< 100 lines): < 1 second
- **Medium files** (100-1000 lines): 1-5 seconds
- **Large files** (1000+ lines): 5-30 seconds

### Optimization Tips
1. Use `pattern_based_analysis` for quick scans
2. Use `enhanced_data_flow_analysis` for thorough analysis
3. Adjust confidence thresholds based on your needs

## 🐛 Troubleshooting

### Common Issues

1. **Import Errors**:
   ```bash
   ModuleNotFoundError: No module named 'enhanced_sql_injection_detector'
   ```
   **Solution**: Ensure you're running from the correct directory

2. **Attribute Errors**:
   ```bash
   AttributeError: 'EnhancedVulnerability' object has no attribute 'message'
   ```
   **Solution**: Use `description` instead of `message`

3. **No Vulnerabilities Detected**:
   - Check if the code contains actual SQL injection patterns
   - Verify the detector is properly initialized
   - Ensure the test file contains vulnerable code

### Debug Mode
```python
detector = EnhancedSQLInjectionDetector()
detector.debug = True  # Enable debug output
vulnerabilities = detector.scan_file('your_file.py')
```

## 📚 Learning Resources

### Understanding SQL Injection
- [OWASP SQL Injection Prevention](https://owasp.org/www-project-top-ten/2017/A1_2017-Injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

### SonarQube Security Standards
- [SonarQube Security Rules](https://docs.sonarqube.org/latest/user-guide/security-rules/)
- [SonarQube Python Rules](https://rules.sonarsource.com/python/type/Vulnerability)

## 🎉 Success Criteria

Your enhanced SQL injection detector is working correctly if:

✅ **Detection**: Finds 24+ vulnerabilities in `test_vulnerable_code.py`
✅ **Accuracy**: Correctly identifies safe patterns as non-vulnerable
✅ **Standards**: Provides CWE, OWASP, and SonarQube rule mappings
✅ **Export**: Generates valid SonarQube-compatible JSON
✅ **Performance**: Completes tests in reasonable time (< 30 seconds)

## 📞 Support

If you encounter issues:
1. Check the test output for specific error messages
2. Verify all dependencies are installed
3. Ensure you're using the correct Python version (3.8+)
4. Review the attribute names in the `EnhancedVulnerability` class

Happy testing! 🚀 