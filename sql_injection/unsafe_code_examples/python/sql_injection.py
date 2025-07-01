#!/usr/bin/env python3
"""
Comprehensive SQL Injection Vulnerable Code Examples
Python examples demonstrating various SQL injection vulnerabilities
for research, education, and security testing purposes.

This file contains various types of SQL injection vulnerabilities:
1. String concatenation vulnerabilities
2. Dynamic query construction
3. Input validation bypasses
4. Authentication bypasses
5. Data extraction techniques
6. Blind SQL injection examples
7. Time-based injection examples
8. Union-based injection examples
9. Error-based injection examples
10. Boolean-based injection examples
11. NoSQL injection examples
12. Framework-specific vulnerabilities
13. Real-world vulnerability patterns
14. Additional unsafe patterns from unsafe_code_example.py

WARNING: This code is intentionally vulnerable and should ONLY be used for:
- Educational purposes
- Security research
- Testing security tools
- Academic studies

NEVER use this code in production environments!
"""

import sqlite3
from flask import Flask, request, jsonify
import re
import time

# Optional imports - handle missing modules gracefully
try:
    import mysql.connector
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False
    print("⚠️  mysql-connector-python not installed. MySQL examples will be skipped.")

try:
    import psycopg2
    POSTGRESQL_AVAILABLE = True
except ImportError:
    POSTGRESQL_AVAILABLE = False
    print("⚠️  psycopg2 not installed. PostgreSQL examples will be skipped.")

try:
    import pymongo
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False
    print("⚠️  pymongo not installed. MongoDB examples will be skipped.")

app = Flask(__name__)

# ============================================================================
# BASIC STRING CONCATENATION VULNERABILITIES
# ============================================================================

def vulnerable_login_1():
    """Vulnerable login with string concatenation."""
    username = request.form['username']
    password = request.form['password']
    
    # VULNERABLE: Direct string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    return user is not None

def vulnerable_login_2():
    """Vulnerable login with f-string."""
    username = request.form['username']
    password = request.form['password']
    
    # VULNERABLE: F-string interpolation
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    return user is not None

def vulnerable_login_3():
    """Vulnerable login with string formatting."""
    username = request.form['username']
    password = request.form['password']
    
    # VULNERABLE: String formatting
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    return user is not None

def vulnerable_login_4():
    """Vulnerable login with .format()."""
    username = request.form['username']
    password = request.form['password']
    
    # VULNERABLE: .format() method
    query = "SELECT * FROM users WHERE username = '{}' AND password = '{}'".format(username, password)
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    return user is not None

# ============================================================================
# ADDITIONAL UNSAFE PATTERNS FROM unsafe_code_example.py
# ============================================================================

def vulnerable_function():
    """Additional vulnerable patterns from unsafe_code_example.py."""
    user_input = request.form['user_id']
    
    # VULNERABLE: String concatenation
    query = "SELECT * FROM users WHERE id = " + user_input
    
    # VULNERABLE: F-string
    query2 = f"SELECT * FROM users WHERE name = {user_input}"
    
    # VULNERABLE: String formatting
    query3 = "SELECT * FROM users WHERE email = %s" % user_input
    
    # VULNERABLE: .format()
    query4 = "SELECT * FROM users WHERE age = {}".format(user_input)
    
    # VULNERABLE: Direct execution
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_input)
    
    # VULNERABLE: INSERT with concatenation
    email = request.form.get('email', '')
    insert_query = "INSERT INTO users (name, email) VALUES (" + user_input + ", " + email + ")"
    
    # VULNERABLE: UPDATE with concatenation
    update_query = "UPDATE users SET name = " + user_input + " WHERE id = 1"
    
    # VULNERABLE: Request parameters
    search_term = request.args['search']
    query5 = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
    
    # VULNERABLE: Cookie values
    session_id = request.cookies['session']
    query6 = "SELECT * FROM sessions WHERE id = " + session_id
    
    # VULNERABLE: Input function (console input)
    try:
        user_name = input("Enter username: ")
        query7 = "SELECT * FROM users WHERE username = " + user_name
    except:
        pass  # Handle case where input() is not available in web context
    
    conn.close()
    return "Vulnerable code executed"

def vulnerable_cookie_based_query():
    """Vulnerable query using cookie values."""
    session_id = request.cookies.get('session', '')
    
    # VULNERABLE: Cookie-based injection
    query = "SELECT * FROM sessions WHERE session_id = '" + session_id + "'"
    
    conn = sqlite3.connect('sessions.db')
    cursor = conn.cursor()
    cursor.execute(query)
    session = cursor.fetchone()
    conn.close()
    
    return session

def vulnerable_header_based_query():
    """Vulnerable query using header values."""
    user_agent = request.headers.get('User-Agent', '')
    
    # VULNERABLE: Header-based injection
    query = "INSERT INTO logs (user_agent, timestamp) VALUES ('" + user_agent + "', datetime('now'))"
    
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()
    conn.close()
    
    return "Log entry created"

def vulnerable_json_based_query():
    """Vulnerable query using JSON data."""
    data = request.get_json()
    user_id = data.get('user_id', '')
    
    # VULNERABLE: JSON-based injection
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    return user

# ============================================================================
# SEARCH FUNCTIONALITY VULNERABILITIES
# ============================================================================

def vulnerable_search_1():
    """Vulnerable search with LIKE clause."""
    search_term = request.args.get('q', '')
    
    # VULNERABLE: String concatenation in LIKE
    query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
    
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()
    cursor.execute(query)
    products = cursor.fetchall()
    conn.close()
    
    return products

def vulnerable_search_2():
    """Vulnerable search with f-string."""
    search_term = request.args.get('q', '')
    
    # VULNERABLE: F-string in LIKE
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()
    cursor.execute(query)
    products = cursor.fetchall()
    conn.close()
    
    return products

# ============================================================================
# DATA MANIPULATION VULNERABILITIES
# ============================================================================

def vulnerable_insert():
    """Vulnerable INSERT statement."""
    name = request.form['name']
    email = request.form['email']
    
    # VULNERABLE: String concatenation in INSERT
    query = "INSERT INTO users (name, email) VALUES ('" + name + "', '" + email + "')"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()
    conn.close()
    
    return "User created successfully"

def vulnerable_update():
    """Vulnerable UPDATE statement."""
    user_id = request.form['id']
    new_name = request.form['name']
    
    # VULNERABLE: String concatenation in UPDATE
    query = "UPDATE users SET name = '" + new_name + "' WHERE id = " + user_id
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()
    conn.close()
    
    return "User updated successfully"

def vulnerable_delete():
    """Vulnerable DELETE statement."""
    user_id = request.form['id']
    
    # VULNERABLE: String concatenation in DELETE
    query = "DELETE FROM users WHERE id = " + user_id
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()
    conn.close()
    
    return "User deleted successfully"

# ============================================================================
# FLASK ROUTES WITH VULNERABILITIES
# ============================================================================

@app.route('/vulnerable_login', methods=['POST'])
def vulnerable_login_route():
    """Vulnerable login endpoint."""
    username = request.form['username']
    password = request.form['password']
    
    # VULNERABLE: Direct string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({"status": "success", "message": "Login successful"})
    else:
        return jsonify({"status": "error", "message": "Invalid credentials"})

@app.route('/vulnerable_search', methods=['GET'])
def vulnerable_search_route():
    """Vulnerable search endpoint."""
    search_term = request.args.get('q', '')
    
    # VULNERABLE: String concatenation in LIKE
    query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
    
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()
    cursor.execute(query)
    products = cursor.fetchall()
    conn.close()
    
    return jsonify({"products": products})

@app.route('/vulnerable_user/<user_id>', methods=['GET'])
def vulnerable_user_route(user_id):
    """Vulnerable user profile endpoint."""
    # VULNERABLE: String concatenation with path parameter
    query = "SELECT * FROM users WHERE id = " + user_id
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    return jsonify({"user": user})

@app.route('/vulnerable_cookie', methods=['GET'])
def vulnerable_cookie_route():
    """Vulnerable cookie-based endpoint."""
    return vulnerable_cookie_based_query()

@app.route('/vulnerable_header', methods=['POST'])
def vulnerable_header_route():
    """Vulnerable header-based endpoint."""
    return vulnerable_header_based_query()

@app.route('/vulnerable_json', methods=['POST'])
def vulnerable_json_route():
    """Vulnerable JSON-based endpoint."""
    return jsonify({"user": vulnerable_json_based_query()})

# ============================================================================
# ADVANCED SQL INJECTION TECHNIQUES
# ============================================================================

class AdvancedSQLInjectionExamples:
    """Advanced SQL injection techniques and examples."""
    
    def union_based_injection(self, user_input):
        """Union-based SQL injection example."""
        # VULNERABLE: Union-based injection
        query = f"SELECT id, name, email FROM users WHERE id = {user_input} UNION SELECT 1,2,3"
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        conn.close()
        
        return result
    
    def error_based_injection(self, user_input):
        """Error-based SQL injection example."""
        # VULNERABLE: Error-based injection
        query = f"SELECT * FROM users WHERE id = {user_input} AND (SELECT COUNT(*) FROM information_schema.tables) > 0"
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        try:
            cursor.execute(query)
            result = cursor.fetchall()
        except Exception as e:
            result = str(e)  # Error information leaked
        conn.close()
        
        return result
    
    def boolean_based_injection(self, user_input):
        """Boolean-based SQL injection example."""
        # VULNERABLE: Boolean-based injection
        query = f"SELECT * FROM users WHERE id = 1 AND (SELECT COUNT(*) FROM users) > {user_input}"
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        conn.close()
        
        return result
    
    def time_based_injection(self, user_input):
        """Time-based SQL injection example."""
        # VULNERABLE: Time-based injection
        query = f"SELECT * FROM users WHERE id = 1 AND (SELECT COUNT(*) FROM users WHERE id = {user_input}) > 0"
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        start_time = time.time()
        cursor.execute(query)
        execution_time = time.time() - start_time
        conn.close()
        
        return {"execution_time": execution_time}
    
    def blind_injection(self, user_input):
        """Blind SQL injection example."""
        # VULNERABLE: Blind injection
        query = f"SELECT * FROM users WHERE id = 1 AND (SELECT SUBSTRING(password,1,1) FROM users WHERE id = {user_input}) = 'a'"
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        conn.close()
        
        return len(result) > 0  # Boolean response

# ============================================================================
# DATABASE-SPECIFIC VULNERABILITIES
# ============================================================================

class DatabaseSpecificVulnerabilities:
    """Database-specific SQL injection vulnerabilities."""
    
    def mysql_vulnerabilities(self, user_input):
        """MySQL-specific vulnerabilities."""
        if not MYSQL_AVAILABLE:
            return "MySQL connector not available"
        
        # VULNERABLE: MySQL-specific injection
        query = f"SELECT * FROM users WHERE id = {user_input} OR 1=1 -- "
        
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="password",
            database="testdb"
        )
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        conn.close()
        
        return result
    
    def postgresql_vulnerabilities(self, user_input):
        """PostgreSQL-specific vulnerabilities."""
        if not POSTGRESQL_AVAILABLE:
            return "PostgreSQL connector not available"
        
        # VULNERABLE: PostgreSQL-specific injection
        query = f"SELECT * FROM users WHERE id = {user_input}; DROP TABLE users; --"
        
        conn = psycopg2.connect(
            host="localhost",
            database="testdb",
            user="postgres",
            password="password"
        )
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        conn.close()
        
        return result
    
    def sqlite_vulnerabilities(self, user_input):
        """SQLite-specific vulnerabilities."""
        # VULNERABLE: SQLite-specific injection
        query = f"SELECT * FROM users WHERE id = {user_input} UNION SELECT sqlite_version()"
        
        conn = sqlite3.connect('test.db')
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        conn.close()
        
        return result

# ============================================================================
# NO-SQL INJECTION VULNERABILITIES
# ============================================================================

class NoSQLInjectionExamples:
    """NoSQL injection vulnerable code examples."""
    
    def mongodb_vulnerable_query(self, user_input):
        """MongoDB vulnerable query."""
        if not MONGODB_AVAILABLE:
            return "MongoDB connector not available"
        
        # VULNERABLE: NoSQL injection in MongoDB
        client = pymongo.MongoClient("mongodb://localhost:27017/")
        db = client["testdb"]
        collection = db["users"]
        
        # VULNERABLE: Direct string interpolation
        query = f'{{"username": "{user_input}"}}'
        user = collection.find_one(query)
        
        return user
    
    def mongodb_vulnerable_authentication(self, username, password):
        """MongoDB vulnerable authentication."""
        if not MONGODB_AVAILABLE:
            return "MongoDB connector not available"
        
        # VULNERABLE: Authentication bypass
        client = pymongo.MongoClient("mongodb://localhost:27017/")
        db = client["testdb"]
        collection = db["users"]
        
        # VULNERABLE: Direct string interpolation
        query = f'{{"username": "{username}", "password": "{password}"}}'
        user = collection.find_one(query)
        
        return user is not None

# ============================================================================
# INPUT VALIDATION BYPASSES
# ============================================================================

class InputValidationBypasses:
    """Examples of input validation bypasses."""
    
    def bypass_simple_validation(self, user_input):
        """Bypass simple input validation."""
        # VULNERABLE: Inadequate validation
        if "'" in user_input or ";" in user_input:
            return "Invalid input"
        
        # Still vulnerable to other injection techniques
        query = f"SELECT * FROM users WHERE id = {user_input}"
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        conn.close()
        
        return result
    
    def bypass_regex_validation(self, user_input):
        """Bypass regex-based validation."""
        # VULNERABLE: Regex can be bypassed
        if not re.match(r'^[0-9]+$', user_input):
            return "Invalid input"
        
        # Still vulnerable to numeric injection
        query = f"SELECT * FROM users WHERE id = {user_input} OR 1=1"
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        conn.close()
        
        return result
    
    def bypass_whitelist_validation(self, user_input):
        """Bypass whitelist validation."""
        # VULNERABLE: Whitelist can be incomplete
        allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        
        if not all(c in allowed_chars for c in user_input):
            return "Invalid input"
        
        # Still vulnerable to case manipulation and encoding
        query = f"SELECT * FROM users WHERE name = '{user_input}'"
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        conn.close()
        
        return result

# ============================================================================
# REAL-WORLD VULNERABILITY PATTERNS
# ============================================================================

class RealWorldVulnerabilityPatterns:
    """Real-world vulnerability patterns commonly found in applications."""
    
    def ecommerce_vulnerability(self, product_id):
        """E-commerce application vulnerability."""
        # VULNERABLE: Product search with injection
        query = f"""
            SELECT p.*, c.name as category_name 
            FROM products p 
            JOIN categories c ON p.category_id = c.id 
            WHERE p.id = {product_id}
        """
        
        conn = sqlite3.connect('ecommerce.db')
        cursor = conn.cursor()
        cursor.execute(query)
        product = cursor.fetchone()
        conn.close()
        
        return product
    
    def banking_vulnerability(self, account_id):
        """Banking application vulnerability."""
        # VULNERABLE: Account balance query
        query = f"SELECT account_number, balance FROM accounts WHERE account_id = {account_id}"
        
        conn = sqlite3.connect('banking.db')
        cursor = conn.cursor()
        cursor.execute(query)
        account = cursor.fetchone()
        conn.close()
        
        return account
    
    def cms_vulnerability(self, post_id):
        """Content Management System vulnerability."""
        # VULNERABLE: Blog post retrieval
        query = f"SELECT title, content, author FROM posts WHERE id = {post_id}"
        
        conn = sqlite3.connect('cms.db')
        cursor = conn.cursor()
        cursor.execute(query)
        post = cursor.fetchone()
        conn.close()
        
        return post
    
    def api_vulnerability(self, user_id):
        """API endpoint vulnerability."""
        # VULNERABLE: REST API endpoint
        query = f"SELECT id, username, email, role FROM users WHERE id = {user_id}"
        
        conn = sqlite3.connect('api.db')
        cursor = conn.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        return user

# ============================================================================
# ADDITIONAL VULNERABLE ENDPOINTS
# ============================================================================

@app.route('/vulnerable_insert', methods=['POST'])
def vulnerable_insert_route():
    """Vulnerable insert endpoint."""
    name = request.form['name']
    email = request.form['email']
    
    # VULNERABLE: String concatenation in INSERT
    query = "INSERT INTO users (name, email) VALUES ('" + name + "', '" + email + "')"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()
    conn.close()
    
    return jsonify({"status": "success", "message": "User created"})

@app.route('/vulnerable_update', methods=['POST'])
def vulnerable_update_route():
    """Vulnerable update endpoint."""
    user_id = request.form['id']
    new_name = request.form['name']
    
    # VULNERABLE: String concatenation in UPDATE
    query = "UPDATE users SET name = '" + new_name + "' WHERE id = " + user_id
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()
    conn.close()
    
    return jsonify({"status": "success", "message": "User updated"})

@app.route('/vulnerable_delete', methods=['POST'])
def vulnerable_delete_route():
    """Vulnerable delete endpoint."""
    user_id = request.form['id']
    
    # VULNERABLE: String concatenation in DELETE
    query = "DELETE FROM users WHERE id = " + user_id
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()
    conn.close()
    
    return jsonify({"status": "success", "message": "User deleted"})

@app.route('/vulnerable_union', methods=['GET'])
def vulnerable_union_route():
    """Vulnerable union-based injection endpoint."""
    user_id = request.args.get('id', '')
    
    # VULNERABLE: Union-based injection
    query = f"SELECT id, name FROM users WHERE id = {user_id} UNION SELECT 1,2"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    
    return jsonify({"result": result})

@app.route('/vulnerable_error', methods=['GET'])
def vulnerable_error_route():
    """Vulnerable error-based injection endpoint."""
    user_id = request.args.get('id', '')
    
    # VULNERABLE: Error-based injection
    query = f"SELECT * FROM users WHERE id = {user_id} AND (SELECT COUNT(*) FROM information_schema.tables) > 0"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)})  # Error information leaked
    finally:
        conn.close()

@app.route('/vulnerable_time', methods=['GET'])
def vulnerable_time_route():
    """Vulnerable time-based injection endpoint."""
    user_id = request.args.get('id', '')
    
    # VULNERABLE: Time-based injection
    query = f"SELECT * FROM users WHERE id = 1 AND (SELECT COUNT(*) FROM users WHERE id = {user_id}) > 0"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    start_time = time.time()
    cursor.execute(query)
    execution_time = time.time() - start_time
    conn.close()
    
    return jsonify({"execution_time": execution_time})

# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    print("🚨 Starting SQL Injection Vulnerable Application...")
    print("⚠️  WARNING: This application is intentionally vulnerable!")
    print("📚 Use only for educational and research purposes.")
    print("🌐 Application will be available at: http://localhost:5001")
    print("🔍 Available vulnerable endpoints:")
    print("   POST /vulnerable_login")
    print("   GET  /vulnerable_search")
    print("   GET  /vulnerable_user/<user_id>")
    print("   POST /vulnerable_insert")
    print("   POST /vulnerable_update")
    print("   POST /vulnerable_delete")
    print("   GET  /vulnerable_union")
    print("   GET  /vulnerable_error")
    print("   GET  /vulnerable_time")
    print("   GET  /vulnerable_cookie")
    print("   POST /vulnerable_header")
    print("   POST /vulnerable_json")
    
    app.run(debug=True, host='0.0.0.0', port=5001) 