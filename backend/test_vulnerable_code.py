#!/usr/bin/env python3
"""
Test Vulnerable Code Examples for SQL Injection Detection
This file contains various SQL injection vulnerabilities to test the enhanced detector
with SonarQube security standards integration.

⚠️ WARNING: This code is intentionally vulnerable!
Only use for testing security tools and educational purposes.
"""

import sqlite3
import mysql.connector
import psycopg2
from flask import Flask, request, jsonify
from django.db import connection
import pymongo
import os
import sys


# ============================================================================
# 1. BASIC STRING CONCATENATION VULNERABILITIES (High Risk)
# ============================================================================

def test_basic_concatenation_1():
    """Test Case 1: Basic string concatenation - Should detect CWE-89"""
    user_id = request.form['user_id']
    
    # VULNERABLE: Direct string concatenation (python:S2077)
    query = "SELECT * FROM users WHERE id = " + user_id
    
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)  # Should trigger SQL_INJECTION_EXECUTE
    return cursor.fetchone()


def test_basic_concatenation_2():
    """Test Case 2: String concatenation with quotes - Should detect CWE-89"""
    username = request.form['username']
    password = request.form['password']
    
    # VULNERABLE: String concatenation with quotes (python:S2077)
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()


def test_multiline_concatenation():
    """Test Case 3: Multi-line concatenation - Should detect CWE-89"""
    search_term = request.args.get('q', '')
    category = request.args.get('category', '')
    
    # VULNERABLE: Multi-line string concatenation (python:S2077)
    query = "SELECT p.id, p.name, p.price " + \
            "FROM products p " + \
            "WHERE p.name LIKE '%" + search_term + "%' " + \
            "AND p.category = '" + category + "' " + \
            "ORDER BY p.price"
    
    conn = sqlite3.connect('shop.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()


# ============================================================================
# 2. F-STRING VULNERABILITIES (High Risk)
# ============================================================================

def test_fstring_vulnerability_1():
    """Test Case 4: F-string interpolation - Should detect CWE-89"""
    user_id = request.form['user_id']
    
    # VULNERABLE: F-string interpolation (python:S2079)
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()


def test_fstring_vulnerability_2():
    """Test Case 5: F-string with quotes - Should detect CWE-89"""
    email = request.form['email']
    
    # VULNERABLE: F-string with string quotes (python:S2079)
    query = f"SELECT * FROM users WHERE email = '{email}'"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()


def test_complex_fstring():
    """Test Case 6: Complex f-string query - Should detect CWE-89"""
    table_name = request.args.get('table', 'users')
    column_name = request.args.get('column', 'id')
    value = request.args.get('value', '1')
    
    # VULNERABLE: Complex f-string with multiple variables (python:S2079)
    query = f"SELECT * FROM {table_name} WHERE {column_name} = '{value}' LIMIT 10"
    
    conn = sqlite3.connect('dynamic.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()


# ============================================================================
# 3. STRING FORMATTING VULNERABILITIES (High Risk)
# ============================================================================

def test_percent_formatting_1():
    """Test Case 7: Percent formatting - Should detect CWE-89"""
    username = request.form['username']
    
    # VULNERABLE: % string formatting (python:S2079)
    query = "SELECT * FROM users WHERE username = '%s'" % username
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()


def test_percent_formatting_2():
    """Test Case 8: Multiple % formatting - Should detect CWE-89"""
    username = request.form['username']
    status = request.form['status']
    
    # VULNERABLE: Multiple % formatting (python:S2079)
    query = "SELECT * FROM users WHERE username = '%s' AND status = '%s'" % (username, status)
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()


def test_format_method():
    """Test Case 9: .format() method - Should detect CWE-89"""
    user_id = request.form['user_id']
    role = request.form['role']
    
    # VULNERABLE: .format() method (python:S2079)
    query = "SELECT * FROM users WHERE id = {} AND role = '{}'".format(user_id, role)
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()


# ============================================================================
# 4. INSERT/UPDATE/DELETE VULNERABILITIES (High Risk)
# ============================================================================

def test_vulnerable_insert():
    """Test Case 10: Vulnerable INSERT - Should detect CWE-89"""
    name = request.form['name']
    email = request.form['email']
    age = request.form['age']
    
    # VULNERABLE: INSERT with concatenation (python:S2077)
    query = "INSERT INTO users (name, email, age) VALUES ('" + name + "', '" + email + "', " + age + ")"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()
    return {"status": "user created"}


def test_vulnerable_update():
    """Test Case 11: Vulnerable UPDATE - Should detect CWE-89"""
    user_id = request.form['user_id']
    new_email = request.form['email']
    
    # VULNERABLE: UPDATE with f-string (python:S2079)
    query = f"UPDATE users SET email = '{new_email}' WHERE id = {user_id}"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()
    return {"status": "user updated"}


def test_vulnerable_delete():
    """Test Case 12: Vulnerable DELETE - Should detect CWE-89"""
    user_id = request.form['user_id']
    
    # VULNERABLE: DELETE with concatenation (python:S2077)
    query = "DELETE FROM users WHERE id = " + user_id
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()
    return {"status": "user deleted"}


# ============================================================================
# 5. DATABASE-SPECIFIC VULNERABILITIES (High Risk)
# ============================================================================

def test_mysql_vulnerability():
    """Test Case 13: MySQL-specific vulnerability - Should detect CWE-89"""
    if not hasattr(mysql, 'connector'):
        return {"error": "MySQL not available"}
    
    user_id = request.form['user_id']
    
    # VULNERABLE: MySQL with concatenation (python:S2077)
    query = "SELECT * FROM users WHERE id = " + user_id
    
    try:
        conn = mysql.connector.connect(
            host='localhost',
            database='testdb',
            user='testuser',
            password='testpass'
        )
        cursor = conn.cursor()
        cursor.execute(query)
        return cursor.fetchall()
    except:
        return {"error": "Database connection failed"}


def test_postgresql_vulnerability():
    """Test Case 14: PostgreSQL vulnerability - Should detect CWE-89"""
    email = request.form['email']
    
    # VULNERABLE: PostgreSQL with f-string (python:S2079)
    query = f"SELECT * FROM users WHERE email = '{email}'"
    
    try:
        conn = psycopg2.connect(
            host="localhost",
            database="testdb",
            user="testuser",
            password="testpass"
        )
        cursor = conn.cursor()
        cursor.execute(query)
        return cursor.fetchall()
    except:
        return {"error": "Database connection failed"}


# ============================================================================
# 6. NOSQL INJECTION VULNERABILITIES (High Risk)
# ============================================================================

def test_mongodb_vulnerability_1():
    """Test Case 15: MongoDB injection - Should detect CWE-89"""
    username = request.form['username']
    
    # VULNERABLE: NoSQL injection (python:S2078)
    client = pymongo.MongoClient('mongodb://localhost:27017/')
    db = client['testdb']
    collection = db['users']
    
    # This could allow injection like: {"$ne": null}
    result = collection.find({"username": username})
    return list(result)


def test_mongodb_vulnerability_2():
    """Test Case 16: MongoDB with eval - Should detect CWE-89"""
    user_query = request.form['query']
    
    # VULNERABLE: MongoDB with eval (python:S2078)
    client = pymongo.MongoClient('mongodb://localhost:27017/')
    db = client['testdb']
    
    # Extremely dangerous - allows arbitrary code execution
    result = db.eval(f"db.users.find({user_query})")
    return result


# ============================================================================
# 7. FRAMEWORK-SPECIFIC VULNERABILITIES (High Risk)
# ============================================================================

def test_django_raw_sql():
    """Test Case 17: Django raw SQL - Should detect CWE-89"""
    user_id = request.POST.get('user_id')
    
    # VULNERABLE: Django raw SQL (python:S2077)
    cursor = connection.cursor()
    query = "SELECT * FROM auth_user WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchall()


def test_flask_sqlalchemy_text():
    """Test Case 18: Flask-SQLAlchemy text() - Should detect CWE-89"""
    try:
        from sqlalchemy import text
        from flask_sqlalchemy import SQLAlchemy
        
        search_term = request.args.get('search', '')
        
        # VULNERABLE: SQLAlchemy text() with concatenation (python:S2077)
        query = text("SELECT * FROM products WHERE name LIKE '%" + search_term + "%'")
        
        # This would be executed with db.session.execute(query)
        return {"query": str(query)}
    except ImportError:
        return {"error": "SQLAlchemy not available"}


# ============================================================================
# 8. ADVANCED VULNERABILITY PATTERNS (High Risk)
# ============================================================================

def test_dynamic_table_name():
    """Test Case 19: Dynamic table name - Should detect CWE-89"""
    table_name = request.args.get('table', 'users')
    user_id = request.args.get('id', '1')
    
    # VULNERABLE: Dynamic table name (python:S2079)
    query = f"SELECT * FROM {table_name} WHERE id = {user_id}"
    
    conn = sqlite3.connect('dynamic.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()


def test_order_by_injection():
    """Test Case 20: ORDER BY injection - Should detect CWE-89"""
    sort_column = request.args.get('sort', 'name')
    sort_order = request.args.get('order', 'ASC')
    
    # VULNERABLE: ORDER BY injection (python:S2079)
    query = f"SELECT * FROM users ORDER BY {sort_column} {sort_order}"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()


def test_union_injection():
    """Test Case 21: UNION injection setup - Should detect CWE-89"""
    search_id = request.args.get('id', '1')
    
    # VULNERABLE: Potential UNION injection (python:S2077)
    query = "SELECT name, email FROM users WHERE id = " + search_id
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()


# ============================================================================
# 9. INPUT SOURCE VARIATIONS (Medium Risk)
# ============================================================================

def test_cookie_injection():
    """Test Case 22: Cookie-based injection - Should detect CWE-89"""
    session_id = request.cookies.get('session_id', '')
    
    # VULNERABLE: Cookie-based injection (python:S2077)
    query = "SELECT * FROM sessions WHERE session_id = '" + session_id + "'"
    
    conn = sqlite3.connect('sessions.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()


def test_header_injection():
    """Test Case 23: Header-based injection - Should detect CWE-89"""
    user_agent = request.headers.get('User-Agent', '')
    
    # VULNERABLE: Header-based injection (python:S2077)
    query = "INSERT INTO logs (user_agent, timestamp) VALUES ('" + user_agent + "', datetime('now'))"
    
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()
    return {"status": "logged"}


def test_environment_injection():
    """Test Case 24: Environment variable injection - Should detect CWE-89"""
    db_table = os.environ.get('DB_TABLE', 'users')
    user_id = request.form['user_id']
    
    # VULNERABLE: Environment variable in query (python:S2079)
    query = f"SELECT * FROM {db_table} WHERE id = {user_id}"
    
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()


# ============================================================================
# 10. SAFE CODE EXAMPLES (Should NOT trigger detection)
# ============================================================================

def test_safe_parameterized_1():
    """Test Case 25: Safe parameterized query - Should NOT detect"""
    user_id = request.form['user_id']
    
    # SAFE: Parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query, (user_id,))
    return cursor.fetchone()


def test_safe_parameterized_2():
    """Test Case 26: Safe multiple parameters - Should NOT detect"""
    username = request.form['username']
    status = request.form['status']
    
    # SAFE: Multiple parameters
    query = "SELECT * FROM users WHERE username = ? AND status = ?"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query, (username, status))
    return cursor.fetchall()


def test_safe_constant_query():
    """Test Case 27: Safe constant query - Should NOT detect"""
    # SAFE: No user input in query
    query = "SELECT COUNT(*) FROM users WHERE active = 1"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()


# ============================================================================
# 11. EDGE CASES AND COMPLEX SCENARIOS
# ============================================================================

def test_nested_function_vulnerability():
    """Test Case 28: Nested function vulnerability - Should detect CWE-89"""
    def build_query(table, column, value):
        # VULNERABLE: Nested function with concatenation (python:S2079)
        return f"SELECT * FROM {table} WHERE {column} = '{value}'"
    
    table = request.args.get('table', 'users')
    column = request.args.get('column', 'id')
    value = request.args.get('value', '1')
    
    query = build_query(table, column, value)
    
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()


def test_conditional_vulnerability():
    """Test Case 29: Conditional vulnerability - Should detect CWE-89"""
    user_input = request.form.get('input', '')
    use_safe_mode = request.form.get('safe', 'false').lower() == 'true'
    
    if use_safe_mode:
        # SAFE path
        query = "SELECT * FROM users WHERE id = ?"
        params = (user_input,)
    else:
        # VULNERABLE path (python:S2077)
        query = "SELECT * FROM users WHERE id = " + user_input
        params = None
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    if params:
        cursor.execute(query, params)
    else:
        cursor.execute(query)  # This should trigger detection
    
    return cursor.fetchall()


def test_class_method_vulnerability():
    """Test Case 30: Class method vulnerability - Should detect CWE-89"""
    class UserManager:
        def __init__(self):
            self.conn = sqlite3.connect('users.db')
        
        def find_user(self, user_id):
            # VULNERABLE: Method with concatenation (python:S2077)
            query = "SELECT * FROM users WHERE id = " + str(user_id)
            cursor = self.conn.cursor()
            cursor.execute(query)
            return cursor.fetchone()
    
    user_id = request.form['user_id']
    manager = UserManager()
    return manager.find_user(user_id)


# ============================================================================
# TEST RUNNER FUNCTIONS
# ============================================================================

def run_all_tests():
    """Run all test cases and return results"""
    test_functions = [
        test_basic_concatenation_1,
        test_basic_concatenation_2,
        test_multiline_concatenation,
        test_fstring_vulnerability_1,
        test_fstring_vulnerability_2,
        test_complex_fstring,
        test_percent_formatting_1,
        test_percent_formatting_2,
        test_format_method,
        test_vulnerable_insert,
        test_vulnerable_update,
        test_vulnerable_delete,
        test_mysql_vulnerability,
        test_postgresql_vulnerability,
        test_mongodb_vulnerability_1,
        test_mongodb_vulnerability_2,
        test_django_raw_sql,
        test_flask_sqlalchemy_text,
        test_dynamic_table_name,
        test_order_by_injection,
        test_union_injection,
        test_cookie_injection,
        test_header_injection,
        test_environment_injection,
        test_safe_parameterized_1,
        test_safe_parameterized_2,
        test_safe_constant_query,
        test_nested_function_vulnerability,
        test_conditional_vulnerability,
        test_class_method_vulnerability
    ]
    
    results = []
    for func in test_functions:
        try:
            result = func()
            results.append({
                "test": func.__name__,
                "status": "executed",
                "result": result
            })
        except Exception as e:
            results.append({
                "test": func.__name__,
                "status": "error",
                "error": str(e)
            })
    
    return results


if __name__ == "__main__":
    print("SQL Injection Test Cases")
    print("=" * 50)
    print("This file contains 30 test cases:")
    print("- 24 vulnerable patterns (should be detected)")
    print("- 3 safe patterns (should NOT be detected)")
    print("- 3 edge cases (complex scenarios)")
    print()
    print("Expected detections:")
    print("✓ CWE-89: SQL Injection")
    print("✓ CWE-564: SQL Injection variant")
    print("✓ CWE-943: Improper neutralization")
    print("✓ OWASP A03:2021-Injection")
    print("✓ SonarQube rules: python:S2077, python:S2078, python:S2079")
    print()
    print("To test with the enhanced detector:")
    print("python3 -c \"")
    print("from enhanced_sql_injection_detector import EnhancedSQLInjectionDetector")
    print("detector = EnhancedSQLInjectionDetector()")
    print("vulnerabilities = detector.scan_file('test_vulnerable_code.py')")
    print("detector.print_enhanced_report()\"") 