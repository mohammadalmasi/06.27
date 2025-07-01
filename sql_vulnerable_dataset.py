#!/usr/bin/env python3
"""
SQL Injection Vulnerable Code Dataset
A comprehensive collection of SQL injection vulnerable code examples
for research and testing purposes.

This dataset contains various types of SQL injection vulnerabilities:
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

WARNING: This code is intentionally vulnerable and should ONLY be used for:
- Educational purposes
- Security research
- Testing security tools
- Academic studies

NEVER use this code in production environments!
"""

import sqlite3
import mysql.connector
import psycopg2
import sqlite3
from flask import Flask, request, jsonify
from django.http import HttpResponse
from django.db import connection
import pymongo
import re
import time

# ============================================================================
# PYTHON EXAMPLES
# ============================================================================

class PythonSQLInjectionExamples:
    """Python-based SQL injection vulnerable code examples."""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.setup_routes()
    
    def setup_routes(self):
        """Setup vulnerable Flask routes."""
        
        @self.app.route('/vulnerable_login', methods=['POST'])
        def vulnerable_login():
            """Vulnerable login endpoint."""
            username = request.form['username']
            password = request.form['password']
            
            # VULNERABLE: String concatenation
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()
            
            if user:
                return jsonify({"status": "success", "message": "Login successful"})
            else:
                return jsonify({"status": "error", "message": "Invalid credentials"})
        
        @self.app.route('/vulnerable_search', methods=['GET'])
        def vulnerable_search():
            """Vulnerable search endpoint."""
            search_term = request.args.get('q', '')
            
            # VULNERABLE: Direct string concatenation
            query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
            
            conn = sqlite3.connect('products.db')
            cursor = conn.cursor()
            cursor.execute(query)
            products = cursor.fetchall()
            conn.close()
            
            return jsonify({"products": products})
        
        @self.app.route('/vulnerable_user_profile', methods=['GET'])
        def vulnerable_user_profile():
            """Vulnerable user profile endpoint."""
            user_id = request.args.get('id', '')
            
            # VULNERABLE: String formatting
            query = "SELECT * FROM users WHERE id = %s" % user_id
            
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()
            
            return jsonify({"user": user})
        
        @self.app.route('/vulnerable_insert', methods=['POST'])
        def vulnerable_insert():
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
        
        @self.app.route('/vulnerable_update', methods=['POST'])
        def vulnerable_update():
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
        
        @self.app.route('/vulnerable_delete', methods=['POST'])
        def vulnerable_delete():
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
# FRAMEWORK-SPECIFIC VULNERABILITIES
# ============================================================================

class FrameworkVulnerabilities:
    """Framework-specific SQL injection vulnerabilities."""
    
    def django_vulnerable_views(self, request):
        """Django vulnerable views."""
        user_id = request.GET.get('id', '')
        
        # VULNERABLE: Django raw SQL
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM auth_user WHERE id = {user_id}")
            user = cursor.fetchone()
        
        return HttpResponse(f"User: {user}")
    
    def flask_vulnerable_views(self, request):
        """Flask vulnerable views."""
        search_term = request.args.get('search', '')
        
        # VULNERABLE: Flask with SQLAlchemy raw SQL
        from sqlalchemy import text
        from sqlalchemy import create_engine
        
        engine = create_engine('sqlite:///test.db')
        with engine.connect() as conn:
            query = text(f"SELECT * FROM products WHERE name LIKE '%{search_term}%'")
            result = conn.execute(query)
            products = result.fetchall()
        
        return jsonify({"products": products})

# ============================================================================
# NO-SQL INJECTION VULNERABILITIES
# ============================================================================

class NoSQLInjectionExamples:
    """NoSQL injection vulnerable code examples."""
    
    def mongodb_vulnerable_query(self, user_input):
        """MongoDB vulnerable query."""
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
# DATASET GENERATION FUNCTIONS
# ============================================================================

def generate_vulnerable_dataset():
    """Generate a comprehensive dataset of vulnerable code examples."""
    
    dataset = {
        "metadata": {
            "description": "SQL Injection Vulnerable Code Dataset",
            "version": "1.0",
            "total_examples": 0,
            "categories": [
                "String Concatenation",
                "Dynamic Query Construction", 
                "Input Validation Bypasses",
                "Authentication Bypasses",
                "Data Extraction",
                "Blind SQL Injection",
                "Time-based Injection",
                "Union-based Injection",
                "Error-based Injection",
                "Boolean-based Injection",
                "NoSQL Injection",
                "Framework-specific",
                "Real-world Patterns"
            ]
        },
        "examples": []
    }
    
    # Basic string concatenation vulnerabilities
    basic_examples = [
        {
            "category": "String Concatenation",
            "language": "Python",
            "vulnerability_type": "Login Bypass",
            "code": "query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"",
            "description": "Direct string interpolation in login query",
            "payload": "admin' OR '1'='1",
            "severity": "Critical"
        },
        {
            "category": "String Concatenation", 
            "language": "Python",
            "vulnerability_type": "Data Extraction",
            "code": "query = \"SELECT * FROM users WHERE id = \" + user_input",
            "description": "String concatenation in WHERE clause",
            "payload": "1 UNION SELECT 1,2,3,4",
            "severity": "High"
        },
        {
            "category": "String Concatenation",
            "language": "Python", 
            "vulnerability_type": "Search Injection",
            "code": "query = \"SELECT * FROM products WHERE name LIKE '%\" + search_term + \"%'\"",
            "description": "Search functionality with string concatenation",
            "payload": "test' UNION SELECT 1,2,3,4 --",
            "severity": "High"
        }
    ]
    
    # Advanced injection techniques
    advanced_examples = [
        {
            "category": "Union-based Injection",
            "language": "Python",
            "vulnerability_type": "Data Extraction",
            "code": "query = f\"SELECT id, name FROM users WHERE id = {user_input} UNION SELECT 1,2\"",
            "description": "Union-based injection to extract data",
            "payload": "1 UNION SELECT username,password FROM users",
            "severity": "Critical"
        },
        {
            "category": "Time-based Injection",
            "language": "Python",
            "vulnerability_type": "Blind Injection",
            "code": "query = f\"SELECT * FROM users WHERE id = 1 AND (SELECT COUNT(*) FROM users WHERE id = {user_input}) > 0\"",
            "description": "Time-based blind SQL injection",
            "payload": "1 AND (SELECT COUNT(*) FROM users) > 0",
            "severity": "High"
        },
        {
            "category": "Error-based Injection",
            "language": "Python",
            "vulnerability_type": "Information Disclosure",
            "code": "query = f\"SELECT * FROM users WHERE id = {user_input} AND (SELECT COUNT(*) FROM information_schema.tables) > 0\"",
            "description": "Error-based injection to extract database information",
            "payload": "1 AND (SELECT COUNT(*) FROM information_schema.tables) > 0",
            "severity": "High"
        }
    ]
    
    # Framework-specific vulnerabilities
    framework_examples = [
        {
            "category": "Framework-specific",
            "language": "Python/Django",
            "vulnerability_type": "Raw SQL",
            "code": "cursor.execute(f\"SELECT * FROM auth_user WHERE id = {user_id}\")",
            "description": "Django raw SQL with string interpolation",
            "payload": "1 OR 1=1",
            "severity": "Critical"
        },
        {
            "category": "Framework-specific",
            "language": "Python/Flask",
            "vulnerability_type": "SQLAlchemy Raw SQL",
            "code": "query = text(f\"SELECT * FROM users WHERE id = {user_id}\")",
            "description": "Flask with SQLAlchemy raw SQL",
            "payload": "1; DROP TABLE users; --",
            "severity": "Critical"
        }
    ]
    
    # NoSQL injection examples
    nosql_examples = [
        {
            "category": "NoSQL Injection",
            "language": "Python/MongoDB",
            "vulnerability_type": "Authentication Bypass",
            "code": "query = f'{{\"username\": \"{username}\", \"password\": \"{password}\"}}'",
            "description": "MongoDB authentication with string interpolation",
            "payload": "admin\", \"$ne\": \"",
            "severity": "Critical"
        },
        {
            "category": "NoSQL Injection",
            "language": "Python/MongoDB",
            "vulnerability_type": "Data Extraction",
            "code": "query = f'{{\"username\": \"{user_input}\"}}'",
            "description": "MongoDB query with string interpolation",
            "payload": "admin\", \"$where\": \"1==1\"",
            "severity": "High"
        }
    ]
    
    # Real-world patterns
    realworld_examples = [
        {
            "category": "Real-world Patterns",
            "language": "Python",
            "vulnerability_type": "E-commerce Search",
            "code": "query = f\"SELECT p.*, c.name FROM products p JOIN categories c ON p.category_id = c.id WHERE p.name LIKE '%{search_term}%'\"",
            "description": "E-commerce product search with injection",
            "payload": "test' UNION SELECT 1,2,3,4,5 --",
            "severity": "High"
        },
        {
            "category": "Real-world Patterns",
            "language": "Python",
            "vulnerability_type": "Banking API",
            "code": "query = f\"SELECT account_number, balance FROM accounts WHERE account_id = {account_id}\"",
            "description": "Banking API with account query injection",
            "payload": "1 UNION SELECT account_number,balance FROM accounts",
            "severity": "Critical"
        }
    ]
    
    # Combine all examples
    all_examples = basic_examples + advanced_examples + framework_examples + nosql_examples + realworld_examples
    
    dataset["examples"] = all_examples
    dataset["metadata"]["total_examples"] = len(all_examples)
    
    return dataset

def save_dataset_to_file(dataset, filename="sql_injection_dataset.json"):
    """Save the dataset to a JSON file."""
    import json
    
    with open(filename, 'w') as f:
        json.dump(dataset, f, indent=2)
    
    print(f"Dataset saved to {filename}")
    print(f"Total examples: {dataset['metadata']['total_examples']}")

# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    print("Generating SQL Injection Vulnerable Code Dataset...")
    
    # Generate the dataset
    dataset = generate_vulnerable_dataset()
    
    # Save to file
    save_dataset_to_file(dataset)
    
    # Print summary
    print("\nDataset Summary:")
    print("================")
    for category in dataset["metadata"]["categories"]:
        count = len([ex for ex in dataset["examples"] if ex["category"] == category])
        print(f"{category}: {count} examples")
    
    print(f"\nTotal examples: {dataset['metadata']['total_examples']}")
    print("\nWARNING: This code is intentionally vulnerable!")
    print("Use only for educational and research purposes.") 