# Test file with SQL injection vulnerabilities
import sqlite3
from flask import request

def vulnerable_function():
    user_input = request.form['user_id']
    
    # Vulnerable: String concatenation
    query = "SELECT * FROM users WHERE id = " + user_input
    
    # Vulnerable: F-string
    query2 = f"SELECT * FROM users WHERE name = {user_input}"
    
    # Vulnerable: String formatting
    query3 = "SELECT * FROM users WHERE email = %s" % user_input
    
    # Vulnerable: .format()
    query4 = "SELECT * FROM users WHERE age = {}".format(user_input)
    
    # Vulnerable: Direct execution
    cursor.execute("SELECT * FROM users WHERE id = " + user_input)
    
    # Vulnerable: INSERT with concatenation
    insert_query = "INSERT INTO users (name, email) VALUES (" + user_input + ", " + email + ")"
    
    # Vulnerable: UPDATE with concatenation
    update_query = "UPDATE users SET name = " + user_input + " WHERE id = 1"
    
    # Vulnerable: Request parameters
    search_term = request.args['search']
    query5 = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
    
    # Vulnerable: Cookie values
    session_id = request.cookies['session']
    query6 = "SELECT * FROM sessions WHERE id = " + session_id
    
    # Vulnerable: Input function
    user_name = input("Enter username: ")
    query7 = "SELECT * FROM users WHERE username = " + user_name
    
    return "Vulnerable code executed" 