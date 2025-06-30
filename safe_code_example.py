# Safe code example - Proper SQL injection prevention
import sqlite3
from flask import request, jsonify
import re

def safe_database_operations():
    """Example of safe database operations that prevent SQL injection."""
    
    # 1. SAFE: Parameterized queries with placeholders
    def safe_select_user(user_id):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Safe: Use parameterized query
        query = "SELECT * FROM users WHERE id = ?"
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()
        
        conn.close()
        return user
    
    # 2. SAFE: Multiple parameters
    def safe_insert_user(name, email, age):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Safe: Multiple placeholders
        query = "INSERT INTO users (name, email, age) VALUES (?, ?, ?)"
        cursor.execute(query, (name, email, age))
        conn.commit()
        conn.close()
    
    # 3. SAFE: Input validation before database operations
    def safe_search_users(search_term):
        # Validate input
        if not search_term or len(search_term) > 100:
            return jsonify({"error": "Invalid search term"}), 400
        
        # Sanitize input (remove dangerous characters)
        search_term = re.sub(r'[^\w\s]', '', search_term)
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Safe: Use parameterized query with sanitized input
        query = "SELECT * FROM users WHERE name LIKE ?"
        cursor.execute(query, (f'%{search_term}%',))
        users = cursor.fetchall()
        
        conn.close()
        return users
    
    # 4. SAFE: Using ORM (SQLAlchemy example)
    from sqlalchemy import create_engine, text
    
    def safe_orm_operations():
        engine = create_engine('sqlite:///database.db')
        
        # Safe: Using SQLAlchemy text() with parameters
        with engine.connect() as conn:
            query = text("SELECT * FROM users WHERE id = :user_id")
            result = conn.execute(query, {"user_id": 123})
            user = result.fetchone()
        
        return user
    
    # 5. SAFE: Request handling with validation
    def safe_handle_request():
        # Safe: Use .get() method with default values
        user_id = request.form.get('user_id')
        if not user_id:
            return jsonify({"error": "Missing user_id"}), 400
        
        # Validate user_id is numeric
        try:
            user_id = int(user_id)
        except ValueError:
            return jsonify({"error": "Invalid user_id format"}), 400
        
        # Safe: Use validated input in parameterized query
        user = safe_select_user(user_id)
        return jsonify({"user": user})
    
    # 6. SAFE: Prepared statements
    def safe_prepared_statements():
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Safe: Prepare statement once, execute multiple times
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE
            )
        """)
        
        # Safe: Use parameterized queries for all operations
        insert_query = "INSERT INTO users (name, email) VALUES (?, ?)"
        select_query = "SELECT * FROM users WHERE email = ?"
        update_query = "UPDATE users SET name = ? WHERE id = ?"
        delete_query = "DELETE FROM users WHERE id = ?"
        
        # Execute with parameters
        cursor.execute(insert_query, ("John Doe", "john@example.com"))
        cursor.execute(select_query, ("john@example.com",))
        cursor.execute(update_query, ("Jane Doe", 1))
        cursor.execute(delete_query, (1,))
        
        conn.commit()
        conn.close()
    
    return "All database operations are safe from SQL injection"

# Example usage
if __name__ == "__main__":
    safe_database_operations() 