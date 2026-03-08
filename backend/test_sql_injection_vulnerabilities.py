# ============================================================================
# SQL INJECTION VULNERABILITIES (HIGH SEVERITY)
# ============================================================================

def vulnerable_sql_high_1():
    """Direct string concatenation in SELECT"""
    user_id = request.form["user_id"]
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)

def vulnerable_sql_high_2():
    """F-string with SQL"""
    name = request.args.get("name")
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)

# ============================================================================
# SQL INJECTION VULNERABILITIES (MEDIUM SEVERITY)
# ============================================================================

def vulnerable_sql_medium_1():
    """ORDER BY clause with concatenation"""
    sort_column = request.args.get("sort", "name")
    query = "SELECT * FROM users ORDER BY " + sort_column
    cursor.execute(query)

def vulnerable_sql_medium_2():
    """LIMIT clause with concatenation"""
    limit_value = request.form.get("limit", "10")
    query = "SELECT * FROM users LIMIT " + limit_value
    cursor.execute(query)

def vulnerable_sql_medium_3():
    """SQL comment injection - user input concatenated then sent to execute"""
    comment_input = request.args.get("comment", "") + "' --"
    query = "SELECT * FROM logs WHERE id = '" + comment_input + "'"
    cursor.execute(query)

# ============================================================================
# SQL INJECTION VULNERABILITIES (LOW SEVERITY)
# ============================================================================

def vulnerable_sql_low_1():
    """Simple string concatenation - user prefix flows into query"""
    prefix_name = request.form.get("prefix", "") + suffix
    query = "SELECT * FROM users WHERE name LIKE '" + prefix_name + "%'"
    cursor.execute(query)

def vulnerable_sql_low_2():
    """Basic string building - table name from user flows into query"""
    table_id = request.args.get("table", "users")
    table_name = "user_" + table_id
    query = "SELECT * FROM " + table_name + " WHERE id = 1"
    cursor.execute(query)
