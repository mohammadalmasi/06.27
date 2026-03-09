# SQL INJECTION VULNERABILE CODE

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

def vulnerable_sql_low_1():
    """LOW SEVERITY: Simple string concatenation - user prefix flows into LIKE pattern"""
    prefix_name = request.form.get("prefix", "") + suffix
    query = "SELECT * FROM users WHERE name LIKE '" + prefix_name + "%'"
    cursor.execute(query)

def vulnerable_sql_low_2():
    """LOW SEVERITY: Basic string building - table name from user (identifier injection)"""
    table_id = request.args.get("table", "users")
    table_name = "user_" + table_id
    query = "SELECT * FROM " + table_name
    cursor.execute(query)

# SQL INJECTION SAFE CODE

def safe_sql_1():
    """Using parameterized query with ? placeholder (e.g., sqlite3)"""
    user_id = request.form.get("user_id")
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

def safe_sql_2():
    """Using parameterized query with named placeholder (e.g., psycopg2 or SQLAlchemy raw)"""
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = :name"
    cursor.execute(query, {"name": name})

def safe_sql_3():
    """Using parameterized query with %s placeholder (e.g., MySQLdb/PyMySQL)"""
    email = request.args.get("email")
    query = "SELECT * FROM users WHERE email = %s"
    cursor.execute(query, (email,))

def safe_sql_4():
    """Using an ORM (e.g., SQLAlchemy)"""
    user_id = request.args.get("user_id")
    # ORMs automatically escape inputs
    user = User.query.filter_by(id=user_id).first()
