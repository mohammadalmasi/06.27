# Auto-generated from backend/datasets/sql_injection.json for Semgrep comparison
user_id = '1'
name = 'test'
username = 'alice'
order_id = '123'
user_input = '1'
admin = 'admin'

# id=1 type=String Concatenation label=vulnerable cwe=CWE-89
def case_1():
    cursor = None  # placeholder for semgrep; not executed
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)

# id=2 type=String Concatenation label=vulnerable cwe=CWE-89
def case_2():
    cursor = None  # placeholder for semgrep; not executed
    sql = "SELECT * FROM products WHERE name='" + name + "'"
    cursor.execute(sql)

# id=3 type=F-String Formatting label=vulnerable cwe=CWE-89
def case_3():
    cursor = None  # placeholder for semgrep; not executed
    query = f"SELECT * FROM users WHERE username='{username}'"
    cursor.execute(query)

# id=4 type=F-String Formatting label=vulnerable cwe=CWE-89
def case_4():
    cursor = None  # placeholder for semgrep; not executed
    sql = f"SELECT * FROM orders WHERE order_id={order_id}"
    cursor.execute(sql)

# id=5 type=Error-based label=vulnerable cwe=CWE-89
def case_5():
    cursor = None  # placeholder for semgrep; not executed
    payload = "' OR 1=1 --"
    query = "SELECT * FROM users WHERE email='" + payload + "'"
    cursor.execute(query)

# id=6 type=Error-based label=vulnerable cwe=CWE-89
def case_6():
    cursor = None  # placeholder for semgrep; not executed
    query = "SELECT * FROM users WHERE id=1 AND (SELECT 1/0)"
    cursor.execute(query)

# id=7 type=Union-based label=vulnerable cwe=CWE-89
def case_7():
    cursor = None  # placeholder for semgrep; not executed
    payload = "1 UNION SELECT username,password FROM users"
    query = "SELECT name FROM products WHERE id=" + payload
    cursor.execute(query)

# id=8 type=Union-based label=vulnerable cwe=CWE-89
def case_8():
    cursor = None  # placeholder for semgrep; not executed
    sql = "SELECT id FROM accounts WHERE id=" + user_input
    cursor.execute(sql)

# id=9 type=Boolean-based blind label=vulnerable cwe=CWE-89
def case_9():
    cursor = None  # placeholder for semgrep; not executed
    payload = "' AND 1=1 --"
    query = "SELECT * FROM users WHERE username='admin" + payload
    cursor.execute(query)

# id=10 type=Boolean-based blind label=vulnerable cwe=CWE-89
def case_10():
    cursor = None  # placeholder for semgrep; not executed
    payload = "' AND 1=2 --"
    query = "SELECT * FROM users WHERE username='admin" + payload
    cursor.execute(query)

# id=11 type=Time-based blind label=vulnerable cwe=CWE-89
def case_11():
    cursor = None  # placeholder for semgrep; not executed
    payload = "' OR SLEEP(5) --"
    query = "SELECT * FROM users WHERE id='" + payload
    cursor.execute(query)

# id=12 type=Time-based blind label=vulnerable cwe=CWE-89
def case_12():
    cursor = None  # placeholder for semgrep; not executed
    query = "SELECT * FROM users WHERE id=1 AND IF(1=1,SLEEP(3),0)"
    cursor.execute(query)
