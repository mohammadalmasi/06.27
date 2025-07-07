#!/usr/bin/env python3
from scanners.sql_injection.sql_injection_scanner import scan_code_content_for_sql_injection
from scanners.xss.xss_scanner import scan_code_content_for_xss

# ============================================================================
# HIGH SEVERITY SQL INJECTION EXAMPLES
# ============================================================================

high_sql_code = '''def high_severity_sql():
    # HIGH: Direct string concatenation in SELECT
    user_id = request.form["user_id"]
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    
    # HIGH: F-string with SQL
    name = request.args.get("name")
    query2 = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query2)'''

# ============================================================================
# MEDIUM SEVERITY SQL INJECTION EXAMPLES
# ============================================================================

medium_sql_code = '''def medium_severity_sql():
    # MEDIUM: ORDER BY clause with concatenation
    sort_column = request.args.get("sort", "name")
    query = "ORDER BY " + sort_column
    
    # MEDIUM: LIMIT clause with concatenation  
    limit_value = request.form.get("limit", "10")
    query2 = "LIMIT " + limit_value
    
    # MEDIUM: SQL comment injection
    comment_input = admin_user + "' --"
    
    # MEDIUM: Blind SQL injection pattern  
    condition = user_input + " AND 1=1"'''

# ============================================================================
# LOW SEVERITY SQL INJECTION EXAMPLES
# ============================================================================

low_sql_code = '''def low_severity_sql():
    # LOW: Simple string concatenation
    prefix_name = user_prefix + suffix
    
    # LOW: Basic string building
    table_name = "user_" + table_id
    
    # LOW: Column name construction
    column_var = "col_" + field_name'''

# ============================================================================
# HIGH SEVERITY XSS EXAMPLES
# ============================================================================

high_xss_code = '''def high_severity_xss():
    # HIGH: F-string with HTML and user input
    user_name = request.args.get("name")
    return f"<h1>Welcome {user_name}!</h1>"
    
    # HIGH: Direct innerHTML manipulation
    content = request.form.get("content")
    script = f"document.getElementById('content').innerHTML = '{content}'"
    
    # HIGH: eval() with user input
    user_code = request.args.get("code")
    result = eval("calculate_" + user_code)'''

# ============================================================================
# MEDIUM SEVERITY XSS EXAMPLES
# ============================================================================

medium_xss_code = '''def medium_severity_xss():
    # MEDIUM: Using |safe filter (potential XSS if not validated)
    user_html = "{{ user_content|safe }}"
    
    # MEDIUM: Markup() usage
    from markupsafe import Markup
    user_input = request.args.get("input")
    safe_html = Markup(user_input)
    
    # MEDIUM: URL parameter usage
    search_term = URLSearchParams(window.location.search)
    
    # MEDIUM: jQuery .append() with HTML
    data = request.form.get("data")
    script = "$('#result').append('<div>' + data + '</div>')"
    
    # MEDIUM: print() with HTML
    message = request.args.get("msg")
    print("<p>" + message)'''

# ============================================================================
# LOW SEVERITY XSS EXAMPLES
# ============================================================================

low_xss_code = '''def low_severity_xss():
    # LOW: Simple string concatenation
    greeting = user_name + " welcome"
    
    # LOW: Template string building
    message_template = "Hello " + username
    
    # LOW: Basic string construction
    display_text = "User: " + user_data'''

# ============================================================================
# TEST ALL SEVERITY LEVELS
# ============================================================================

def test_severity_levels():
    print("=" * 60)
    print("SQL INJECTION VULNERABILITY SEVERITY TESTING")
    print("=" * 60)
    
    # Test HIGH severity SQL
    print("\n🔴 HIGH SEVERITY SQL INJECTION:")
    high_sql_result = scan_code_content_for_sql_injection(high_sql_code, 'high_sql.py')
    print(f"Total vulnerabilities: {high_sql_result['total_vulnerabilities']}")
    for vuln in high_sql_result['vulnerabilities']:
        print(f"  Line {vuln['line_number']}: {vuln['severity'].upper()} - {vuln['description']}")
    
    # Test MEDIUM severity SQL
    print("\n🟡 MEDIUM SEVERITY SQL INJECTION:")
    medium_sql_result = scan_code_content_for_sql_injection(medium_sql_code, 'medium_sql.py')
    print(f"Total vulnerabilities: {medium_sql_result['total_vulnerabilities']}")
    for vuln in medium_sql_result['vulnerabilities']:
        print(f"  Line {vuln['line_number']}: {vuln['severity'].upper()} - {vuln['description']}")
    
    # Test LOW severity SQL
    print("\n🟢 LOW SEVERITY SQL INJECTION:")
    low_sql_result = scan_code_content_for_sql_injection(low_sql_code, 'low_sql.py')
    print(f"Total vulnerabilities: {low_sql_result['total_vulnerabilities']}")
    for vuln in low_sql_result['vulnerabilities']:
        print(f"  Line {vuln['line_number']}: {vuln['severity'].upper()} - {vuln['description']}")
    
    print("\n" + "=" * 60)
    print("XSS VULNERABILITY SEVERITY TESTING")
    print("=" * 60)
    
    # Test HIGH severity XSS
    print("\n🔴 HIGH SEVERITY XSS:")
    high_xss_result = scan_code_content_for_xss(high_xss_code, 'high_xss.py')
    print(f"Total vulnerabilities: {high_xss_result['total_vulnerabilities']}")
    for vuln in high_xss_result['vulnerabilities']:
        print(f"  Line {vuln['line_number']}: {vuln['severity'].upper()} - {vuln['description']}")
    
    # Test MEDIUM severity XSS
    print("\n🟡 MEDIUM SEVERITY XSS:")
    medium_xss_result = scan_code_content_for_xss(medium_xss_code, 'medium_xss.py')
    print(f"Total vulnerabilities: {medium_xss_result['total_vulnerabilities']}")
    for vuln in medium_xss_result['vulnerabilities']:
        print(f"  Line {vuln['line_number']}: {vuln['severity'].upper()} - {vuln['description']}")
    
    # Test LOW severity XSS
    print("\n🟢 LOW SEVERITY XSS:")
    low_xss_result = scan_code_content_for_xss(low_xss_code, 'low_xss.py')
    print(f"Total vulnerabilities: {low_xss_result['total_vulnerabilities']}")
    for vuln in low_xss_result['vulnerabilities']:
        print(f"  Line {vuln['line_number']}: {vuln['severity'].upper()} - {vuln['description']}")

if __name__ == "__main__":
    test_severity_levels()
