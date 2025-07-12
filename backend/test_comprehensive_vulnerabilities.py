#!/usr/bin/env python3
"""
Comprehensive Test File for All Vulnerability Types and Severity Levels
This file contains intentional security vulnerabilities for testing purposes.
DO NOT use this code in production!
"""

import os
import subprocess
import sys
from flask import request
from scanners.sql_injection.sql_injection_scanner import scan_code_content_for_sql_injection
from scanners.xss.xss_scanner import scan_code_content_for_xss
from scanners.command_injection.command_injection_scanner import scan_code_content_for_command_injection

# ============================================================================
# COMMAND INJECTION VULNERABILITIES (HIGH SEVERITY)
# ============================================================================

def vulnerable_command_1():
    """Direct os.system with user input"""
    user_input = request.form.get('filename')
    os.system("ls -la " + user_input)  # Command injection vulnerability

def vulnerable_command_2():
    """subprocess.call with shell=True"""
    filename = request.args.get('file')
    subprocess.call("cat " + filename, shell=True)  # Command injection vulnerability

def vulnerable_command_3():
    """os.popen with concatenated input"""
    directory = request.form.get('dir')
    result = os.popen("ls " + directory).read()  # Command injection vulnerability
    return result

def vulnerable_command_4():
    """eval with user input"""
    code = request.form.get('code')
    eval("print('" + code + "')")  # Code injection vulnerability

def vulnerable_command_5():
    """exec with user input"""
    command = request.form.get('cmd')
    exec("os.system('" + command + "')")  # Code injection vulnerability

def vulnerable_command_6():
    """subprocess.run with shell=True"""
    user_cmd = request.form.get('command')
    subprocess.run(user_cmd, shell=True)  # Command injection vulnerability

def vulnerable_command_7():
    """subprocess.Popen with shell=True"""
    cmd = request.form.get('cmd')
    subprocess.Popen(cmd, shell=True)  # Command injection vulnerability

def vulnerable_command_8():
    """Dynamic import with user input"""
    module_name = request.form.get('module')
    __import__(module_name)  # Code injection vulnerability

# ============================================================================
# COMMAND INJECTION VULNERABILITIES (MEDIUM SEVERITY)
# ============================================================================

def vulnerable_command_9():
    """os.remove with user input"""
    filepath = request.form.get('file')
    os.remove("/tmp/" + filepath)  # Path traversal vulnerability

def vulnerable_command_10():
    """Template injection"""
    from string import Template
    template_str = request.form.get('template')
    template = Template("Hello $name")
    result = template.substitute(name=template_str)  # Template injection vulnerability

# ============================================================================
# COMMAND INJECTION VULNERABILITIES (LOW SEVERITY)
# ============================================================================

def vulnerable_command_low_1():
    """Basic string concatenation with user input"""
    user_input = request.form.get('input')
    message = "Command: " + user_input  # Low severity - just string concatenation

def vulnerable_command_low_2():
    """Simple variable assignment with user input"""
    filename = request.args.get('file')
    command = "ls " + filename  # Low severity - command construction without execution

def vulnerable_command_low_3():
    """Path construction with user input"""
    user_path = request.form.get('path')
    full_path = "/home/user/" + user_path  # Low severity - path construction

def vulnerable_command_low_4():
    """Environment variable with user input"""
    env_var = request.args.get('env')
    os.environ['CUSTOM_VAR'] = env_var  # Low severity - environment variable setting

def vulnerable_command_low_5():
    """Configuration with user input"""
    config_value = request.form.get('config')
    config = {"setting": config_value}  # Low severity - configuration setting

# ============================================================================
# COMMAND INJECTION SAFE FUNCTIONS
# ============================================================================

def safe_command_1():
    """Safe subprocess usage"""
    filename = request.form.get('file')
    # Input validation
    if not filename or '..' in filename or '/' in filename:
        return "Invalid filename"
    
    # Safe subprocess usage
    subprocess.run(['ls', '-la', filename], shell=False)

def safe_command_2():
    """Safe os.path operations"""
    import os.path
    directory = request.form.get('dir')
    # Input validation
    if not directory or '..' in directory:
        return "Invalid directory"
    
    # Safe path operations
    safe_path = os.path.join('/safe/base/path', directory)
    if os.path.exists(safe_path):
        return "Directory exists"

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
    query = "ORDER BY " + sort_column

def vulnerable_sql_medium_2():
    """LIMIT clause with concatenation"""
    limit_value = request.form.get("limit", "10")
    query = "LIMIT " + limit_value

def vulnerable_sql_medium_3():
    """SQL comment injection"""
    comment_input = admin_user + "' --"

# ============================================================================
# SQL INJECTION VULNERABILITIES (LOW SEVERITY)
# ============================================================================

def vulnerable_sql_low_1():
    """Simple string concatenation"""
    prefix_name = user_prefix + suffix

def vulnerable_sql_low_2():
    """Basic string building"""
    table_name = "user_" + table_id

# ============================================================================
# XSS VULNERABILITIES (HIGH SEVERITY)
# ============================================================================

def vulnerable_xss_high_1():
    """F-string with HTML and user input"""
    user_name = request.args.get("name")
    return f"<h1>Welcome {user_name}!</h1>"

def vulnerable_xss_high_2():
    """Direct innerHTML manipulation"""
    content = request.form.get("content")
    script = f"document.getElementById('content').innerHTML = '{content}'"

def vulnerable_xss_high_3():
    """eval() with user input"""
    user_code = request.args.get("code")
    result = eval("calculate_" + user_code)

# ============================================================================
# XSS VULNERABILITIES (MEDIUM SEVERITY)
# ============================================================================

def vulnerable_xss_medium_1():
    """Using |safe filter (potential XSS if not validated)"""
    user_html = "{{ user_content|safe }}"

def vulnerable_xss_medium_2():
    """Markup() usage"""
    from markupsafe import Markup
    user_input = request.args.get("input")
    safe_html = Markup(user_input)

def vulnerable_xss_medium_3():
    """URL parameter usage"""
    search_term = URLSearchParams(window.location.search)

def vulnerable_xss_medium_4():
    """jQuery .append() with HTML"""
    data = request.form.get("data")
    script = "$('#result').append('<div>' + data + '</div>')"

# ============================================================================
# XSS VULNERABILITIES (LOW SEVERITY)
# ============================================================================

def vulnerable_xss_low_1():
    """Simple string concatenation"""
    greeting = user_name + " welcome"

def vulnerable_xss_low_2():
    """Template string building"""
    message_template = "Hello " + username

# ============================================================================
# TEST ALL VULNERABILITY TYPES AND SEVERITY LEVELS
# ============================================================================

def test_all_vulnerabilities():
    print("=" * 80)
    print("COMPREHENSIVE VULNERABILITY TESTING - ALL TYPES AND SEVERITY LEVELS")
    print("=" * 80)
    
    # Test Command Injection
    print("\n🔴 COMMAND INJECTION VULNERABILITIES:")
    print("-" * 50)
    
    command_injection_code = '''
def vulnerable_command_1():
    user_input = request.form.get('filename')
    os.system("ls -la " + user_input)

def vulnerable_command_2():
    filename = request.args.get('file')
    subprocess.call("cat " + filename, shell=True)

def vulnerable_command_3():
    directory = request.form.get('dir')
    result = os.popen("ls " + directory).read()
    return result

def vulnerable_command_4():
    code = request.form.get('code')
    eval("print('" + code + "')")

def vulnerable_command_8():
    module_name = request.form.get('module')
    __import__(module_name)

def vulnerable_command_9():
    filepath = request.form.get('file')
    os.remove("/tmp/" + filepath)

def vulnerable_command_10():
    from string import Template
    template_str = request.form.get('template')
    template = Template("Hello $name")
    result = template.substitute(name=template_str)

def vulnerable_command_low_1():
    user_input = request.form.get('input')
    message = "Command: " + user_input

def vulnerable_command_low_2():
    filename = request.args.get('file')
    command = "ls " + filename

def vulnerable_command_low_3():
    user_path = request.form.get('path')
    full_path = "/home/user/" + user_path

def vulnerable_command_low_4():
    env_var = request.args.get('env')
    os.environ['CUSTOM_VAR'] = env_var

def vulnerable_command_low_5():
    config_value = request.form.get('config')
    config = {"setting": config_value}
'''
    
    command_result = scan_code_content_for_command_injection(command_injection_code, 'command_injection_test.py')
    print(f"Total vulnerabilities: {command_result['total_vulnerabilities']}")
    print(f"Severity breakdown: {command_result['severity_breakdown']}")
    for vuln in command_result['vulnerabilities']:
        print(f"  Line {vuln['line_number']}: {vuln['severity'].upper()} - {vuln['description']}")
    
    # Test SQL Injection
    print("\n🔴 SQL INJECTION VULNERABILITIES:")
    print("-" * 50)
    
    sql_injection_code = '''
def vulnerable_sql_high_1():
    user_id = request.form["user_id"]
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)

def vulnerable_sql_high_2():
    name = request.args.get("name")
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)

def vulnerable_sql_medium_1():
    sort_column = request.args.get("sort", "name")
    query = "ORDER BY " + sort_column

def vulnerable_sql_medium_2():
    limit_value = request.form.get("limit", "10")
    query = "LIMIT " + limit_value

def vulnerable_sql_low_1():
    prefix_name = user_prefix + suffix

def vulnerable_sql_low_2():
    table_name = "user_" + table_id
'''
    
    sql_result = scan_code_content_for_sql_injection(sql_injection_code, 'sql_injection_test.py')
    print(f"Total vulnerabilities: {sql_result['total_vulnerabilities']}")
    print(f"Severity breakdown: {sql_result['severity_breakdown']}")
    for vuln in sql_result['vulnerabilities']:
        print(f"  Line {vuln['line_number']}: {vuln['severity'].upper()} - {vuln['description']}")
    
    # Test XSS
    print("\n🔴 XSS VULNERABILITIES:")
    print("-" * 50)
    
    xss_code = '''
def vulnerable_xss_high_1():
    user_name = request.args.get("name")
    return f"<h1>Welcome {user_name}!</h1>"

def vulnerable_xss_high_2():
    content = request.form.get("content")
    script = f"document.getElementById('content').innerHTML = '{content}'"

def vulnerable_xss_high_3():
    user_code = request.args.get("code")
    result = eval("calculate_" + user_code)

def vulnerable_xss_medium_1():
    user_html = "{{ user_content|safe }}"

def vulnerable_xss_medium_2():
    from markupsafe import Markup
    user_input = request.args.get("input")
    safe_html = Markup(user_input)

def vulnerable_xss_low_1():
    greeting = user_name + " welcome"

def vulnerable_xss_low_2():
    message_template = "Hello " + username
'''
    
    xss_result = scan_code_content_for_xss(xss_code, 'xss_test.py')
    print(f"Total vulnerabilities: {xss_result['total_vulnerabilities']}")
    print(f"Severity breakdown: {xss_result['severity_breakdown']}")
    for vuln in xss_result['vulnerabilities']:
        print(f"  Line {vuln['line_number']}: {vuln['severity'].upper()} - {vuln['description']}")
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY:")
    print("=" * 80)
    print(f"Command Injection: {command_result['total_vulnerabilities']} vulnerabilities")
    print(f"SQL Injection: {sql_result['total_vulnerabilities']} vulnerabilities")
    print(f"XSS: {xss_result['total_vulnerabilities']} vulnerabilities")
    print(f"TOTAL: {command_result['total_vulnerabilities'] + sql_result['total_vulnerabilities'] + xss_result['total_vulnerabilities']} vulnerabilities")

if __name__ == "__main__":
    test_all_vulnerabilities()
    print("\n" + "=" * 80)
    print("This comprehensive test file contains:")
    print("- 15 Command Injection vulnerabilities (8 high, 2 medium, 5 low)")
    print("- 6 SQL Injection vulnerabilities (2 high, 2 medium, 2 low)")
    print("- 7 XSS vulnerabilities (3 high, 2 medium, 2 low)")
    print("- 2 Safe command injection functions")
    print("=" * 80) 