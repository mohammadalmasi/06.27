#!/usr/bin/env python3
"""
Test file for command injection vulnerabilities
This file contains intentional security vulnerabilities for testing purposes.
DO NOT use this code in production!
"""

import os
import subprocess
import sys
from flask import request

def vulnerable_function_1():
    """Direct os.system with user input"""
    user_input = request.form.get('filename')
    os.system("ls -la " + user_input)  # Command injection vulnerability

def vulnerable_function_2():
    """subprocess.call with shell=True"""
    filename = request.args.get('file')
    subprocess.call("cat " + filename, shell=True)  # Command injection vulnerability

def vulnerable_function_3():
    """os.popen with concatenated input"""
    directory = request.form.get('dir')
    result = os.popen("ls " + directory).read()  # Command injection vulnerability
    return result

def vulnerable_function_4():
    """eval with user input"""
    code = request.form.get('code')
    eval("print('" + code + "')")  # Code injection vulnerability

def vulnerable_function_5():
    """exec with user input"""
    command = request.form.get('cmd')
    exec("os.system('" + command + "')")  # Code injection vulnerability

def vulnerable_function_6():
    """subprocess.run with shell=True"""
    user_cmd = request.form.get('command')
    subprocess.run(user_cmd, shell=True)  # Command injection vulnerability

def vulnerable_function_7():
    """subprocess.Popen with shell=True"""
    cmd = request.form.get('cmd')
    subprocess.Popen(cmd, shell=True)  # Command injection vulnerability

def vulnerable_function_8():
    """Dynamic import with user input"""
    module_name = request.form.get('module')
    __import__(module_name)  # Code injection vulnerability

def vulnerable_function_9():
    """os.remove with user input"""
    filepath = request.form.get('file')
    os.remove("/tmp/" + filepath)  # Path traversal vulnerability

def vulnerable_function_10():
    """Template injection"""
    from string import Template
    template_str = request.form.get('template')
    template = Template("Hello $name")
    result = template.substitute(name=template_str)  # Template injection vulnerability

def safe_function_1():
    """Safe subprocess usage"""
    filename = request.form.get('file')
    # Input validation
    if not filename or '..' in filename or '/' in filename:
        return "Invalid filename"
    
    # Safe subprocess usage
    subprocess.run(['ls', '-la', filename], shell=False)

def safe_function_2():
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
    
if __name__ == "__main__":
    print("This is a test file for command injection vulnerabilities")
    print("Total functions: 12 (10 vulnerable, 2 safe)") 