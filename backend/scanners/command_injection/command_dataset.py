# COMMAND INJECTION VULNERABLE CODE

def vulnerable_code_auto_1():
    """os.system with user input"""
    import os
    from flask import request
    
    user_input = request.args.get("ip")
    # Vulnerable: directly passing user input to system command
    os.system(f"ping -c 4 {user_input}")

def vulnerable_code_auto_2():
    """subprocess.Popen with shell=True"""
    import subprocess
    from flask import request
    
    filename = request.form.get("file")
    # Vulnerable: shell=True and untrusted input
    subprocess.Popen("cat " + filename, shell=True)

def vulnerable_code_auto_3():
    """eval() with user input"""
    from flask import request
    user_code = request.args.get("calc")
    # Vulnerable: evaluating untrusted string
    result = eval(user_code)

def vulnerable_code_auto_4():
    """subprocess.call with potentially unsafe arguments"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-la")
    # Vulnerable if cmd/arg aren't properly validated, though no shell=True
    subprocess.call([cmd, arg])

def vulnerable_code_auto_5():
    """os.popen reading from untrusted source"""
    import os
    from flask import request
    
    dir_path = request.args.get("dir")
    # Vulnerable: popen executes in shell
    stream = os.popen('ls -l ' + dir_path)
    output = stream.read()

def vulnerable_code_auto_6():
    """Safe usage but looks suspicious to static analyzers"""
    import subprocess
    
    # Safe: predefined command list, no shell=True
    command = ["ls", "-l", "/tmp"]
    subprocess.run(command)

def vulnerable_code_auto_7():
    """Input validation before execution"""
    import os
    import re
    from flask import request
    
    ip = request.args.get("ip")
    # Safe if regex strictly enforces IP format
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        os.system(f"ping -c 4 {ip}")


def vulnerable_code_auto_8():
    """subprocess.run with shell=True and query param"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    # Vulnerable: shell=True and untrusted input
    subprocess.run(cmd, shell=True)


def vulnerable_code_auto_9():
    """subprocess.check_output with string formatting + shell=True"""
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    file_path = request.args.get("file", "/etc/passwd")
    # Vulnerable: shell=True and untrusted input in a shell command string
    subprocess.check_output(f"grep {pattern} {file_path}", shell=True)


def vulnerable_code_auto_10():
    """sh -c wrapper (command injection)"""
    import subprocess
    from flask import request
    
    user_cmd = request.args.get("cmd")
    # Vulnerable: forces a shell to interpret user input
    subprocess.run(["sh", "-c", user_cmd])


def vulnerable_code_auto_11():
    """os.system with headers input"""
    import os
    from flask import request
    
    host = request.headers.get("X-Host", "127.0.0.1")
    # Vulnerable: attacker controls part of the command line
    os.system("ping -c 1 " + host)


def vulnerable_code_auto_12():
    """os.system with request args (no sanitization)"""
    import os
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    # Vulnerable: attacker-controlled string reaches a shell command
    os.system(f"cat {filename}")


def vulnerable_code_auto_13():
    """subprocess.run with user-controlled command in argv"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-l")
    # Vulnerable: attacker can control which binary runs / arguments
    subprocess.run([cmd, arg], check=True)

 
# COMMAND INJECTION SAFE CODE -------------------------------------------------------------

def safe_code_auto_1():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)


def safe_code_auto_2():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")


def safe_code_auto_3():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)


def safe_code_auto_4():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)


def safe_code_auto_5():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)


def safe_code_auto_6():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)


def safe_code_auto_7():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)
