
# ============================================================================
# COMMAND INJECTION VULNERABILITIES (HIGH SEVERITY)
# ============================================================================

def vulnerable_command_high_1():
    """os.system with user input"""
    import os
    from flask import request
    
    user_input = request.args.get("ip")
    # Vulnerable: directly passing user input to system command
    os.system(f"ping -c 4 {user_input}")

def vulnerable_command_high_2():
    """subprocess.Popen with shell=True"""
    import subprocess
    from flask import request
    
    filename = request.form.get("file")
    # Vulnerable: shell=True and untrusted input
    subprocess.Popen("cat " + filename, shell=True)

def vulnerable_command_high_3():
    """eval() with user input"""
    from flask import request
    user_code = request.args.get("calc")
    # Vulnerable: evaluating untrusted string
    result = eval(user_code)

# ============================================================================
# COMMAND INJECTION VULNERABILITIES (MEDIUM SEVERITY)
# ============================================================================

def vulnerable_command_medium_1():
    """subprocess.call with potentially unsafe arguments"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-la")
    # Vulnerable if cmd/arg aren't properly validated, though no shell=True
    subprocess.call([cmd, arg])

def vulnerable_command_medium_2():
    """os.popen reading from untrusted source"""
    import os
    from flask import request
    
    dir_path = request.args.get("dir")
    # Vulnerable: popen executes in shell
    stream = os.popen('ls -l ' + dir_path)
    output = stream.read()

# ============================================================================
# COMMAND INJECTION VULNERABILITIES (LOW SEVERITY)
# ============================================================================

def vulnerable_command_low_1():
    """Safe usage but looks suspicious to static analyzers"""
    import subprocess
    
    # Safe: predefined command list, no shell=True
    command = ["ls", "-l", "/tmp"]
    subprocess.run(command)

def vulnerable_command_low_2():
    """Input validation before execution"""
    import os
    from flask import request
    
    ip = request.args.get("ip")
    # Safe if regex strictly enforces IP format
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        os.system(f"ping -c 4 {ip}")
