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

def vulnerable_code_auto_14():
    """os.system with user input"""
    import os
    from flask import request
    
    user_input = request.args.get("ip")
    # Vulnerable: directly passing user input to system command
    os.system(f"ping -c 4 {user_input}")


def vulnerable_code_auto_15():
    """subprocess.Popen with shell=True"""
    import subprocess
    from flask import request
    
    filename = request.form.get("file")
    # Vulnerable: shell=True and untrusted input
    subprocess.Popen("cat " + filename, shell=True)


def vulnerable_code_auto_16():
    """eval() with user input"""
    from flask import request
    user_code = request.args.get("calc")
    # Vulnerable: evaluating untrusted string
    result = eval(user_code)


def vulnerable_code_auto_17():
    """subprocess.call with potentially unsafe arguments"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-la")
    # Vulnerable if cmd/arg aren't properly validated, though no shell=True
    subprocess.call([cmd, arg])


def vulnerable_code_auto_18():
    """os.popen reading from untrusted source"""
    import os
    from flask import request
    
    dir_path = request.args.get("dir")
    # Vulnerable: popen executes in shell
    stream = os.popen('ls -l ' + dir_path)
    output = stream.read()


def vulnerable_code_auto_19():
    """Safe usage but looks suspicious to static analyzers"""
    import subprocess
    
    # Safe: predefined command list, no shell=True
    command = ["ls", "-l", "/tmp"]
    subprocess.run(command)


def vulnerable_code_auto_20():
    """Input validation before execution"""
    import os
    import re
    from flask import request
    
    ip = request.args.get("ip")
    # Safe if regex strictly enforces IP format
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        os.system(f"ping -c 4 {ip}")



def vulnerable_code_auto_21():
    """subprocess.run with shell=True and query param"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    # Vulnerable: shell=True and untrusted input
    subprocess.run(cmd, shell=True)



def vulnerable_code_auto_22():
    """subprocess.check_output with string formatting + shell=True"""
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    file_path = request.args.get("file", "/etc/passwd")
    # Vulnerable: shell=True and untrusted input in a shell command string
    subprocess.check_output(f"grep {pattern} {file_path}", shell=True)



def vulnerable_code_auto_23():
    """sh -c wrapper (command injection)"""
    import subprocess
    from flask import request
    
    user_cmd = request.args.get("cmd")
    # Vulnerable: forces a shell to interpret user input
    subprocess.run(["sh", "-c", user_cmd])



def vulnerable_code_auto_24():
    """os.system with headers input"""
    import os
    from flask import request
    
    host = request.headers.get("X-Host", "127.0.0.1")
    # Vulnerable: attacker controls part of the command line
    os.system("ping -c 1 " + host)



def vulnerable_code_auto_25():
    """os.system with request args (no sanitization)"""
    import os
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    # Vulnerable: attacker-controlled string reaches a shell command
    os.system(f"cat {filename}")



def vulnerable_code_auto_26():
    """subprocess.run with user-controlled command in argv"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-l")
    # Vulnerable: attacker can control which binary runs / arguments
    subprocess.run([cmd, arg], check=True)

 
# COMMAND INJECTION SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_27():
    """os.system with user input"""
    import os
    from flask import request
    
    user_input = request.args.get("ip")
    # Vulnerable: directly passing user input to system command
    os.system(f"ping -c 4 {user_input}")


def vulnerable_code_auto_28():
    """subprocess.Popen with shell=True"""
    import subprocess
    from flask import request
    
    filename = request.form.get("file")
    # Vulnerable: shell=True and untrusted input
    subprocess.Popen("cat " + filename, shell=True)


def vulnerable_code_auto_29():
    """eval() with user input"""
    from flask import request
    user_code = request.args.get("calc")
    # Vulnerable: evaluating untrusted string
    result = eval(user_code)


def vulnerable_code_auto_30():
    """subprocess.call with potentially unsafe arguments"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-la")
    # Vulnerable if cmd/arg aren't properly validated, though no shell=True
    subprocess.call([cmd, arg])


def vulnerable_code_auto_31():
    """os.popen reading from untrusted source"""
    import os
    from flask import request
    
    dir_path = request.args.get("dir")
    # Vulnerable: popen executes in shell
    stream = os.popen('ls -l ' + dir_path)
    output = stream.read()


def vulnerable_code_auto_32():
    """Safe usage but looks suspicious to static analyzers"""
    import subprocess
    
    # Safe: predefined command list, no shell=True
    command = ["ls", "-l", "/tmp"]
    subprocess.run(command)


def vulnerable_code_auto_33():
    """Input validation before execution"""
    import os
    import re
    from flask import request
    
    ip = request.args.get("ip")
    # Safe if regex strictly enforces IP format
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        os.system(f"ping -c 4 {ip}")



def vulnerable_code_auto_34():
    """subprocess.run with shell=True and query param"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    # Vulnerable: shell=True and untrusted input
    subprocess.run(cmd, shell=True)



def vulnerable_code_auto_35():
    """subprocess.check_output with string formatting + shell=True"""
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    file_path = request.args.get("file", "/etc/passwd")
    # Vulnerable: shell=True and untrusted input in a shell command string
    subprocess.check_output(f"grep {pattern} {file_path}", shell=True)



def vulnerable_code_auto_36():
    """sh -c wrapper (command injection)"""
    import subprocess
    from flask import request
    
    user_cmd = request.args.get("cmd")
    # Vulnerable: forces a shell to interpret user input
    subprocess.run(["sh", "-c", user_cmd])



def vulnerable_code_auto_37():
    """os.system with headers input"""
    import os
    from flask import request
    
    host = request.headers.get("X-Host", "127.0.0.1")
    # Vulnerable: attacker controls part of the command line
    os.system("ping -c 1 " + host)



def vulnerable_code_auto_38():
    """os.system with request args (no sanitization)"""
    import os
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    # Vulnerable: attacker-controlled string reaches a shell command
    os.system(f"cat {filename}")



def vulnerable_code_auto_39():
    """subprocess.run with user-controlled command in argv"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-l")
    # Vulnerable: attacker can control which binary runs / arguments
    subprocess.run([cmd, arg], check=True)

 
# COMMAND INJECTION SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_40():
    """os.system with user input"""
    import os
    from flask import request
    
    user_input = request.args.get("ip")
    # Vulnerable: directly passing user input to system command
    os.system(f"ping -c 4 {user_input}")


def vulnerable_code_auto_41():
    """subprocess.Popen with shell=True"""
    import subprocess
    from flask import request
    
    filename = request.form.get("file")
    # Vulnerable: shell=True and untrusted input
    subprocess.Popen("cat " + filename, shell=True)


def vulnerable_code_auto_42():
    """eval() with user input"""
    from flask import request
    user_code = request.args.get("calc")
    # Vulnerable: evaluating untrusted string
    result = eval(user_code)


def vulnerable_code_auto_43():
    """subprocess.call with potentially unsafe arguments"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-la")
    # Vulnerable if cmd/arg aren't properly validated, though no shell=True
    subprocess.call([cmd, arg])


def vulnerable_code_auto_44():
    """os.popen reading from untrusted source"""
    import os
    from flask import request
    
    dir_path = request.args.get("dir")
    # Vulnerable: popen executes in shell
    stream = os.popen('ls -l ' + dir_path)
    output = stream.read()


def vulnerable_code_auto_45():
    """Safe usage but looks suspicious to static analyzers"""
    import subprocess
    
    # Safe: predefined command list, no shell=True
    command = ["ls", "-l", "/tmp"]
    subprocess.run(command)


def vulnerable_code_auto_46():
    """Input validation before execution"""
    import os
    import re
    from flask import request
    
    ip = request.args.get("ip")
    # Safe if regex strictly enforces IP format
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        os.system(f"ping -c 4 {ip}")



def vulnerable_code_auto_47():
    """subprocess.run with shell=True and query param"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    # Vulnerable: shell=True and untrusted input
    subprocess.run(cmd, shell=True)



def vulnerable_code_auto_48():
    """subprocess.check_output with string formatting + shell=True"""
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    file_path = request.args.get("file", "/etc/passwd")
    # Vulnerable: shell=True and untrusted input in a shell command string
    subprocess.check_output(f"grep {pattern} {file_path}", shell=True)



def vulnerable_code_auto_49():
    """sh -c wrapper (command injection)"""
    import subprocess
    from flask import request
    
    user_cmd = request.args.get("cmd")
    # Vulnerable: forces a shell to interpret user input
    subprocess.run(["sh", "-c", user_cmd])



def vulnerable_code_auto_50():
    """os.system with headers input"""
    import os
    from flask import request
    
    host = request.headers.get("X-Host", "127.0.0.1")
    # Vulnerable: attacker controls part of the command line
    os.system("ping -c 1 " + host)



def vulnerable_code_auto_51():
    """os.system with request args (no sanitization)"""
    import os
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    # Vulnerable: attacker-controlled string reaches a shell command
    os.system(f"cat {filename}")



def vulnerable_code_auto_52():
    """subprocess.run with user-controlled command in argv"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-l")
    # Vulnerable: attacker can control which binary runs / arguments
    subprocess.run([cmd, arg], check=True)

 
# COMMAND INJECTION SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_53():
    """os.system with user input"""
    import os
    from flask import request
    
    user_input = request.args.get("ip")
    # Vulnerable: directly passing user input to system command
    os.system(f"ping -c 4 {user_input}")


def vulnerable_code_auto_54():
    """subprocess.Popen with shell=True"""
    import subprocess
    from flask import request
    
    filename = request.form.get("file")
    # Vulnerable: shell=True and untrusted input
    subprocess.Popen("cat " + filename, shell=True)


def vulnerable_code_auto_55():
    """eval() with user input"""
    from flask import request
    user_code = request.args.get("calc")
    # Vulnerable: evaluating untrusted string
    result = eval(user_code)


def vulnerable_code_auto_56():
    """subprocess.call with potentially unsafe arguments"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-la")
    # Vulnerable if cmd/arg aren't properly validated, though no shell=True
    subprocess.call([cmd, arg])


def vulnerable_code_auto_57():
    """os.popen reading from untrusted source"""
    import os
    from flask import request
    
    dir_path = request.args.get("dir")
    # Vulnerable: popen executes in shell
    stream = os.popen('ls -l ' + dir_path)
    output = stream.read()


def vulnerable_code_auto_58():
    """Safe usage but looks suspicious to static analyzers"""
    import subprocess
    
    # Safe: predefined command list, no shell=True
    command = ["ls", "-l", "/tmp"]
    subprocess.run(command)


def vulnerable_code_auto_59():
    """Input validation before execution"""
    import os
    import re
    from flask import request
    
    ip = request.args.get("ip")
    # Safe if regex strictly enforces IP format
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        os.system(f"ping -c 4 {ip}")



def vulnerable_code_auto_60():
    """subprocess.run with shell=True and query param"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    # Vulnerable: shell=True and untrusted input
    subprocess.run(cmd, shell=True)



def vulnerable_code_auto_61():
    """subprocess.check_output with string formatting + shell=True"""
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    file_path = request.args.get("file", "/etc/passwd")
    # Vulnerable: shell=True and untrusted input in a shell command string
    subprocess.check_output(f"grep {pattern} {file_path}", shell=True)



def vulnerable_code_auto_62():
    """sh -c wrapper (command injection)"""
    import subprocess
    from flask import request
    
    user_cmd = request.args.get("cmd")
    # Vulnerable: forces a shell to interpret user input
    subprocess.run(["sh", "-c", user_cmd])



def vulnerable_code_auto_63():
    """os.system with headers input"""
    import os
    from flask import request
    
    host = request.headers.get("X-Host", "127.0.0.1")
    # Vulnerable: attacker controls part of the command line
    os.system("ping -c 1 " + host)



def vulnerable_code_auto_64():
    """os.system with request args (no sanitization)"""
    import os
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    # Vulnerable: attacker-controlled string reaches a shell command
    os.system(f"cat {filename}")



def vulnerable_code_auto_65():
    """subprocess.run with user-controlled command in argv"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-l")
    # Vulnerable: attacker can control which binary runs / arguments
    subprocess.run([cmd, arg], check=True)

 
# COMMAND INJECTION SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_66():
    """os.system with user input"""
    import os
    from flask import request
    
    user_input = request.args.get("ip")
    # Vulnerable: directly passing user input to system command
    os.system(f"ping -c 4 {user_input}")


def vulnerable_code_auto_67():
    """subprocess.Popen with shell=True"""
    import subprocess
    from flask import request
    
    filename = request.form.get("file")
    # Vulnerable: shell=True and untrusted input
    subprocess.Popen("cat " + filename, shell=True)


def vulnerable_code_auto_68():
    """eval() with user input"""
    from flask import request
    user_code = request.args.get("calc")
    # Vulnerable: evaluating untrusted string
    result = eval(user_code)


def vulnerable_code_auto_69():
    """subprocess.call with potentially unsafe arguments"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-la")
    # Vulnerable if cmd/arg aren't properly validated, though no shell=True
    subprocess.call([cmd, arg])


def vulnerable_code_auto_70():
    """os.popen reading from untrusted source"""
    import os
    from flask import request
    
    dir_path = request.args.get("dir")
    # Vulnerable: popen executes in shell
    stream = os.popen('ls -l ' + dir_path)
    output = stream.read()


def vulnerable_code_auto_71():
    """Safe usage but looks suspicious to static analyzers"""
    import subprocess
    
    # Safe: predefined command list, no shell=True
    command = ["ls", "-l", "/tmp"]
    subprocess.run(command)


def vulnerable_code_auto_72():
    """Input validation before execution"""
    import os
    import re
    from flask import request
    
    ip = request.args.get("ip")
    # Safe if regex strictly enforces IP format
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        os.system(f"ping -c 4 {ip}")



def vulnerable_code_auto_73():
    """subprocess.run with shell=True and query param"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    # Vulnerable: shell=True and untrusted input
    subprocess.run(cmd, shell=True)



def vulnerable_code_auto_74():
    """subprocess.check_output with string formatting + shell=True"""
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    file_path = request.args.get("file", "/etc/passwd")
    # Vulnerable: shell=True and untrusted input in a shell command string
    subprocess.check_output(f"grep {pattern} {file_path}", shell=True)



def vulnerable_code_auto_75():
    """sh -c wrapper (command injection)"""
    import subprocess
    from flask import request
    
    user_cmd = request.args.get("cmd")
    # Vulnerable: forces a shell to interpret user input
    subprocess.run(["sh", "-c", user_cmd])



def vulnerable_code_auto_76():
    """os.system with headers input"""
    import os
    from flask import request
    
    host = request.headers.get("X-Host", "127.0.0.1")
    # Vulnerable: attacker controls part of the command line
    os.system("ping -c 1 " + host)



def vulnerable_code_auto_77():
    """os.system with request args (no sanitization)"""
    import os
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    # Vulnerable: attacker-controlled string reaches a shell command
    os.system(f"cat {filename}")



def vulnerable_code_auto_78():
    """subprocess.run with user-controlled command in argv"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-l")
    # Vulnerable: attacker can control which binary runs / arguments
    subprocess.run([cmd, arg], check=True)

 
# COMMAND INJECTION SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_79():
    """os.system with user input"""
    import os
    from flask import request
    
    user_input = request.args.get("ip")
    # Vulnerable: directly passing user input to system command
    os.system(f"ping -c 4 {user_input}")


def vulnerable_code_auto_80():
    """subprocess.Popen with shell=True"""
    import subprocess
    from flask import request
    
    filename = request.form.get("file")
    # Vulnerable: shell=True and untrusted input
    subprocess.Popen("cat " + filename, shell=True)


def vulnerable_code_auto_81():
    """eval() with user input"""
    from flask import request
    user_code = request.args.get("calc")
    # Vulnerable: evaluating untrusted string
    result = eval(user_code)


def vulnerable_code_auto_82():
    """subprocess.call with potentially unsafe arguments"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-la")
    # Vulnerable if cmd/arg aren't properly validated, though no shell=True
    subprocess.call([cmd, arg])


def vulnerable_code_auto_83():
    """os.popen reading from untrusted source"""
    import os
    from flask import request
    
    dir_path = request.args.get("dir")
    # Vulnerable: popen executes in shell
    stream = os.popen('ls -l ' + dir_path)
    output = stream.read()


def vulnerable_code_auto_84():
    """Safe usage but looks suspicious to static analyzers"""
    import subprocess
    
    # Safe: predefined command list, no shell=True
    command = ["ls", "-l", "/tmp"]
    subprocess.run(command)


def vulnerable_code_auto_85():
    """Input validation before execution"""
    import os
    import re
    from flask import request
    
    ip = request.args.get("ip")
    # Safe if regex strictly enforces IP format
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        os.system(f"ping -c 4 {ip}")



def vulnerable_code_auto_86():
    """subprocess.run with shell=True and query param"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    # Vulnerable: shell=True and untrusted input
    subprocess.run(cmd, shell=True)



def vulnerable_code_auto_87():
    """subprocess.check_output with string formatting + shell=True"""
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    file_path = request.args.get("file", "/etc/passwd")
    # Vulnerable: shell=True and untrusted input in a shell command string
    subprocess.check_output(f"grep {pattern} {file_path}", shell=True)



def vulnerable_code_auto_88():
    """sh -c wrapper (command injection)"""
    import subprocess
    from flask import request
    
    user_cmd = request.args.get("cmd")
    # Vulnerable: forces a shell to interpret user input
    subprocess.run(["sh", "-c", user_cmd])



def vulnerable_code_auto_89():
    """os.system with headers input"""
    import os
    from flask import request
    
    host = request.headers.get("X-Host", "127.0.0.1")
    # Vulnerable: attacker controls part of the command line
    os.system("ping -c 1 " + host)



def vulnerable_code_auto_90():
    """os.system with request args (no sanitization)"""
    import os
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    # Vulnerable: attacker-controlled string reaches a shell command
    os.system(f"cat {filename}")



def vulnerable_code_auto_91():
    """subprocess.run with user-controlled command in argv"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-l")
    # Vulnerable: attacker can control which binary runs / arguments
    subprocess.run([cmd, arg], check=True)

 
# COMMAND INJECTION SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_92():
    """os.system with user input"""
    import os
    from flask import request
    
    user_input = request.args.get("ip")
    # Vulnerable: directly passing user input to system command
    os.system(f"ping -c 4 {user_input}")


def vulnerable_code_auto_93():
    """subprocess.Popen with shell=True"""
    import subprocess
    from flask import request
    
    filename = request.form.get("file")
    # Vulnerable: shell=True and untrusted input
    subprocess.Popen("cat " + filename, shell=True)


def vulnerable_code_auto_94():
    """eval() with user input"""
    from flask import request
    user_code = request.args.get("calc")
    # Vulnerable: evaluating untrusted string
    result = eval(user_code)


def vulnerable_code_auto_95():
    """subprocess.call with potentially unsafe arguments"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-la")
    # Vulnerable if cmd/arg aren't properly validated, though no shell=True
    subprocess.call([cmd, arg])


def vulnerable_code_auto_96():
    """os.popen reading from untrusted source"""
    import os
    from flask import request
    
    dir_path = request.args.get("dir")
    # Vulnerable: popen executes in shell
    stream = os.popen('ls -l ' + dir_path)
    output = stream.read()


def vulnerable_code_auto_97():
    """Safe usage but looks suspicious to static analyzers"""
    import subprocess
    
    # Safe: predefined command list, no shell=True
    command = ["ls", "-l", "/tmp"]
    subprocess.run(command)


def vulnerable_code_auto_98():
    """Input validation before execution"""
    import os
    import re
    from flask import request
    
    ip = request.args.get("ip")
    # Safe if regex strictly enforces IP format
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        os.system(f"ping -c 4 {ip}")



def vulnerable_code_auto_99():
    """subprocess.run with shell=True and query param"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    # Vulnerable: shell=True and untrusted input
    subprocess.run(cmd, shell=True)



def vulnerable_code_auto_100():
    """subprocess.check_output with string formatting + shell=True"""
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    file_path = request.args.get("file", "/etc/passwd")
    # Vulnerable: shell=True and untrusted input in a shell command string
    subprocess.check_output(f"grep {pattern} {file_path}", shell=True)



def vulnerable_code_auto_101():
    """sh -c wrapper (command injection)"""
    import subprocess
    from flask import request
    
    user_cmd = request.args.get("cmd")
    # Vulnerable: forces a shell to interpret user input
    subprocess.run(["sh", "-c", user_cmd])



def vulnerable_code_auto_102():
    """os.system with headers input"""
    import os
    from flask import request
    
    host = request.headers.get("X-Host", "127.0.0.1")
    # Vulnerable: attacker controls part of the command line
    os.system("ping -c 1 " + host)



def vulnerable_code_auto_103():
    """os.system with request args (no sanitization)"""
    import os
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    # Vulnerable: attacker-controlled string reaches a shell command
    os.system(f"cat {filename}")



def vulnerable_code_auto_104():
    """subprocess.run with user-controlled command in argv"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-l")
    # Vulnerable: attacker can control which binary runs / arguments
    subprocess.run([cmd, arg], check=True)

 
# COMMAND INJECTION SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_105():
    """os.system with user input"""
    import os
    from flask import request
    
    user_input = request.args.get("ip")
    # Vulnerable: directly passing user input to system command
    os.system(f"ping -c 4 {user_input}")


def vulnerable_code_auto_106():
    """subprocess.Popen with shell=True"""
    import subprocess
    from flask import request
    
    filename = request.form.get("file")
    # Vulnerable: shell=True and untrusted input
    subprocess.Popen("cat " + filename, shell=True)


def vulnerable_code_auto_107():
    """eval() with user input"""
    from flask import request
    user_code = request.args.get("calc")
    # Vulnerable: evaluating untrusted string
    result = eval(user_code)


def vulnerable_code_auto_108():
    """subprocess.call with potentially unsafe arguments"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-la")
    # Vulnerable if cmd/arg aren't properly validated, though no shell=True
    subprocess.call([cmd, arg])


def vulnerable_code_auto_109():
    """os.popen reading from untrusted source"""
    import os
    from flask import request
    
    dir_path = request.args.get("dir")
    # Vulnerable: popen executes in shell
    stream = os.popen('ls -l ' + dir_path)
    output = stream.read()


def vulnerable_code_auto_110():
    """Safe usage but looks suspicious to static analyzers"""
    import subprocess
    
    # Safe: predefined command list, no shell=True
    command = ["ls", "-l", "/tmp"]
    subprocess.run(command)


def vulnerable_code_auto_111():
    """Input validation before execution"""
    import os
    import re
    from flask import request
    
    ip = request.args.get("ip")
    # Safe if regex strictly enforces IP format
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        os.system(f"ping -c 4 {ip}")



def vulnerable_code_auto_112():
    """subprocess.run with shell=True and query param"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    # Vulnerable: shell=True and untrusted input
    subprocess.run(cmd, shell=True)



def vulnerable_code_auto_113():
    """subprocess.check_output with string formatting + shell=True"""
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    file_path = request.args.get("file", "/etc/passwd")
    # Vulnerable: shell=True and untrusted input in a shell command string
    subprocess.check_output(f"grep {pattern} {file_path}", shell=True)



def vulnerable_code_auto_114():
    """sh -c wrapper (command injection)"""
    import subprocess
    from flask import request
    
    user_cmd = request.args.get("cmd")
    # Vulnerable: forces a shell to interpret user input
    subprocess.run(["sh", "-c", user_cmd])



def vulnerable_code_auto_115():
    """os.system with headers input"""
    import os
    from flask import request
    
    host = request.headers.get("X-Host", "127.0.0.1")
    # Vulnerable: attacker controls part of the command line
    os.system("ping -c 1 " + host)



def vulnerable_code_auto_116():
    """os.system with request args (no sanitization)"""
    import os
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    # Vulnerable: attacker-controlled string reaches a shell command
    os.system(f"cat {filename}")



def vulnerable_code_auto_117():
    """subprocess.run with user-controlled command in argv"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-l")
    # Vulnerable: attacker can control which binary runs / arguments
    subprocess.run([cmd, arg], check=True)

 
# COMMAND INJECTION SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_118():
    """os.system with user input"""
    import os
    from flask import request
    
    user_input = request.args.get("ip")
    # Vulnerable: directly passing user input to system command
    os.system(f"ping -c 4 {user_input}")


def vulnerable_code_auto_119():
    """subprocess.Popen with shell=True"""
    import subprocess
    from flask import request
    
    filename = request.form.get("file")
    # Vulnerable: shell=True and untrusted input
    subprocess.Popen("cat " + filename, shell=True)


def vulnerable_code_auto_120():
    """eval() with user input"""
    from flask import request
    user_code = request.args.get("calc")
    # Vulnerable: evaluating untrusted string
    result = eval(user_code)


def vulnerable_code_auto_121():
    """subprocess.call with potentially unsafe arguments"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-la")
    # Vulnerable if cmd/arg aren't properly validated, though no shell=True
    subprocess.call([cmd, arg])


def vulnerable_code_auto_122():
    """os.popen reading from untrusted source"""
    import os
    from flask import request
    
    dir_path = request.args.get("dir")
    # Vulnerable: popen executes in shell
    stream = os.popen('ls -l ' + dir_path)
    output = stream.read()


def vulnerable_code_auto_123():
    """Safe usage but looks suspicious to static analyzers"""
    import subprocess
    
    # Safe: predefined command list, no shell=True
    command = ["ls", "-l", "/tmp"]
    subprocess.run(command)


def vulnerable_code_auto_124():
    """Input validation before execution"""
    import os
    import re
    from flask import request
    
    ip = request.args.get("ip")
    # Safe if regex strictly enforces IP format
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        os.system(f"ping -c 4 {ip}")



def vulnerable_code_auto_125():
    """subprocess.run with shell=True and query param"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    # Vulnerable: shell=True and untrusted input
    subprocess.run(cmd, shell=True)



def vulnerable_code_auto_126():
    """subprocess.check_output with string formatting + shell=True"""
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    file_path = request.args.get("file", "/etc/passwd")
    # Vulnerable: shell=True and untrusted input in a shell command string
    subprocess.check_output(f"grep {pattern} {file_path}", shell=True)



def vulnerable_code_auto_127():
    """sh -c wrapper (command injection)"""
    import subprocess
    from flask import request
    
    user_cmd = request.args.get("cmd")
    # Vulnerable: forces a shell to interpret user input
    subprocess.run(["sh", "-c", user_cmd])



def vulnerable_code_auto_128():
    """os.system with headers input"""
    import os
    from flask import request
    
    host = request.headers.get("X-Host", "127.0.0.1")
    # Vulnerable: attacker controls part of the command line
    os.system("ping -c 1 " + host)



def vulnerable_code_auto_129():
    """os.system with request args (no sanitization)"""
    import os
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    # Vulnerable: attacker-controlled string reaches a shell command
    os.system(f"cat {filename}")



def vulnerable_code_auto_130():
    """subprocess.run with user-controlled command in argv"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-l")
    # Vulnerable: attacker can control which binary runs / arguments
    subprocess.run([cmd, arg], check=True)

 
# COMMAND INJECTION SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_131():
    """os.system with user input"""
    import os
    from flask import request
    
    user_input = request.args.get("ip")
    # Vulnerable: directly passing user input to system command
    os.system(f"ping -c 4 {user_input}")


def vulnerable_code_auto_132():
    """subprocess.Popen with shell=True"""
    import subprocess
    from flask import request
    
    filename = request.form.get("file")
    # Vulnerable: shell=True and untrusted input
    subprocess.Popen("cat " + filename, shell=True)


def vulnerable_code_auto_133():
    """eval() with user input"""
    from flask import request
    user_code = request.args.get("calc")
    # Vulnerable: evaluating untrusted string
    result = eval(user_code)


def vulnerable_code_auto_134():
    """subprocess.call with potentially unsafe arguments"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-la")
    # Vulnerable if cmd/arg aren't properly validated, though no shell=True
    subprocess.call([cmd, arg])


def vulnerable_code_auto_135():
    """os.popen reading from untrusted source"""
    import os
    from flask import request
    
    dir_path = request.args.get("dir")
    # Vulnerable: popen executes in shell
    stream = os.popen('ls -l ' + dir_path)
    output = stream.read()


def vulnerable_code_auto_136():
    """Safe usage but looks suspicious to static analyzers"""
    import subprocess
    
    # Safe: predefined command list, no shell=True
    command = ["ls", "-l", "/tmp"]
    subprocess.run(command)


def vulnerable_code_auto_137():
    """Input validation before execution"""
    import os
    import re
    from flask import request
    
    ip = request.args.get("ip")
    # Safe if regex strictly enforces IP format
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        os.system(f"ping -c 4 {ip}")



def vulnerable_code_auto_138():
    """subprocess.run with shell=True and query param"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    # Vulnerable: shell=True and untrusted input
    subprocess.run(cmd, shell=True)



def vulnerable_code_auto_139():
    """subprocess.check_output with string formatting + shell=True"""
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    file_path = request.args.get("file", "/etc/passwd")
    # Vulnerable: shell=True and untrusted input in a shell command string
    subprocess.check_output(f"grep {pattern} {file_path}", shell=True)



def vulnerable_code_auto_140():
    """sh -c wrapper (command injection)"""
    import subprocess
    from flask import request
    
    user_cmd = request.args.get("cmd")
    # Vulnerable: forces a shell to interpret user input
    subprocess.run(["sh", "-c", user_cmd])



def vulnerable_code_auto_141():
    """os.system with headers input"""
    import os
    from flask import request
    
    host = request.headers.get("X-Host", "127.0.0.1")
    # Vulnerable: attacker controls part of the command line
    os.system("ping -c 1 " + host)



def vulnerable_code_auto_142():
    """os.system with request args (no sanitization)"""
    import os
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    # Vulnerable: attacker-controlled string reaches a shell command
    os.system(f"cat {filename}")



def vulnerable_code_auto_143():
    """subprocess.run with user-controlled command in argv"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-l")
    # Vulnerable: attacker can control which binary runs / arguments
    subprocess.run([cmd, arg], check=True)

 
# COMMAND INJECTION SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_144():
    """os.system with user input"""
    import os
    from flask import request
    
    user_input = request.args.get("ip")
    # Vulnerable: directly passing user input to system command
    os.system(f"ping -c 4 {user_input}")


def vulnerable_code_auto_145():
    """subprocess.Popen with shell=True"""
    import subprocess
    from flask import request
    
    filename = request.form.get("file")
    # Vulnerable: shell=True and untrusted input
    subprocess.Popen("cat " + filename, shell=True)


def vulnerable_code_auto_146():
    """eval() with user input"""
    from flask import request
    user_code = request.args.get("calc")
    # Vulnerable: evaluating untrusted string
    result = eval(user_code)


def vulnerable_code_auto_147():
    """subprocess.call with potentially unsafe arguments"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-la")
    # Vulnerable if cmd/arg aren't properly validated, though no shell=True
    subprocess.call([cmd, arg])


def vulnerable_code_auto_148():
    """os.popen reading from untrusted source"""
    import os
    from flask import request
    
    dir_path = request.args.get("dir")
    # Vulnerable: popen executes in shell
    stream = os.popen('ls -l ' + dir_path)
    output = stream.read()


def vulnerable_code_auto_149():
    """Safe usage but looks suspicious to static analyzers"""
    import subprocess
    
    # Safe: predefined command list, no shell=True
    command = ["ls", "-l", "/tmp"]
    subprocess.run(command)


def vulnerable_code_auto_150():
    """Input validation before execution"""
    import os
    import re
    from flask import request
    
    ip = request.args.get("ip")
    # Safe if regex strictly enforces IP format
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        os.system(f"ping -c 4 {ip}")



def vulnerable_code_auto_151():
    """subprocess.run with shell=True and query param"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    # Vulnerable: shell=True and untrusted input
    subprocess.run(cmd, shell=True)



def vulnerable_code_auto_152():
    """subprocess.check_output with string formatting + shell=True"""
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    file_path = request.args.get("file", "/etc/passwd")
    # Vulnerable: shell=True and untrusted input in a shell command string
    subprocess.check_output(f"grep {pattern} {file_path}", shell=True)



def vulnerable_code_auto_153():
    """sh -c wrapper (command injection)"""
    import subprocess
    from flask import request
    
    user_cmd = request.args.get("cmd")
    # Vulnerable: forces a shell to interpret user input
    subprocess.run(["sh", "-c", user_cmd])



def vulnerable_code_auto_154():
    """os.system with headers input"""
    import os
    from flask import request
    
    host = request.headers.get("X-Host", "127.0.0.1")
    # Vulnerable: attacker controls part of the command line
    os.system("ping -c 1 " + host)



def vulnerable_code_auto_155():
    """os.system with request args (no sanitization)"""
    import os
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    # Vulnerable: attacker-controlled string reaches a shell command
    os.system(f"cat {filename}")



def vulnerable_code_auto_156():
    """subprocess.run with user-controlled command in argv"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-l")
    # Vulnerable: attacker can control which binary runs / arguments
    subprocess.run([cmd, arg], check=True)

 
# COMMAND INJECTION SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_157():
    """os.system with user input"""
    import os
    from flask import request
    
    user_input = request.args.get("ip")
    # Vulnerable: directly passing user input to system command
    os.system(f"ping -c 4 {user_input}")


def vulnerable_code_auto_158():
    """subprocess.Popen with shell=True"""
    import subprocess
    from flask import request
    
    filename = request.form.get("file")
    # Vulnerable: shell=True and untrusted input
    subprocess.Popen("cat " + filename, shell=True)


def vulnerable_code_auto_159():
    """eval() with user input"""
    from flask import request
    user_code = request.args.get("calc")
    # Vulnerable: evaluating untrusted string
    result = eval(user_code)


def vulnerable_code_auto_160():
    """subprocess.call with potentially unsafe arguments"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-la")
    # Vulnerable if cmd/arg aren't properly validated, though no shell=True
    subprocess.call([cmd, arg])


def vulnerable_code_auto_161():
    """os.popen reading from untrusted source"""
    import os
    from flask import request
    
    dir_path = request.args.get("dir")
    # Vulnerable: popen executes in shell
    stream = os.popen('ls -l ' + dir_path)
    output = stream.read()


def vulnerable_code_auto_162():
    """Safe usage but looks suspicious to static analyzers"""
    import subprocess
    
    # Safe: predefined command list, no shell=True
    command = ["ls", "-l", "/tmp"]
    subprocess.run(command)


def vulnerable_code_auto_163():
    """Input validation before execution"""
    import os
    import re
    from flask import request
    
    ip = request.args.get("ip")
    # Safe if regex strictly enforces IP format
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        os.system(f"ping -c 4 {ip}")



def vulnerable_code_auto_164():
    """subprocess.run with shell=True and query param"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    # Vulnerable: shell=True and untrusted input
    subprocess.run(cmd, shell=True)



def vulnerable_code_auto_165():
    """subprocess.check_output with string formatting + shell=True"""
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    file_path = request.args.get("file", "/etc/passwd")
    # Vulnerable: shell=True and untrusted input in a shell command string
    subprocess.check_output(f"grep {pattern} {file_path}", shell=True)



def vulnerable_code_auto_166():
    """sh -c wrapper (command injection)"""
    import subprocess
    from flask import request
    
    user_cmd = request.args.get("cmd")
    # Vulnerable: forces a shell to interpret user input
    subprocess.run(["sh", "-c", user_cmd])



def vulnerable_code_auto_167():
    """os.system with headers input"""
    import os
    from flask import request
    
    host = request.headers.get("X-Host", "127.0.0.1")
    # Vulnerable: attacker controls part of the command line
    os.system("ping -c 1 " + host)



def vulnerable_code_auto_168():
    """os.system with request args (no sanitization)"""
    import os
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    # Vulnerable: attacker-controlled string reaches a shell command
    os.system(f"cat {filename}")



def vulnerable_code_auto_169():
    """subprocess.run with user-controlled command in argv"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-l")
    # Vulnerable: attacker can control which binary runs / arguments
    subprocess.run([cmd, arg], check=True)

 
# COMMAND INJECTION SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_170():
    """os.system with user input"""
    import os
    from flask import request
    
    user_input = request.args.get("ip")
    # Vulnerable: directly passing user input to system command
    os.system(f"ping -c 4 {user_input}")


def vulnerable_code_auto_171():
    """subprocess.Popen with shell=True"""
    import subprocess
    from flask import request
    
    filename = request.form.get("file")
    # Vulnerable: shell=True and untrusted input
    subprocess.Popen("cat " + filename, shell=True)


def vulnerable_code_auto_172():
    """eval() with user input"""
    from flask import request
    user_code = request.args.get("calc")
    # Vulnerable: evaluating untrusted string
    result = eval(user_code)


def vulnerable_code_auto_173():
    """subprocess.call with potentially unsafe arguments"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-la")
    # Vulnerable if cmd/arg aren't properly validated, though no shell=True
    subprocess.call([cmd, arg])


def vulnerable_code_auto_174():
    """os.popen reading from untrusted source"""
    import os
    from flask import request
    
    dir_path = request.args.get("dir")
    # Vulnerable: popen executes in shell
    stream = os.popen('ls -l ' + dir_path)
    output = stream.read()


def vulnerable_code_auto_175():
    """Safe usage but looks suspicious to static analyzers"""
    import subprocess
    
    # Safe: predefined command list, no shell=True
    command = ["ls", "-l", "/tmp"]
    subprocess.run(command)


def vulnerable_code_auto_176():
    """Input validation before execution"""
    import os
    import re
    from flask import request
    
    ip = request.args.get("ip")
    # Safe if regex strictly enforces IP format
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        os.system(f"ping -c 4 {ip}")



def vulnerable_code_auto_177():
    """subprocess.run with shell=True and query param"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    # Vulnerable: shell=True and untrusted input
    subprocess.run(cmd, shell=True)



def vulnerable_code_auto_178():
    """subprocess.check_output with string formatting + shell=True"""
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    file_path = request.args.get("file", "/etc/passwd")
    # Vulnerable: shell=True and untrusted input in a shell command string
    subprocess.check_output(f"grep {pattern} {file_path}", shell=True)



def vulnerable_code_auto_179():
    """sh -c wrapper (command injection)"""
    import subprocess
    from flask import request
    
    user_cmd = request.args.get("cmd")
    # Vulnerable: forces a shell to interpret user input
    subprocess.run(["sh", "-c", user_cmd])



def vulnerable_code_auto_180():
    """os.system with headers input"""
    import os
    from flask import request
    
    host = request.headers.get("X-Host", "127.0.0.1")
    # Vulnerable: attacker controls part of the command line
    os.system("ping -c 1 " + host)



def vulnerable_code_auto_181():
    """os.system with request args (no sanitization)"""
    import os
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    # Vulnerable: attacker-controlled string reaches a shell command
    os.system(f"cat {filename}")



def vulnerable_code_auto_182():
    """subprocess.run with user-controlled command in argv"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-l")
    # Vulnerable: attacker can control which binary runs / arguments
    subprocess.run([cmd, arg], check=True)

 
# COMMAND INJECTION SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_183():
    """os.system with user input"""
    import os
    from flask import request
    
    user_input = request.args.get("ip")
    # Vulnerable: directly passing user input to system command
    os.system(f"ping -c 4 {user_input}")


def vulnerable_code_auto_184():
    """subprocess.Popen with shell=True"""
    import subprocess
    from flask import request
    
    filename = request.form.get("file")
    # Vulnerable: shell=True and untrusted input
    subprocess.Popen("cat " + filename, shell=True)


def vulnerable_code_auto_185():
    """eval() with user input"""
    from flask import request
    user_code = request.args.get("calc")
    # Vulnerable: evaluating untrusted string
    result = eval(user_code)


def vulnerable_code_auto_186():
    """subprocess.call with potentially unsafe arguments"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-la")
    # Vulnerable if cmd/arg aren't properly validated, though no shell=True
    subprocess.call([cmd, arg])


def vulnerable_code_auto_187():
    """os.popen reading from untrusted source"""
    import os
    from flask import request
    
    dir_path = request.args.get("dir")
    # Vulnerable: popen executes in shell
    stream = os.popen('ls -l ' + dir_path)
    output = stream.read()


def vulnerable_code_auto_188():
    """Safe usage but looks suspicious to static analyzers"""
    import subprocess
    
    # Safe: predefined command list, no shell=True
    command = ["ls", "-l", "/tmp"]
    subprocess.run(command)


def vulnerable_code_auto_189():
    """Input validation before execution"""
    import os
    import re
    from flask import request
    
    ip = request.args.get("ip")
    # Safe if regex strictly enforces IP format
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        os.system(f"ping -c 4 {ip}")



def vulnerable_code_auto_190():
    """subprocess.run with shell=True and query param"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    # Vulnerable: shell=True and untrusted input
    subprocess.run(cmd, shell=True)



def vulnerable_code_auto_191():
    """subprocess.check_output with string formatting + shell=True"""
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    file_path = request.args.get("file", "/etc/passwd")
    # Vulnerable: shell=True and untrusted input in a shell command string
    subprocess.check_output(f"grep {pattern} {file_path}", shell=True)



def vulnerable_code_auto_192():
    """sh -c wrapper (command injection)"""
    import subprocess
    from flask import request
    
    user_cmd = request.args.get("cmd")
    # Vulnerable: forces a shell to interpret user input
    subprocess.run(["sh", "-c", user_cmd])



def vulnerable_code_auto_193():
    """os.system with headers input"""
    import os
    from flask import request
    
    host = request.headers.get("X-Host", "127.0.0.1")
    # Vulnerable: attacker controls part of the command line
    os.system("ping -c 1 " + host)



def vulnerable_code_auto_194():
    """os.system with request args (no sanitization)"""
    import os
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    # Vulnerable: attacker-controlled string reaches a shell command
    os.system(f"cat {filename}")



def vulnerable_code_auto_195():
    """subprocess.run with user-controlled command in argv"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-l")
    # Vulnerable: attacker can control which binary runs / arguments
    subprocess.run([cmd, arg], check=True)

 
# COMMAND INJECTION SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_196():
    """os.system with user input"""
    import os
    from flask import request
    
    user_input = request.args.get("ip")
    # Vulnerable: directly passing user input to system command
    os.system(f"ping -c 4 {user_input}")


def vulnerable_code_auto_197():
    """subprocess.Popen with shell=True"""
    import subprocess
    from flask import request
    
    filename = request.form.get("file")
    # Vulnerable: shell=True and untrusted input
    subprocess.Popen("cat " + filename, shell=True)


def vulnerable_code_auto_198():
    """eval() with user input"""
    from flask import request
    user_code = request.args.get("calc")
    # Vulnerable: evaluating untrusted string
    result = eval(user_code)


def vulnerable_code_auto_199():
    """subprocess.call with potentially unsafe arguments"""
    import subprocess
    from flask import request
    
    cmd = request.args.get("cmd", "ls")
    arg = request.args.get("arg", "-la")
    # Vulnerable if cmd/arg aren't properly validated, though no shell=True
    subprocess.call([cmd, arg])


def vulnerable_code_auto_200():
    """os.popen reading from untrusted source"""
    import os
    from flask import request
    
    dir_path = request.args.get("dir")
    # Vulnerable: popen executes in shell
    stream = os.popen('ls -l ' + dir_path)
    output = stream.read()


def safe_code_auto_8():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_9():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_10():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_11():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_12():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_13():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_14():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_15():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_16():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_17():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_18():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_19():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_20():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_21():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_22():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_23():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_24():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_25():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_26():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_27():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_28():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_29():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_30():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_31():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_32():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_33():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_34():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_35():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_36():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_37():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_38():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_39():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_40():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_41():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_42():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_43():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_44():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_45():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_46():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_47():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_48():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_49():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_50():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_51():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_52():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_53():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_54():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_55():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_56():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_57():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_58():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_59():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_60():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_61():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_62():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_63():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_64():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_65():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_66():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_67():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_68():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_69():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_70():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_71():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_72():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_73():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_74():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_75():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_76():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_77():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_78():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_79():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_80():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_81():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_82():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_83():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_84():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_85():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_86():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_87():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_88():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_89():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_90():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_91():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_92():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_93():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_94():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_95():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_96():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_97():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_98():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_99():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_100():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_101():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_102():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_103():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_104():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_105():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_106():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_107():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_108():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_109():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_110():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_111():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_112():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_113():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_114():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_115():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_116():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_117():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_118():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_119():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_120():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_121():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_122():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_123():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_124():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_125():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_126():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_127():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_128():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_129():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_130():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_131():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_132():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_133():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_134():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_135():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_136():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_137():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_138():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_139():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_140():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_141():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_142():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_143():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_144():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_145():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_146():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_147():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_148():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_149():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_150():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_151():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_152():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_153():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_154():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_155():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_156():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_157():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_158():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_159():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_160():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_161():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_162():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_163():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_164():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_165():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_166():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_167():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_168():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_169():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_170():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_171():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_172():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_173():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_174():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_175():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_176():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_177():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_178():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_179():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_180():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_181():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_182():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_183():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_184():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_185():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_186():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_187():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_188():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_189():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_190():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_191():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_192():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_193():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



def safe_code_auto_194():
    """Safe: send user data via stdin; argv is constant"""
    import subprocess
    from flask import request
    
    data = request.args.get("data", "")
    subprocess.run(["wc", "-c"], input=data, text=True, check=True, capture_output=True)



def safe_code_auto_195():
    """Safe: build a shell command using shlex.quote for the dynamic part"""
    import shlex
    import subprocess
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)



def safe_code_auto_196():
    """Safe: constant argv list with absolute path"""
    import subprocess
    
    subprocess.run(["/bin/ls", "-la", "/tmp"], check=True)

def safe_code_auto_197():
    """Safe: constant argv list, no shell, no user input"""
    import subprocess
    
    subprocess.run(["ls", "-l", "/tmp"], check=True)



def safe_code_auto_198():
    """Safe: sanitize user input before shell execution (shlex.quote)"""
    import os
    import shlex
    from flask import request
    
    filename = request.args.get("file", "test.txt")
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")



def safe_code_auto_199():
    """Safe: execute a fixed binary; user input not used in command"""
    import subprocess
    from flask import request
    
    _ignored = request.args.get("anything")
    subprocess.run(["echo", "hello"], check=True)



def safe_code_auto_200():
    """Safe: sanitize user input even when passed as argv"""
    import shlex
    import subprocess
    from flask import request
    
    pattern = request.args.get("pattern", "root")
    safe_pattern = shlex.quote(pattern)
    subprocess.run(["grep", "-F", safe_pattern, "/etc/passwd"], check=True)



