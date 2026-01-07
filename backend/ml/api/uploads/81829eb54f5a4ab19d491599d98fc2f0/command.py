def vulnerable_command_3():
    """os.popen with concatenated input"""
    directory = request.form.get('dir')
    result = os.popen("ls " + directory).read()  # Command injection vulnerability
    return result