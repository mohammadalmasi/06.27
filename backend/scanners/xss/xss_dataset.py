# XSS VULNERABLE CODE
 
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
    return search_term

def vulnerable_xss_medium_4():
    """jQuery .append() with HTML"""
    data = request.form.get("data")
    script = "$('#result').append('<div>' + data + '</div>')"
 
def vulnerable_xss_low_1():
    """Simple string concatenation"""
    greeting = user_name + " welcome"
    return greeting

def vulnerable_xss_low_2():
    """Template string building"""
    message_template = "Hello " + username
    return message_template

    def vulnerable_xss_high_4():
    """Flask render_template_string with user input in template"""
    from flask import render_template_string
    user_input = request.args.get("name")
    # Dangerous: Injecting variable directly into the template string
    template = f"<h1>Hello {user_input}</h1>"
    return render_template_string(template)

def vulnerable_xss_high_5():
    """Django HttpResponse with unescaped input"""
    from django.http import HttpResponse
    user_input = request.GET.get("name")
    return HttpResponse(f"<div>{user_input}</div>")

def vulnerable_xss_medium_5():
    """document.write() usage"""
    user_payload = request.form.get("payload")
    script = f"document.write('{user_payload}');"
    return script

# ============================================================================
# XSS SAFE CODE
# ============================================================================

def safe_xss_1():
    """Using markupsafe escape() for user input"""
    from markupsafe import escape
    user_name = request.args.get("name")
    return f"<h1>Welcome {escape(user_name)}!</h1>"

def safe_xss_2():
    """Safe DOM manipulation using textContent instead of innerHTML"""
    import json
    content = request.form.get("content")
    # json.dumps() safely escapes quotes and newlines for JavaScript
    safe_js_string = json.dumps(content) 
    script = f"document.getElementById('content').textContent = {safe_js_string}"
    return script

def safe_xss_3():
    """Safe template rendering (default auto-escaping in Jinja2)"""
    # Removing the |safe filter makes it secure
    user_html = "{{ user_content }}"
    return user_html

def safe_xss_4():
    """Safe jQuery usage with .text() instead of .append() with HTML"""
    data = request.form.get("data")
    script = "$('#result').text(data)"
    return script

def safe_xss_5():
    """Using an HTML sanitizer (like bleach) before rendering"""
    import bleach
    user_input = request.args.get("input")
    # Bleach sanitizes the input by removing/escaping dangerous tags
    clean_html = bleach.clean(user_input)
    return f"<div>{clean_html}</div>"

def safe_xss_6():
    """Flask render_template_string safe context passing"""
    from flask import render_template_string
    user_input = request.args.get("name")
    # Safe: Template string is static, user data is passed as context variable
    template = "<h1>Hello {{ name }}</h1>"
    return render_template_string(template, name=user_input)

def safe_xss_7():
    """Django HttpResponse with html.escape"""
    from django.http import HttpResponse
    import html
    user_input = request.GET.get("name")
    # Safe: using Python's built-in html.escape
    safe_input = html.escape(user_input)
    return HttpResponse(f"<div>{safe_input}</div>")

def safe_xss_8():
    """Safe DOM manipulation with document.createElement"""
    import json
    content = request.form.get("content")
    safe_js_string = json.dumps(content)
    # Safe: Using textContent on a newly created element
    script = f"""
    var div = document.createElement('div');
    div.textContent = {safe_js_string};
    document.body.appendChild(div);
    """
    return script

