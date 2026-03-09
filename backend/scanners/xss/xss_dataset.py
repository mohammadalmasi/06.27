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
    content = request.form.get("content")
    # textContent automatically escapes HTML
    script = f"document.getElementById('content').textContent = '{content}'"
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

