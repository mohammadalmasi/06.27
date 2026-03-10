# XSS VULNERABLE CODE

def vulnerable_code_auto_1():
    """Auto-generated vulnerable: HTML f-string with unescaped user input"""
    user_1 = request.args.get("name_1")
    return f"<h1>Welcome {user_1}!</h1>"


def vulnerable_code_auto_2():
    """Auto-generated vulnerable: HTML string concatenation with user input"""
    user_2 = request.args.get("name_2")
    return "<div>Hello " + user_2 + "</div>"


def vulnerable_code_auto_3():
    """Auto-generated vulnerable: Flask render_template_string with direct interpolation"""
    from flask import render_template_string

    name_3 = request.args.get("name_3")
    template = f"<p>User: {name_3}</p>"
    return render_template_string(template)


def vulnerable_code_auto_4():
    """Auto-generated vulnerable: Django HttpResponse with unescaped input"""
    from django.http import HttpResponse

    name_4 = request.GET.get("name_4")
    return HttpResponse(f"<span>{name_4}</span>")


def vulnerable_code_auto_5():
    """Auto-generated vulnerable: Markup() on raw user input"""
    from markupsafe import Markup

    raw_5 = request.args.get("raw_5")
    html_5 = Markup(raw_5)
    return f"<div>{html_5}</div>"


def vulnerable_code_auto_6():
    """Auto-generated vulnerable: Jinja2 |safe filter on user content"""
    user_content_6 = "{{ user_content_6|safe }}"
    return user_content_6


def vulnerable_code_auto_7():
    """Auto-generated vulnerable: innerHTML assignment with user input"""
    content_7 = request.form.get("content_7")
    script_7 = (
        "document.getElementById('content_7').innerHTML = '" + str(content_7) + "';"
    )
    return script_7


def vulnerable_code_auto_8():
    """Auto-generated vulnerable: document.write with user payload"""
    payload_8 = request.form.get("payload_8")
    script_8 = "document.write('" + str(payload_8) + "');"
    return script_8


def vulnerable_code_auto_9():
    """Auto-generated vulnerable: jQuery .html() with untrusted data"""
    data_9 = request.form.get("data_9")
    script_9 = "$('#result_9').html('<div>' + " + repr(data_9) + " + '</div>');"
    return script_9


def vulnerable_code_auto_10():
    """Auto-generated vulnerable: building script tag with user input"""
    js_10 = request.args.get("js_10")
    return "<script>" + js_10 + "</script>"


def vulnerable_code_auto_11():
    """Auto-generated vulnerable: attribute injection inside HTML"""
    href_11 = request.args.get("href_11")
    return f'<a href="{href_11}">click</a>'


def vulnerable_code_auto_12():
    """Auto-generated vulnerable: inline event handler with user input"""
    handler_12 = request.args.get("handler_12")
    return f'<button onclick="{handler_12}">Run</button>'


def vulnerable_code_auto_13():
    """Auto-generated vulnerable: HTML f-string with unescaped user input"""
    user_13 = request.args.get("name_13")
    return f"<h2>Profile for {user_13}</h2>"


def vulnerable_code_auto_14():
    """Auto-generated vulnerable: HTML string concatenation with user input"""
    user_14 = request.args.get("name_14")
    return "<p>User: " + user_14 + "</p>"


def vulnerable_code_auto_15():
    """Auto-generated vulnerable: Flask render_template_string with direct interpolation"""
    from flask import render_template_string

    name_15 = request.args.get("name_15")
    template = f"<div>User: {name_15}</div>"
    return render_template_string(template)


def vulnerable_code_auto_16():
    """Auto-generated vulnerable: Django HttpResponse with unescaped input"""
    from django.http import HttpResponse

    name_16 = request.GET.get("name_16")
    return HttpResponse(f"<p>{name_16}</p>")


def vulnerable_code_auto_17():
    """Auto-generated vulnerable: Markup() on raw user input"""
    from markupsafe import Markup

    raw_17 = request.args.get("raw_17")
    html_17 = Markup(raw_17)
    return f"<section>{html_17}</section>"


def vulnerable_code_auto_18():
    """Auto-generated vulnerable: Jinja2 |safe filter on user content"""
    user_content_18 = "{{ another_user_content_18|safe }}"
    return user_content_18


def vulnerable_code_auto_19():
    """Auto-generated vulnerable: innerHTML assignment with user input"""
    content_19 = request.form.get("content_19")
    script_19 = (
        "document.getElementById('content_19').innerHTML = '" + str(content_19) + "';"
    )
    return script_19


def vulnerable_code_auto_20():
    """Auto-generated vulnerable: document.write with user payload"""
    payload_20 = request.form.get("payload_20")
    script_20 = "document.write('" + str(payload_20) + "');"
    return script_20


def vulnerable_code_auto_21():
    """Auto-generated vulnerable: jQuery .html() with untrusted data"""
    data_21 = request.form.get("data_21")
    script_21 = "$('#result_21').html('<span>' + " + repr(data_21) + " + '</span>');"
    return script_21


def vulnerable_code_auto_22():
    """Auto-generated vulnerable: building script tag with user input"""
    js_22 = request.args.get("js_22")
    return "<script>" + js_22 + "</script>"


def vulnerable_code_auto_23():
    """Auto-generated vulnerable: attribute injection inside HTML"""
    href_23 = request.args.get("href_23")
    return f'<a href="{href_23}">open</a>'


def vulnerable_code_auto_24():
    """Auto-generated vulnerable: inline event handler with user input"""
    handler_24 = request.args.get("handler_24")
    return f'<img src="/x.png" onerror="{handler_24}">'


def vulnerable_code_auto_25():
    """Auto-generated vulnerable: JSON string with embedded HTML"""
    value_25 = request.args.get("value_25")
    return '{"message": "<b>' + value_25 + '</b>"}'


def vulnerable_code_auto_26():
    """Auto-generated vulnerable: template literal style concatenation"""
    name_26 = request.args.get("name_26")
    return "`Hello ${" + name_26 + "}`"


def vulnerable_code_auto_27():
    """Auto-generated vulnerable: unsafe comment rendering"""
    comment_27 = request.form.get("comment_27")
    return "<!-- " + comment_27 + " -->"


def vulnerable_code_auto_28():
    """Auto-generated vulnerable: raw HTML snippet returned"""
    html_28 = request.form.get("html_28")
    return html_28


def vulnerable_code_auto_29():
    """Auto-generated vulnerable: concatenation inside style attribute"""
    color_29 = request.args.get("color_29")
    return f'<div style="color:{color_29}">text</div>'


def vulnerable_code_auto_30():
    """Auto-generated vulnerable: building script URL with user-supplied src"""
    src_30 = request.args.get("src_30")
    return f'<script src="{src_30}"></script>'


def vulnerable_code_auto_31():
    """F-string with HTML and user input"""
    user_name = request.args.get("name")
    return f"<h1>Welcome {user_name}!</h1>"

def vulnerable_code_auto_32():
    """Direct innerHTML manipulation"""
    content = request.form.get("content")
    script = f"document.getElementById('content').innerHTML = '{content}'"

def vulnerable_code_auto_33():
    """eval() with user input"""
    user_code = request.args.get("code")
    result = eval("calculate_" + user_code)

 
def vulnerable_code_auto_34():
    """Using |safe filter (potential XSS if not validated)"""
    user_html = "{{ user_content|safe }}"

def vulnerable_code_auto_35():
    """Markup() usage"""
    from markupsafe import Markup
    user_input = request.args.get("input")
    safe_html = Markup(user_input)

def vulnerable_code_auto_36():
    """URL parameter usage"""
    search_term = URLSearchParams(window.location.search)
    return search_term

def vulnerable_code_auto_37():
    """jQuery .append() with HTML"""
    data = request.form.get("data")
    script = "$('#result').append('<div>' + data + '</div>')"
 
def vulnerable_code_auto_38():
    """Simple string concatenation"""
    greeting = user_name + " welcome"
    return greeting

def vulnerable_code_auto_39():
    """Template string building"""
    message_template = "Hello " + username
    return message_template

def vulnerable_code_auto_40():
    """Flask render_template_string with user input in template"""
    from flask import render_template_string
    user_input = request.args.get("name")
    # Dangerous: Injecting variable directly into the template string
    template = f"<h1>Hello {user_input}</h1>"
    return render_template_string(template)

def vulnerable_code_auto_41():
    """Django HttpResponse with unescaped input"""
    from django.http import HttpResponse
    user_input = request.GET.get("name")
    return HttpResponse(f"<div>{user_input}</div>")

def vulnerable_code_auto_42():
    """document.write() usage"""
    user_payload = request.form.get("payload")
    script = f"document.write('{user_payload}');"
    return script


# XSS SAFE CODE -------------------------------------------------------------


def safe_code_auto_1():
    """Auto-generated safe: HTML f-string using markupsafe.escape"""
    from markupsafe import escape

    user_1 = request.args.get("name_1")
    return f"<h1>Welcome {escape(user_1)}</h1>"


def safe_code_auto_2():
    """Auto-generated safe: HTML string with html.escape"""
    import html

    user_2 = request.args.get("name_2")
    safe_2 = html.escape(user_2 or "")
    return "<div>Hello " + safe_2 + "</div>"


def safe_code_auto_3():
    """Auto-generated safe: Flask render_template_string with context variable"""
    from flask import render_template_string

    name_3 = request.args.get("name_3")
    template = "<p>User: {{ name }}</p>"
    return render_template_string(template, name=name_3)


def safe_code_auto_4():
    """Auto-generated safe: Django HttpResponse with html.escape"""
    from django.http import HttpResponse
    import html

    name_4 = request.GET.get("name_4")
    safe_4 = html.escape(name_4 or "")
    return HttpResponse(f"<span>{safe_4}</span>")


def safe_code_auto_5():
    """Auto-generated safe: using bleach.clean before rendering"""
    import bleach

    raw_5 = request.args.get("raw_5")
    clean_5 = bleach.clean(raw_5 or "", strip=True)
    return f"<div>{clean_5}</div>"


def safe_code_auto_6():
    """Auto-generated safe: Jinja2 template without |safe filter"""
    user_content_6 = "{{ user_content_6 }}"
    return user_content_6


def safe_code_auto_7():
    """Auto-generated safe: using textContent instead of innerHTML"""
    import json

    content_7 = request.form.get("content_7")
    safe_js_string_7 = json.dumps(content_7)
    script_7 = (
        "document.getElementById('content_7').textContent = " + safe_js_string_7 + ";"
    )
    return script_7


def safe_code_auto_8():
    """Auto-generated safe: document.createElement with textContent"""
    import json

    payload_8 = request.form.get("payload_8")
    safe_js_string_8 = json.dumps(payload_8)
    script_8 = (
        "var n = document.createElement('div');"
        "n.textContent = "
        + safe_js_string_8
        + ";document.body.appendChild(n);"
    )
    return script_8


def safe_code_auto_9():
    """Auto-generated safe: jQuery .text() instead of .html()"""
    data_9 = request.form.get("data_9")
    script_9 = "$('#result_9').text(" + repr(data_9) + ");"
    return script_9


def safe_code_auto_10():
    """Auto-generated safe: script tag content sanitized with bleach"""
    import bleach

    js_10 = request.args.get("js_10")
    safe_js_10 = bleach.clean(js_10 or "", strip=True)
    return "<script>// sanitized\n" + safe_js_10 + "</script>"


def safe_code_auto_11():
    """Auto-generated safe: href validated against allowlist"""
    href_11 = request.args.get("href_11")
    allowed_11 = ("/home", "/profile", "/logout")
    if href_11 not in allowed_11:
        href_11 = "/home"
    return f'<a href="{href_11}">click</a>'


def safe_code_auto_12():
    """Auto-generated safe: fixed onclick handler, no user injection"""
    return '<button onclick="runSafeAction()">Run</button>'


def safe_code_auto_13():
    """Auto-generated safe: HTML f-string using markupsafe.escape"""
    from markupsafe import escape

    user_13 = request.args.get("name_13")
    return f"<h2>Profile for {escape(user_13)}</h2>"


def safe_code_auto_14():
    """Auto-generated safe: HTML string with html.escape"""
    import html

    user_14 = request.args.get("name_14")
    safe_14 = html.escape(user_14 or "")
    return "<p>User: " + safe_14 + "</p>"


def safe_code_auto_15():
    """Auto-generated safe: Flask render_template_string with context variable"""
    from flask import render_template_string

    name_15 = request.args.get("name_15")
    template = "<div>User: {{ name }}</div>"
    return render_template_string(template, name=name_15)


def safe_code_auto_16():
    """Auto-generated safe: Django HttpResponse with html.escape"""
    from django.http import HttpResponse
    import html

    name_16 = request.GET.get("name_16")
    safe_16 = html.escape(name_16 or "")
    return HttpResponse(f"<p>{safe_16}</p>")


def safe_code_auto_17():
    """Auto-generated safe: bleach.clean before Markup usage"""
    import bleach
    from markupsafe import Markup

    raw_17 = request.args.get("raw_17")
    clean_17 = bleach.clean(raw_17 or "", strip=True)
    html_17 = Markup(clean_17)
    return f"<section>{html_17}</section>"


def safe_code_auto_18():
    """Auto-generated safe: Jinja2 template without |safe filter"""
    user_content_18 = "{{ another_user_content_18 }}"
    return user_content_18


def safe_code_auto_19():
    """Auto-generated safe: using textContent instead of innerHTML"""
    import json

    content_19 = request.form.get("content_19")
    safe_js_string_19 = json.dumps(content_19)
    script_19 = (
        "document.getElementById('content_19').textContent = " + safe_js_string_19 + ";"
    )
    return script_19


def safe_code_auto_20():
    """Auto-generated safe: document.createElement with textContent"""
    import json

    payload_20 = request.form.get("payload_20")
    safe_js_string_20 = json.dumps(payload_20)
    script_20 = (
        "var n = document.createElement('span');"
        "n.textContent = "
        + safe_js_string_20
        + ";document.body.appendChild(n);"
    )
    return script_20


def safe_code_auto_21():
    """Auto-generated safe: jQuery .text() instead of .html()"""
    data_21 = request.form.get("data_21")
    script_21 = "$('#result_21').text(" + repr(data_21) + ");"
    return script_21


def safe_code_auto_22():
    """Auto-generated safe: strip potentially dangerous JS with bleach"""
    import bleach

    js_22 = request.args.get("js_22")
    safe_js_22 = bleach.clean(js_22 or "", strip=True)
    return "<script>// sanitized\n" + safe_js_22 + "</script>"


def safe_code_auto_23():
    """Auto-generated safe: href validated against allowlist"""
    href_23 = request.args.get("href_23")
    allowed_23 = ("/dashboard", "/settings", "/logout")
    if href_23 not in allowed_23:
        href_23 = "/dashboard"
    return f'<a href="{href_23}">open</a>'


def safe_code_auto_24():
    """Auto-generated safe: fixed onerror handler, no user injection"""
    return '<img src="/x.png" onerror="handleError()">'


def safe_code_auto_25():
    """Auto-generated safe: JSON string using html.escape"""
    import html

    value_25 = request.args.get("value_25")
    safe_25 = html.escape(value_25 or "")
    return '{"message": "<b>' + safe_25 + '</b>"}'


def safe_code_auto_26():
    """Auto-generated safe: template literal style escaped as text"""
    name_26 = request.args.get("name_26")
    return "`Hello ${name}` // " + str(name_26)


def safe_code_auto_27():
    """Auto-generated safe: comment content sanitized with bleach"""
    import bleach

    comment_27 = request.form.get("comment_27")
    clean_27 = bleach.clean(comment_27 or "", strip=True)
    return "<!-- " + clean_27 + " -->"


def safe_code_auto_28():
    """Auto-generated safe: only allow subset of HTML tags"""
    import bleach

    html_28 = request.form.get("html_28")
    clean_28 = bleach.clean(html_28 or "", tags=["b", "i", "u"], strip=True)
    return clean_28


def safe_code_auto_29():
    """Auto-generated safe: validate CSS color against allowlist"""
    color_29 = request.args.get("color_29")
    allowed_29 = {"red", "green", "blue", "black", "white"}
    if color_29 not in allowed_29:
        color_29 = "black"
    return f'<div style="color:{color_29}">text</div>'


def safe_code_auto_30():
    """Auto-generated safe: script src validated against known hosts"""
    src_30 = request.args.get("src_30")
    allowed_prefixes_30 = ("https://cdn.example.com/", "/static/js/")
    if not src_30 or not src_30.startswith(allowed_prefixes_30):
        src_30 = "/static/js/app.js"
    return f'<script src="{src_30}"></script>'


# XSS SAFE CODE -------------------------------------------------------------

def safe_code_auto_32():
    """Using markupsafe escape() for user input"""
    from markupsafe import escape
    user_name = request.args.get("name")
    return f"<h1>Welcome {escape(user_name)}!</h1>"

def safe_code_auto_33():
    """Safe DOM manipulation using textContent instead of innerHTML"""
    import json
    content = request.form.get("content")
    # json.dumps() safely escapes quotes and newlines for JavaScript
    safe_js_string = json.dumps(content) 
    script = f"document.getElementById('content').textContent = {safe_js_string}"
    return script

def safe_code_auto_34():
    """Safe template rendering (default auto-escaping in Jinja2)"""
    # Removing the |safe filter makes it secure
    user_html = "{{ user_content }}"
    return user_html

def safe_code_auto_35():
    """Safe jQuery usage with .text() instead of .append() with HTML"""
    data = request.form.get("data")
    script = "$('#result').text(data)"
    return script

def safe_code_auto_36():
    """Using an HTML sanitizer (like bleach) before rendering"""
    import bleach
    user_input = request.args.get("input")
    # Bleach sanitizes the input by removing/escaping dangerous tags
    clean_html = bleach.clean(user_input)
    return f"<div>{clean_html}</div>"

def safe_code_auto_37():
    """Flask render_template_string safe context passing"""
    from flask import render_template_string
    user_input = request.args.get("name")
    # Safe: Template string is static, user data is passed as context variable
    template = "<h1>Hello {{ name }}</h1>"
    return render_template_string(template, name=user_input)

def safe_code_auto_38():
    """Django HttpResponse with html.escape"""
    from django.http import HttpResponse
    import html
    user_input = request.GET.get("name")
    # Safe: using Python's built-in html.escape
    safe_input = html.escape(user_input)
    return HttpResponse(f"<div>{safe_input}</div>")

def safe_code_auto_39():
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

