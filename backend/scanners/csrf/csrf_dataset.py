# CSRF VULNERABLE CODE



# CSRF SAFE CODE -------------------------------------------------------------

def safe_code_auto_1():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_2():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_3():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_4():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def vulnerable_code_auto_9():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_10():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_11():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_12():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_13():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_14():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_15():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_16():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_17():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_18():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_19():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_20():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_21():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_22():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_23():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_24():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_25():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_26():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_27():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_28():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_29():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_30():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_31():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_32():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_33():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_34():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_35():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_36():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_37():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_38():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_39():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_40():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_41():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_42():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_43():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_44():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_45():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_46():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_47():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_48():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_49():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_50():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_51():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_52():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_53():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_54():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_55():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_56():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_57():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_58():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_59():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_60():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_61():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_62():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_63():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_64():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_65():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_66():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_67():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_68():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_69():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_70():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_71():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_72():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_73():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_74():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_75():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_76():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_77():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_78():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_79():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_80():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_81():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_82():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_83():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_84():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_85():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_86():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_87():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_88():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_89():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_90():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_91():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_92():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_93():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_94():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_95():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_96():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_97():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_98():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_99():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_100():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_101():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_102():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_103():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_104():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_105():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_106():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_107():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_108():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_109():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_110():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_111():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_112():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_113():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_114():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_115():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_116():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_117():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_118():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_119():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_120():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_121():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_122():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_123():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_124():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_125():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_126():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_127():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_128():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_129():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_130():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_131():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_132():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_133():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_134():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_135():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_136():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_137():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_138():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_139():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_140():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_141():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_142():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_143():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_144():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_145():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_146():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_147():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_148():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_149():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_150():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_151():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_152():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_153():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_154():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_155():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_156():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_157():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_158():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_159():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_160():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_161():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_162():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_163():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_164():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_165():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_166():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_167():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_168():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_169():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_170():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_171():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_172():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_173():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_174():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_175():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_176():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_177():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_178():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_179():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_180():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_181():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_182():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_183():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_184():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_185():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_186():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_187():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_188():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_189():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_190():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_191():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_192():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


# CSRF SAFE CODE -------------------------------------------------------------


def vulnerable_code_auto_193():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_194():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_195():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_196():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_197():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_198():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_199():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_200():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403


def vulnerable_code_auto_201():
    """Missing CSRF protection on state-changing endpoint"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    # Vulnerable: Explicitly disabling CSRF protection on a POST view
    @csrf_exempt
    def update_password(request):
        if request.method == "POST":
            new_pass = request.POST.get("password")
            request.user.set_password(new_pass)
            request.user.save()
            return HttpResponse("Password updated")


def vulnerable_code_auto_202():
    """State change via GET request"""
    from flask import request
    
    # Vulnerable: State modification using a GET request (CSRF tokens usually aren't checked on GET)
    @app.route('/transfer_funds', methods=['GET'])
    def transfer():
        amount = request.args.get('amount')
        to_account = request.args.get('to')
        user = get_current_user()
        user.balance -= int(amount)
        user.save()
        return "Funds transferred"


def vulnerable_code_auto_203():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"


def vulnerable_code_auto_204():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")


def vulnerable_code_auto_205():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"


def vulnerable_code_auto_206():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")


def vulnerable_code_auto_207():
    """Custom token check that always passes"""
    from django.http import HttpResponse

    # Vulnerable: Fake or broken CSRF check
    def validate_csrf(request):
        return True  # Always returns True

    def update_settings(request):
        if request.method == "POST" and validate_csrf(request):
            request.user.settings = request.POST.get("settings")
            request.user.save()
            return HttpResponse("Settings updated")


def vulnerable_code_auto_8():
    """Relies only on Referer/Origin without token"""
    from flask import request

    # Vulnerable: No CSRF token; only checks origin (can be spoofed in some setups)
    @app.route("/confirm_order", methods=["POST"])
    def confirm_order():
        if request.headers.get("Origin") == "https://mysite.com":
            order_id = request.form.get("order_id")
            confirm_order_in_db(order_id)
            return "Order confirmed"
        return "Forbidden", 403



# CSRF SAFE CODE -------------------------------------------------------------

def safe_code_auto_5():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_6():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_7():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_8():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_9():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_10():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_11():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_12():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_13():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_14():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_15():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_16():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_17():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_18():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_19():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_20():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_21():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_22():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_23():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_24():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_25():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_26():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_27():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_28():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_29():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_30():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_31():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_32():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_33():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_34():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_35():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_36():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_37():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_38():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_39():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_40():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_41():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_42():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_43():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_44():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_45():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_46():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_47():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_48():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_49():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_50():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_51():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_52():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_53():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_54():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_55():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_56():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_57():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_58():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_59():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_60():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_61():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_62():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_63():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_64():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_65():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_66():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_67():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_68():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_69():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_70():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_71():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_72():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_73():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_74():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_75():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_76():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_77():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_78():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_79():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_80():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_81():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_82():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_83():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_84():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_85():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_86():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_87():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_88():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_89():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_90():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_91():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_92():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_93():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_94():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_95():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_96():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_97():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_98():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_99():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_100():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_101():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_102():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_103():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_104():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_105():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_106():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_107():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_108():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_109():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_110():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_111():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_112():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_113():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_114():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_115():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_116():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_117():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_118():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_119():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_120():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_121():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_122():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_123():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_124():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_125():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_126():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_127():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_128():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_129():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_130():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_131():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_132():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_133():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_134():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_135():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_136():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_137():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_138():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_139():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_140():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_141():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_142():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_143():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_144():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_145():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_146():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_147():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_148():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_149():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_150():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_151():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_152():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_153():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_154():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_155():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_156():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_157():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_158():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_159():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_160():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_161():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_162():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_163():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_164():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_165():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_166():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_167():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_168():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_169():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_170():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_171():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_172():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_173():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_174():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_175():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_176():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_177():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_178():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_179():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_180():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_181():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_182():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_183():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_184():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_185():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_186():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_187():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_188():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_189():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_190():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_191():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_192():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_193():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_194():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_195():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_196():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

def safe_code_auto_197():
    """Explicit CSRF token validation in Django"""
    from django.http import HttpResponse
    from django.middleware.csrf import get_token

    # Safe: Uses Django's built-in CSRF protection and token
    def update_avatar(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        # Django's CsrfViewMiddleware validates request.POST['csrfmiddlewaretoken']
        request.user.avatar_url = request.POST.get("avatar_url")
        request.user.save()
        return HttpResponse("Avatar updated")



def safe_code_auto_198():
    """Flask with CSRF protection via extension"""
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

    # Safe: Flask-WTF CSRFProtect validates token on POST/PUT/DELETE/PATCH
    @app.route("/change_username", methods=["POST"])
    def change_username():
        new_name = request.form.get("username")
        current_user.username = new_name
        db.session.commit()
        return "Username updated"



def safe_code_auto_199():
    """Idempotent GET read-only; state change only via protected POST"""
    from django.http import JsonResponse

    # Safe: GET is read-only; no state change
    def get_preferences(request):
        if request.method == "GET":
            return JsonResponse({"preferences": request.user.preferences})
        return JsonResponse({"error": "Use POST to update"}, status=405)

    # Safe: Actual update requires POST with CSRF (middleware enabled)
    def update_preferences(request):
        if request.method == "POST":
            request.user.preferences = request.POST.get("preferences")
            request.user.save()
            return JsonResponse({"ok": True})
        return JsonResponse({"error": "Method not allowed"}, status=405)



def safe_code_auto_200():
    """Double-submit cookie / custom token check implemented correctly"""
    from django.http import HttpResponse
    import secrets

    # Safe: Validates CSRF token from cookie vs body
    def get_csrf_token():
        return secrets.token_urlsafe(32)

    def update_notifications(request):
        if request.method != "POST":
            return HttpResponse("Method not allowed", status=405)
        token_cookie = request.cookies.get("csrf_token")
        token_body = request.POST.get("csrf_token")
        if not token_cookie or not token_body or not secrets.compare_digest(token_cookie, token_body):
            return HttpResponse("Invalid CSRF token", status=403)
        request.user.notification_prefs = request.POST.get("prefs")
        request.user.save()
        return HttpResponse("Notifications updated")

