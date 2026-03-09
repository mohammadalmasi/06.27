# CSRF VULNERABLE CODE
def vulnerable_code1():
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

def vulnerable_code2():
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

def vulnerable_code3():
    """Custom CSRF exemption mechanisms"""
    
    # Vulnerable: Custom decorator or mechanism that bypasses standard CSRF
    @disable_csrf
    def change_email(request):
        email = request.POST.get("email")
        request.user.email = email
        request.user.save()
        return "Email changed"

def vulnerable_code4():
    """Safe state change with proper method and default CSRF"""
    
    # Safe: Standard POST endpoint in a framework with default CSRF middleware enabled
    def update_profile(request):
        if request.method == "POST":
            # Assuming Django CSRF middleware is active
            request.user.bio = request.POST.get("bio")
            request.user.save()
            return HttpResponse("Profile updated")

def vulnerable_code5():
    """POST without CSRF token validation"""
    from flask import request

    # Vulnerable: Accepts POST but never checks CSRF token
    @app.route("/delete_account", methods=["POST"])
    def delete_account():
        user = get_current_user()
        user.delete()
        return "Account deleted"

def vulnerable_code6():
    """State change via GET with sensitive action"""
    from django.http import HttpResponse

    # Vulnerable: GET used for destructive action (no CSRF protection on GET)
    def unsubscribe(request):
        if request.method == "GET":
            user = request.user
            user.newsletter_subscribed = False
            user.save()
            return HttpResponse("Unsubscribed")

def vulnerable_code7():
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

def vulnerable_code8():
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


# SAFE CODE

def safe_code1():
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


def safe_code2():
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


def safe_code3():
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


def safe_code4():
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
