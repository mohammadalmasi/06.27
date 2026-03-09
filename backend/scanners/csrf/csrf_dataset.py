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
