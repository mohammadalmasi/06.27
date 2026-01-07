def vulnerable_csrf_high_1():
    """Flask route with POST method without CSRF protection"""
    from flask import Flask, request, render_template
    
    app = Flask(__name__)
    
    @app.route('/submit', methods=['POST'])
    def submit_form():
        data = request.form.get('data')
        # Process form data without CSRF protection
        return render_template('result.html', data=data)