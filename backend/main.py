from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import sqlite3
from datetime import datetime, timedelta
import jwt
from functools import wraps
import tempfile
import zipfile

# Import XSS scanner functions
from scanners.xss.xss_scanner import (
    api_scan_xss,
    api_generate_xss_report,
    api_xss_sonarqube_export
)

# Import SQL injection scanner functions  
from scanners.sql_injection.sql_injection_scanner import (
    api_scan_sql_injection,
    api_generate_sql_injection_report,
    api_sql_injection_sonarqube_export
)

# Import Command injection scanner functions
from scanners.command_injection.command_injection_scanner import (
    api_scan_command_injection,
    api_generate_command_injection_report,
    api_command_injection_sonarqube_export
)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB upload limit
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'sql-injection-scanner-secret-key-2024')

# Enable CORS for all origins (production and development)
CORS(app, origins=["*"], 
     methods=["GET", "POST", "OPTIONS"], 
     allow_headers=["Content-Type", "Authorization"])

# Authentication configuration
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "a"

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # JWT is passed in the request header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]  # Bearer <token>
            except IndexError:
                return jsonify({'error': 'Token is missing!'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing!'}), 401
        
        try:
            # Decode the token
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            current_user = data['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def ensure_dirs():
    # Use /tmp directory which is writable on App Engine
    os.makedirs('/tmp/results', exist_ok=True)

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            # Generate JWT token with 1 hour expiration
            token = jwt.encode({
                'username': username,
                'exp': datetime.utcnow() + timedelta(hours=1)
            }, app.config['JWT_SECRET_KEY'], algorithm="HS256")
            
            return jsonify({
                'message': 'Login successful',
                'token': token,
                'username': username
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': f'Login error: {str(e)}'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/verify-token', methods=['POST'])
@token_required
def verify_token(current_user):
    return jsonify({
        'message': 'Token is valid',
        'username': current_user
    })

# XSS Scanner API endpoints
@app.route('/api/scan-xss', methods=['POST'])
@token_required
def scan_xss(current_user):
    """XSS vulnerability scanning endpoint"""
    return api_scan_xss(current_user)

@app.route('/api/generate-xss-report', methods=['POST'])
@token_required
def generate_xss_report(current_user):
    """Generate Word report for XSS vulnerabilities"""
    return api_generate_xss_report(current_user)

@app.route('/api/xss-sonarqube-export', methods=['POST'])
@token_required
def xss_sonarqube_export(current_user):
    """Export XSS vulnerabilities in SonarQube format"""
    return api_xss_sonarqube_export(current_user)

# SQL Injection Scanner API endpoints
@app.route('/api/scan-sql-injection', methods=['POST'])
@token_required
def scan_sql_injection(current_user):
    """SQL injection vulnerability scanning endpoint"""
    return api_scan_sql_injection(current_user)

@app.route('/api/generate-sql-injection-report', methods=['POST'])
@token_required
def generate_sql_injection_report(current_user):
    """Generate Word report for SQL injection vulnerabilities"""
    return api_generate_sql_injection_report(current_user)

@app.route('/api/sql-injection-sonarqube-export', methods=['POST'])
@token_required
def sql_injection_sonarqube_export(current_user):
    """Export SQL injection vulnerabilities in SonarQube format"""
    return api_sql_injection_sonarqube_export(current_user)

# Command Injection Scanner API endpoints
@app.route('/api/scan-command-injection', methods=['POST'])
@token_required
def scan_command_injection(current_user):
    """Command injection vulnerability scanning endpoint"""
    return api_scan_command_injection(current_user)

@app.route('/api/generate-command-injection-report', methods=['POST'])
@token_required
def generate_command_injection_report(current_user):
    """Generate Word report for command injection vulnerabilities"""
    return api_generate_command_injection_report(current_user)

@app.route('/api/command-injection-sonarqube-export', methods=['POST'])
@token_required
def command_injection_sonarqube_export(current_user):
    """Export command injection vulnerabilities in SonarQube format"""
    return api_command_injection_sonarqube_export(current_user)

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'scanners': ['xss', 'sql_injection', 'command_injection']
    })

# Initialize directories on startup
ensure_dirs()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug)


# cd /Users/mohammen.almasi/thesis/06.27 && source venv/bin/activate && cd backend && python main.py
# cd frontend && npm start