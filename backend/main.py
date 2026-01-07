from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import sqlite3
import json
from datetime import datetime, timedelta
# import jwt
# from functools import wraps
import tempfile
import zipfile
import uuid
import subprocess
from pathlib import Path

# Import XSS scanner functions
from scanners.xss.xss_scanner import (
    api_scan_xss,
    api_generate_xss_report
)

# Import SQL injection scanner functions  
from scanners.sql_injection.sql_injection_scanner import (
    api_scan_sql_injection,
    api_generate_sql_injection_report
)

# Import Command injection scanner functions
from scanners.command_injection.command_injection_scanner import (
    api_scan_command_injection,
    api_generate_command_injection_report
)

# Import CSRF scanner functions
from scanners.csrf.csrf_scanner import (
    api_scan_csrf,
    api_generate_csrf_report
)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB upload limit
# app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'sql-injection-scanner-secret-key-2024')

# Enable CORS for all origins (production and development)
CORS(app, origins=["*"], 
     methods=["GET", "POST", "OPTIONS"], 
     allow_headers=["Content-Type", "Authorization"])

# Authentication configuration
# ADMIN_USERNAME = "admin"
# ADMIN_PASSWORD = "a"

# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = None
#         
#         # JWT is passed in the request header
#         if 'Authorization' in request.headers:
#             auth_header = request.headers['Authorization']
#             try:
#                 token = auth_header.split(" ")[1]  # Bearer <token>
#             except IndexError:
#                 return jsonify({'error': 'Token is missing!'}), 401
#         
#         if not token:
#             return jsonify({'error': 'Token is missing!'}), 401
#         
#         try:
#             # Decode the token
#             data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
#             current_user = data['username']
#         except IndexError
#             return jsonify({'error': 'Token has expired!'}), 401
#         except jwt.InvalidTokenError:
#             return jsonify({'error': 'Token is invalid!'}), 401
#         
#         return f(current_user, *args, **kwargs)
#     
#     return decorated

def ensure_dirs():
    # Use /tmp directory which is writable on App Engine
    os.makedirs('/tmp/results', exist_ok=True)
    # Ensure ML upload directory exists
    ml_uploads = Path(__file__).parent / 'ml' / 'api' / 'uploads'
    ml_uploads.mkdir(parents=True, exist_ok=True)

# @app.route('/api/login', methods=['POST'])
# def login():
#     try:
#         data = request.get_json()
#         username = data.get('username')
#         password = data.get('password')
#         
#         if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
#             # Generate JWT token with 1 hour expiration
#             token = jwt.encode({
#                 'username': username,
#                 'exp': datetime.utcnow() + timedelta(hours=1)
#             }, app.config['JWT_SECRET_KEY'], algorithm="HS256")
#             
#             return jsonify({
#                 'message': 'Login successful',
#                 'token': token,
#                 'username': username
#             })
#         else:
#             return jsonify({'error': 'Invalid credentials'}), 401
#     except Exception as e:
#         return jsonify({'error': f'Login error: {str(e)}'}), 500

# @app.route('/api/logout', methods=['POST'])
# def logout():
#     return jsonify({'message': 'Logged out successfully'})

# @app.route('/api/verify-token', methods=['POST'])
# @token_required
# def verify_token(current_user):
#     return jsonify({
#         'message': 'Token is valid',
#         'username': current_user
#     })

# XSS Scanner API endpoints
@app.route('/api/scan-xss', methods=['POST'])
# @token_required
def scan_xss():
    """XSS vulnerability scanning endpoint"""
    return api_scan_xss("anonymous")

@app.route('/api/generate-xss-report', methods=['POST'])
# @token_required
def generate_xss_report():
    """Generate Word report for XSS vulnerabilities"""
    return api_generate_xss_report("anonymous")


# SQL Injection Scanner API endpoints
@app.route('/api/scan-sql-injection', methods=['POST'])
# @token_required
def scan_sql_injection():
    """SQL injection vulnerability scanning endpoint"""
    return api_scan_sql_injection("anonymous")

@app.route('/api/generate-sql-injection-report', methods=['POST'])
# @token_required
def generate_sql_injection_report():
    """Generate Word report for SQL injection vulnerabilities"""
    return api_generate_sql_injection_report("anonymous")


# Command Injection Scanner API endpoints
@app.route('/api/scan-command-injection', methods=['POST'])
# @token_required
def scan_command_injection():
    """Command injection vulnerability scanning endpoint"""
    return api_scan_command_injection("anonymous")

@app.route('/api/generate-command-injection-report', methods=['POST'])
# @token_required
def generate_command_injection_report():
    """Generate Word report for command injection vulnerabilities"""
    return api_generate_command_injection_report("anonymous")


# CSRF Scanner API endpoints
@app.route('/api/scan-csrf', methods=['POST'])
# @token_required
def scan_csrf():
    """CSRF vulnerability scanning endpoint"""
    return api_scan_csrf("anonymous")

@app.route('/api/generate-csrf-report', methods=['POST'])
# @token_required
def generate_csrf_report():
    """Generate Word report for CSRF vulnerabilities"""
    return api_generate_csrf_report("anonymous")


# Configuration endpoint
@app.route('/api/scanner-config', methods=['GET'])
def get_scanner_config():
    """Get scanner configuration"""
    try:
        config_path = os.path.join(os.path.dirname(__file__), 'scanner_config.json')
        with open(config_path, 'r') as f:
            config = json.load(f)
        return jsonify(config)
    except Exception as e:
        return jsonify({'error': f'Failed to load configuration: {str(e)}'}), 500

# ML-based analysis endpoint
@app.route('/api/scan-ml', methods=['POST'])
def scan_ml():
    """Run machine learning based analysis using LSTM models (Atiqullah Ahmadzai’s project)."""
    try:
        data = request.get_json(force=True)
        vuln_type = (data.get('type') or '').lower()
        code = data.get('code', '')
        filename = data.get('filename') or 'code.py'

        if not code or not vuln_type:
            return jsonify({'error': 'type and code are required'}), 400

        # Map UI types to model modes
        mode_map = {
            'sql': 'sql',
            'xss': 'xss',
            'command': 'command_injection',
            'csrf': 'xsrf'
        }
        if vuln_type not in mode_map:
            return jsonify({'error': f'Unsupported type: {vuln_type}'}), 400
        mode = mode_map[vuln_type]

        # Prepare upload folder and file
        uid = uuid.uuid4().hex
        uploads_dir = Path(__file__).parent / 'ml' / 'api' / 'uploads' / uid
        uploads_dir.mkdir(parents=True, exist_ok=True)
        file_path = uploads_dir / filename
        file_path.write_text(code)

        # Choose python interpreter for ML
        backend_root = Path(__file__).parent
        ml_python_candidates = [
            backend_root / 'mlvenv' / 'bin' / 'python',
            Path(__file__).parent.parent / 'venv' / 'bin' / 'python',
        ]
        python_bin = None
        for candidate in ml_python_candidates:
            if candidate.exists():
                python_bin = str(candidate)
                break
        if python_bin is None:
            python_bin = 'python3'

        # Call ML pipeline in dedicated env (mlvenv) to avoid TF incompatibilities in main venv.
        ml_api_cwd = backend_root / 'ml' / 'api'
        analyzer_script = backend_root / 'ml' / 'lib' / 'analyze.py'

        try:
            completed = subprocess.run(
                [python_bin, str(analyzer_script), mode, uid, filename],
                cwd=str(ml_api_cwd),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300
            )
        except subprocess.CalledProcessError as e:
            return jsonify({
                'status': 'error',
                'type': vuln_type,
                'mode': mode,
                'upload_id': uid,
                'filename': filename,
                'message': 'ML analysis failed',
                'stderr': e.stderr[-1000:],
                'stdout': e.stdout[-1000:]
            }), 500
        except subprocess.TimeoutExpired:
            return jsonify({
                'status': 'timeout',
                'type': vuln_type,
                'mode': mode,
                'upload_id': uid,
                'filename': filename,
                'message': 'ML analysis timed out'
            }), 504

        try:
            analyzer_result = json.loads((completed.stdout or '').strip() or '{}')
        except json.JSONDecodeError:
            analyzer_result = {
                'status': 'error',
                'message': 'Invalid ML analyzer output (expected JSON)',
                'stdout': (completed.stdout or '')[-1000:],
                'stderr': (completed.stderr or '')[-1000:]
            }

        if analyzer_result.get('status') != 'completed':
            return jsonify({
                'status': 'error',
                'type': vuln_type,
                'mode': mode,
                'upload_id': uid,
                'filename': filename,
                'message': analyzer_result.get('message') or 'ML analysis error',
                'stderr': (completed.stderr or '')[-1000:],
                'stdout': (completed.stdout or '')[-1000:]
            }), 500

        # Keep response compatible with existing UI fields and add static-like outputs for ML.
        return jsonify({
            'status': 'completed',
            'type': vuln_type,
            'mode': mode,
            'upload_id': uid,
            'filename': filename,
            'prediction': analyzer_result.get('prediction'),
            'windows': analyzer_result.get('windows', []),
            'vulnerabilities': analyzer_result.get('vulnerabilities', []),
            'highlighted_code': analyzer_result.get('highlighted_code'),
            'original_code': analyzer_result.get('original_code', code),
            # image_url is optional now (older pipeline produced it)
            'image_url': analyzer_result.get('image_url')
        })
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500

@app.route('/api/ml-output/<string:uid>/<path:filename>', methods=['GET'])
def get_ml_output(uid: str, filename: str):
    """Serve generated ML visualization images from ml/api/uploads/<uid>/output."""
    try:
        backend_root = Path(__file__).parent
        file_path = backend_root / 'ml' / 'api' / 'uploads' / uid / 'output' / filename
        if not file_path.exists():
            return jsonify({'error': 'File not found'}), 404
        return send_file(str(file_path), mimetype='image/png')
    except Exception as e:
        return jsonify({'error': f'Failed to serve file: {str(e)}'}), 500

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'scanners': ['xss', 'sql_injection', 'command_injection', 'csrf']
    })

# Initialize directories on startup
ensure_dirs()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug)


# cd /Users/mohammen.almasi/thesis/06.27 && source venv/bin/activate && cd backend && python main.py
# cd frontend && npm start