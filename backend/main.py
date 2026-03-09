import os
import uuid
import json
import sqlite3
import zipfile
import tempfile
import subprocess
from pathlib import Path
from flask_cors import CORS
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from flask import Flask, request, jsonify, send_file
from scanners.sql_injection.static_sql_injection_scanner import (
    StaticSqlInjectionScanner,
)
from scanners.sql_injection.ml_sql_injection_scanner import MLSQLInjectionDetector, _github_blob_to_raw

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB upload limit

# Enable CORS for all origins (production and development)
CORS(app, origins=["*"], 
     methods=["GET", "POST", "OPTIONS"], 
     allow_headers=["Content-Type", "Authorization"])

def ensure_dirs():
    # Use /tmp directory which is writable on App Engine
    os.makedirs('/tmp/results', exist_ok=True)
    # Ensure ML upload directory exists
    ml_uploads = Path(__file__).parent / 'ml' / 'api' / 'uploads'
    ml_uploads.mkdir(parents=True, exist_ok=True)


@app.route('/api/static-sql-injection', methods=['POST'])
def scan_sql_injection():
        data = request.get_json(force=True)
        code = data.get('code')  
        url = (data.get('url'))
        scan_type = data.get('scanType')
        
        detector = StaticSqlInjectionScanner()
      
        if scan_type == 1:
            vulns = detector.scan_source(code, source_name='Direct input')
        elif scan_type == 2:
            vulns = detector.scan_file(code)
        elif scan_type == 3:
            vulns = detector.scan_url(url)
        else:
            return jsonify({'error': 'Invalid scanType'}), 400

        vulnerabilities = []
        vulns_list = vulns.get("vulnerabilities", []) if isinstance(vulns, dict) else vulns
        for v in vulns_list:
            vulnerabilities.append({
                "code_snippet": v.get("code_snippet"),
                "confidence": v.get("confidence"),
                "line_number": v.get("line_number"),
                "severity": v.get("severity")
            })

        return jsonify({
            'vulnerabilities': vulnerabilities,
            'code': code
        })

@app.route('/api/ml-sql-injection', methods=['POST'])
def ml_sql_injection():
        data = request.get_json(force=True)
        code = data.get('code')  
        url = (data.get('url'))
        scan_type = data.get('scanType')
        
        detector = MLSQLInjectionDetector()
      
        if scan_type == 1:
            vulns = detector.scan_source(code, source_name='Direct input')
        elif scan_type == 2:
            vulns = detector.scan_file(code)
        elif scan_type == 3:
            vulns = detector.scan_url(url)
        else:
            return jsonify({'error': 'Invalid scanType'}), 400

        vulnerabilities = []
        vulns_list = vulns.get("vulnerabilities", []) if isinstance(vulns, dict) else vulns
        for v in vulns_list:
            vulnerabilities.append({
                "code_snippet": v.get("code_snippet"),
                "confidence": v.get("confidence"),
                "line_number": v.get("line_number"),
                "severity": v.get("severity")
            })

        return jsonify({
            'vulnerabilities': vulnerabilities,
            'code': code
        })

# Initialize directories on startup
ensure_dirs()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug)

# cd /Users/mohammadalmasi/thesis/06.27/backend && venv/bin/python main.py
# cd /Users/mohammadalmasi/thesis/06.27/frontend && npm start