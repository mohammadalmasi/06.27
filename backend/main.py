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
    """SQL injection vulnerability scanning endpoint"""
    try:
        data = request.get_json()
        code_content = data.get('code', '')
        url = data.get('url', '')
        scan_type = data.get('scanType')
        
        scanner = StaticSqlInjectionScanner()
        
        # Determine scan_type if not provided for backward compatibility
        if not scan_type:
            if url:
                scan_type = 3
            else:
                scan_type = 1
        
        if scan_type == 1:
            print(json.dumps({"debug": "calling scan_source for scanType 1"}))
            raw_results = scanner.scan_source(code_content, source_name='Direct input')
            effective_code = code_content
        elif scan_type == 2:
            print(json.dumps({"debug": "calling scan_file for scanType 2"}))
            import tempfile
            import os
            with tempfile.NamedTemporaryFile(delete=False, suffix=".py", mode='w', encoding='utf-8') as tmp:
                tmp.write(code_content)
                tmp_path = tmp.name
                
            try:
                raw_results = scanner.scan_file(tmp_path)
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            effective_code = code_content
        elif scan_type == 3:
            print(json.dumps({"debug": "calling scan_url for scanType 3"}))
            if not url:
                return jsonify({'error': 'URL is required for GitHub URL scan'}), 400
            
            raw_results = scanner.scan_url(url)
            
            try:
                raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                req = Request(raw_url, headers={"User-Agent": "SQL-Scanner/1.0"})
                with urlopen(req, timeout=10) as resp:
                    effective_code = resp.read().decode("utf-8", errors="replace")
            except Exception:
                effective_code = "# Could not fetch source code for display"
        else:
            return jsonify({'error': 'Invalid scanType'}), 400

        vulns = raw_results.get('vulnerabilities', [])
        
        simplified_vulns = []
        for v in vulns:
            simplified_vulns.append({
                "code_snippet": v.get("code_snippet"),
                "confidence": v.get("confidence"),
                "line_number": v.get("line_number"),
                "severity": v.get("severity")
            })

        results = {
            'vulnerabilities': simplified_vulns,
            'code': effective_code
        }
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': f'Error during SQL injection scan: {str(e)}'}), 500

@app.route('/api/ml-sql-injection', methods=['POST'])
def ml_sql_injection():
        data = request.get_json(force=True)
        code = data.get('code')  
        url = (data.get('url')).strip()

        detector = MLSQLInjectionDetector()
      
        if scan_type == 1:
            vulns = detector.scan_source(code, source_name='Direct input')
        elif scan_type == 2:
            vulns = detector.scan_file(code)
        elif scan_type == 3:
            vulns = detector.scan_url(url)
        else:
            return jsonify({'error': 'Invalid scanType'}), 400

        vuln_dicts = []
        for v in vulns:
            vuln_dicts.append({
                "code_snippet": v.get("code_snippet"),
                "confidence": v.get("confidence"),
                "line_number": v.get("line_number"),
                "severity": v.get("severity")
            })

        return jsonify({
            'vulnerabilities': vuln_dicts,
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