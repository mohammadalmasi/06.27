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
        code_content = data.get('code')
        url = data.get('url')
        scanner = StaticSqlInjectionScanner()
        if code_content:
            results = scanner.scan_code_content(code_content, 'Direct input')
        elif url:
            # Support GitHub .py URLs: convert blob URL to raw
            if "github.com" in url and url.endswith(".py"):
                raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                try:
                    req = Request(raw_url, headers={"User-Agent": "SQL-Scanner/1.0"})
                    with urlopen(req, timeout=10) as resp:
                        text = resp.read().decode("utf-8", errors="replace")
                    results = scanner.scan_code_content(text, url)
                except Exception as e:
                    return jsonify({'error': f'Error fetching URL: {str(e)}'}), 400
            else:
                return jsonify({'error': 'Invalid GitHub Python file URL'}), 400
        else:
            return jsonify({'error': 'Invalid scan parameters'}), 400
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': f'Error during SQL injection scan: {str(e)}'}), 500

@app.route('/api/ml-sql-injection', methods=['POST'])
def ml_sql_injection():
    """Run machine learning based analysis using LSTM models (Atiqullah Ahmadzai’s project) for SQL injection."""
    try:
        data = request.get_json(force=True)
        code = data.get('code') or ''
        url = (data.get('url') or '').strip()

        if not code and not url:
            return jsonify({'error': 'either code or url is required'}), 400

        detector = MLSQLInjectionDetector()
        effective_code = code
        vuln_source_name = 'code.py'

        # If no code was provided but a URL was, fetch the source from the URL.
        if not effective_code and url:
            fetch_url = _github_blob_to_raw(url)
            try:
                req = Request(fetch_url, headers={"User-Agent": "ML-SQL-Scanner/1.0"})
                with urlopen(req, timeout=30) as resp:
                    effective_code = resp.read().decode("utf-8", errors="replace")
                vuln_source_name = url
            except Exception as e:
                return jsonify({
                    'status': 'error',
                    'message': f'Failed to fetch source from URL: {str(e)}',
                }), 400

        detector = MLSQLInjectionDetector()
        vulns = detector.scan_source(effective_code, source_name=vuln_source_name)

        vuln_dicts = vulns
        high = sum(1 for v in vulns if (v.get('severity') or '').lower() == 'high')
        medium = sum(1 for v in vulns if (v.get('severity') or '').lower() == 'medium')
        low = sum(1 for v in vulns if (v.get('severity') or '').lower() == 'low')
        lines_to_highlight = [{'line_number': v['line_number'], 'severity': (v.get('severity') or 'high').lower()} for v in vulns]

        return jsonify({
            'status': 'completed',
            'vulnerabilities': vuln_dicts,
            'lines_to_highlight': lines_to_highlight,
            'code': effective_code,
            'highlighted_code': effective_code,
            'original_code': effective_code,
            'total_issues': len(vulns),
            'high_severity': high,
            'medium_severity': medium,
            'low_severity': low,
        })

    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500

# Initialize directories on startup
ensure_dirs()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug)


# cd /Users/mohammadalmasi/thesis/06.27/backend && venv/bin/python main.py

# cd /Users/mohammadalmasi/thesis/06.27/frontend && npm start