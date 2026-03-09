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

@app.route('/api/scan-ml', methods=['POST'])
def scan_ml():
    """Run machine learning based analysis using LSTM models (Atiqullah Ahmadzai’s project)."""
    try:
        data = request.get_json(force=True)
        vuln_type = (data.get('type') or '').lower()
        code = data.get('code') or ''
        url = (data.get('url') or '').strip()
        filename = data.get('filename') or 'code.py'

        if not vuln_type:
            return jsonify({'error': 'type is required'}), 400

        # Map UI types to model modes
        mode_map = {
            'sql': 'sql'
        }
        if vuln_type not in mode_map:
            return jsonify({'error': f'Unsupported type: {vuln_type}'}), 400
        mode = mode_map[vuln_type]

        # For ML analysis: sql accepts code or URL.
        if vuln_type == 'sql' and not code and not url:
            return jsonify({'error': 'type and either code or url are required'}), 400

        # SQL: use integrated ML SQL scanner (BiLSTM), return vulnerabilities + highlighted code
        if vuln_type == 'sql':
            try:
                if not code and not url:
                    return jsonify({'error': 'type and either code or url are required'}), 400

                detector = MLSQLInjectionDetector()

                effective_code = code
                vuln_source_name = filename

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
                            'type': vuln_type,
                            'mode': mode,
                            'message': f'Failed to fetch source from URL: {str(e)}',
                        }), 400

                detector = MLSQLInjectionDetector()
                vulns = detector.scan_source(effective_code, source_name=vuln_source_name)
            except Exception as e:
                return jsonify({
                    'status': 'error',
                    'type': vuln_type,
                    'mode': mode,
                    'message': f'ML SQL scan failed: {str(e)}',
                }), 500

            vuln_dicts = vulns
            high = sum(1 for v in vulns if (v.get('severity') or '').lower() == 'high')
            medium = sum(1 for v in vulns if (v.get('severity') or '').lower() == 'medium')
            low = sum(1 for v in vulns if (v.get('severity') or '').lower() == 'low')
            lines_to_highlight = [{'line_number': v['line_number'], 'severity': (v.get('severity') or 'high').lower()} for v in vulns]

            return jsonify({
                'status': 'completed',
                'type': vuln_type,
                'mode': mode,
                'filename': filename,
                'file_name': filename,
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

        # Other types: use external ML pipeline
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

        if not analyzer_script.exists():
            return jsonify({
                'status': 'error',
                'type': vuln_type,
                'mode': mode,
                'message': 'ML analyzer is not available in this repository checkout',
                'details': {
                    'missing_path': str(analyzer_script),
                    'hint': 'Add the ML analyzer and model files under backend/ml/ or disable ML in the UI.'
                }
            }), 501

        if not ml_api_cwd.exists():
            return jsonify({
                'status': 'error',
                'type': vuln_type,
                'mode': mode,
                'message': 'ML working directory is missing',
                'details': {
                    'missing_path': str(ml_api_cwd)
                }
            }), 501

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

# Initialize directories on startup
ensure_dirs()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug)


# cd /Users/mohammadalmasi/thesis/06.27/backend && venv/bin/python main.py

# cd /Users/mohammadalmasi/thesis/06.27/frontend && npm start