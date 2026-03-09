import re
import os
import ast
import json
import tempfile
from docx import Document
from datetime import datetime
from urllib.request import Request, urlopen
from docx.shared import RGBColor, Inches, Pt
from docx.oxml.shared import OxmlElement, qn
from flask import request, jsonify, send_file
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_COLOR_INDEX

class StaticXSSScanner:
    """XSS detector: taint + sink analysis. All scan and helper methods live here."""
    def __init__(self):
        pass

    def _vuln_result(self, *, line, call_node, code_snippet, file_path):
        return {
            "line_number": line,
            "severity": "high",
            "code_snippet": code_snippet,
            "confidence": 0.9,
        }

    def _make_taint_analyzer(self, filename, source_code):
        from scanners.taint_analyzer import TaintAnalyzer
        return TaintAnalyzer(
            filename=filename,
            source_code=source_code,
            taint_source_attrs={
                "args", "form", "cookies", "headers", "json", "data", "values",
                "get", "getlist", "get_json", "get_data", "search",
            },
            taint_source_names={"input", "URLSearchParams"},
            request_like_names={"request", "req", "flask_request", "environ", "window", "location"},
            sink_attrs={"send", "write", "send_file"},
            sink_names={"render_template_string", "Markup", "mark_safe", "HttpResponse", "eval"},
            sanitizer_names={"escape", "escape_html", "bleach", "clean", "dumps"},
            vulnerability_factory=self._vuln_result,
            sink_arg_index=0,
            returns_are_sinks=True,
            taint_source_vars={"user_name", "username", "user_content", "search_term", "data", "content"},
            sink_patterns={".innerHTML", ".append(", "|safe"}
        )

    def scan_source(self, source_code, source_name="<source>"):
        """Scan source code string. Returns dict with 'vulnerabilities' and 'source_name'."""
        try:
            tree = ast.parse(source_code)
            analyzer = self._make_taint_analyzer(source_name, source_code)
            analyzer.analyze(tree)
            return {"vulnerabilities": analyzer.vulnerabilities, "source_name": source_name}
        except SyntaxError:
            return {"vulnerabilities": [], "source_name": source_name}

    def scan_file(self, filename):
        """Scan a Python file. Returns dict with 'vulnerabilities' and 'source_name'."""
        try:
            with open(filename, "r", encoding="utf-8") as f:
                code = f.read()
        except UnicodeDecodeError:
            with open(filename, "r", encoding="latin-1") as f:
                code = f.read()
        return self.scan_source(code, source_name=filename)

    def scan_url(self, url, timeout=30):
        """Fetch URL and scan. Supports GitHub blob URLs (converted to raw). Returns dict with 'vulnerabilities' and 'source_name'."""
        fetch_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        req = Request(fetch_url, headers={"User-Agent": "Static-XSS-Scanner/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            code = resp.read().decode("utf-8", errors="replace")
        return self.scan_source(code, source_name=url)