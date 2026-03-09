from flask import request, jsonify, send_file
import re
import os
import ast
import tempfile
from urllib.request import Request, urlopen
from docx import Document
from docx.shared import RGBColor, Inches, Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_COLOR_INDEX
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.shared import OxmlElement, qn
from datetime import datetime
import json

class StaticSqlInjectionScanner:
    """SQL injection detector: taint + sink analysis. All scan and helper methods live here."""
    def __init__(self):
        pass

    def _vuln_factory(self, *, line, call_node, code_snippet, file_path):
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
                "get", "getlist", "get_json", "get_data",
            },
            taint_source_names={"input"},
            request_like_names={"request", "req", "flask_request", "environ"},
            sink_attrs={"execute", "executemany", "raw"},
            sink_names={"text"},
            vulnerability_factory=self._vuln_factory,
            sink_arg_index=0,
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
        req = Request(fetch_url, headers={"User-Agent": "Static-SQL-Scanner/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            code = resp.read().decode("utf-8", errors="replace")
        return self.scan_source(code, source_name=url)

if __name__ == "__main__":
    import sys
    
    mode = sys.argv[1]
    argument = sys.argv[2]

    detector = StaticSqlInjectionScanner()

    if mode == "0":
        result = detector.scan_source(argument)
    elif mode == "1":
        result = detector.scan_file(argument)
    elif mode == "2":
        result = detector.scan_url(argument)
    else:
        print("Unknown mode. Use 0 for source, 1 for file, 2 for URL.")
        sys.exit(1)
    vulns = result["vulnerabilities"]
    print("Vulnerabilities found:", len(vulns))
    for v in vulns:
        print("  Line", v["line_number"], ":", v.get("code_snippet", ""))