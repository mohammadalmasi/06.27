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

class CSRFVisitor(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.vulnerabilities = []

    def visit_FunctionDef(self, node):
        has_route_get = False
        
        # 1. Check decorators for csrf_exempt / disable_csrf
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                if dec.id in ('csrf_exempt', 'disable_csrf'):
                    self.vulnerabilities.append({
                        "line_number": node.lineno,
                        "severity": "high" if dec.id == "csrf_exempt" else "medium",
                        "code_snippet": f"@{dec.id}",
                        "confidence": 0.9,
                    })
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Attribute) and dec.func.attr == 'route':
                    for keyword in dec.keywords:
                        if keyword.arg == 'methods':
                            if isinstance(keyword.value, ast.List):
                                # check if it only has GET, or GET is present without POST
                                methods = []
                                for el in keyword.value.elts:
                                    if isinstance(el, ast.Constant):
                                        methods.append(el.value)
                                    elif isinstance(el, ast.Str): # Python 3.7 compatibility
                                        methods.append(el.s)
                                
                                if 'GET' in methods and 'POST' not in methods:
                                    has_route_get = True
        
        # 2. Check for state changes inside GET routes
        if has_route_get:
            for child in ast.walk(node):
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                    if child.func.attr in ('save', 'delete', 'update', 'commit'):
                        try:
                            snippet = ast.unparse(child)
                        except Exception:
                            snippet = f"Line {child.lineno}"
                        self.vulnerabilities.append({
                            "line_number": child.lineno,
                            "severity": "high",
                            "code_snippet": snippet,
                            "confidence": 0.8,
                        })
                        break

        self.generic_visit(node)

class StaticCSRFScanner:
    """CSRF detector: Custom AST visitor to find disabled CSRF protection."""
    def __init__(self):
        pass

    def scan_source(self, source_code, source_name="<source>"):
        """Scan source code string. Returns dict with 'vulnerabilities' and 'source_name'."""
        try:
            tree = ast.parse(source_code)
            visitor = CSRFVisitor(source_name)
            visitor.visit(tree)
            return {"vulnerabilities": visitor.vulnerabilities, "source_name": source_name}
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
        req = Request(fetch_url, headers={"User-Agent": "Static-CSRF-Scanner/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            code = resp.read().decode("utf-8", errors="replace")
        return self.scan_source(code, source_name=url)