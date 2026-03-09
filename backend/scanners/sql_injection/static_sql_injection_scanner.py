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
        method = "execute" if isinstance(call_node.func, ast.Attribute) else "text()"
        return {
            "line_number": line,
            "vulnerability_type": "sql_injection",
            "description": f"Tainted data (user input) flows to SQL sink ({method}) - SQL injection risk",
            "severity": "high",
            "code_snippet": code_snippet,
            "remediation": "Use parameterized queries; do not build SQL from user input.",
            "confidence": 0.9,
            "file_path": file_path or "unknown",
            "cwe_references": ["89", "564", "943"],
            "owasp_references": ["A03:2021-Injection"],
            "rule_key": "python:S2077",
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

    def scan_code_content(self, code_content, source_name):
        """Scan code and return full API result dict (vulnerabilities, summary, lines_to_highlight, etc.)."""
        result = self.scan_source(code_content, source_name=source_name)
        vulnerabilities = result["vulnerabilities"]
        file_name = source_name
        if "/" in source_name:
            file_name = source_name.split("/")[-1]
        elif source_name.startswith("http"):
            file_name = source_name.split("/")[-1] if "/" in source_name else "scanned_code.py"
        lines_to_highlight = [{"line_number": v["line_number"], "severity": v["severity"]} for v in vulnerabilities]
        summary = {
            "total_vulnerabilities": len(vulnerabilities),
            "high_severity": sum(1 for v in vulnerabilities if v.get("severity") == "high"),
            "medium_severity": sum(1 for v in vulnerabilities if v.get("severity") == "medium"),
            "low_severity": sum(1 for v in vulnerabilities if v.get("severity") == "low"),
            "high": sum(1 for v in vulnerabilities if v.get("severity") == "high"),
            "medium": sum(1 for v in vulnerabilities if v.get("severity") == "medium"),
            "low": sum(1 for v in vulnerabilities if v.get("severity") == "low"),
        }
        return {
            "source": source_name,
            "scan_type": "sql_injection",
            "summary": summary,
            "vulnerabilities": vulnerabilities,
            "lines_to_highlight": lines_to_highlight,
            "code": code_content,
            "original_code": code_content,
            "highlighted_code": code_content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"),
            "total_vulnerabilities": len(vulnerabilities),
            "scan_timestamp": datetime.now().isoformat(),
            "total_issues": len(vulnerabilities),
            "high_severity": summary["high_severity"],
            "medium_severity": summary["medium_severity"],
            "low_severity": summary["low_severity"],
            "high_count": summary["high"],
            "medium_count": summary["medium"],
            "low_count": summary["low"],
            "file_name": file_name,
        }

    def highlight_word(self, code):
        """Highlight SQL injection patterns for Word documents."""
        patterns = [
            r'([\'\"]\s*(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|EXEC|EXECUTE).*?\{\}.*?[\'\"]\s*\.format\s*\([^)]*\))',
            r'([\'\"]\s*(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|EXEC|EXECUTE).*?%[sd].*?[\'\"]\s*%\s*[^;]+)',
            r'(f[\'\"]\s*(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|EXEC|EXECUTE).*?\{[^}]*\}.*?[\'"])',
            r'([\'\"]\s*.*(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|EXEC|EXECUTE).*[\'\"]\s*\+\s*\w+)',
            r'(\w+\s*\+\s*[\'"].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|JOIN|UNION).*[\'"])',
            r'(cursor\.execute\s*\(\s*[\'"][^\'\"]*[\'"]\s*\+\s*\w+)',
            r'(\.execute\s*\(\s*[\'"][^\'\"]*[\'"]\s*\+\s*\w+)',
            r'(cursor\.execute\s*\(\s*f[\'"][^\'\"]*\{[^}]*\}[^\'\"]*[\'"])',
            r'(\.raw\s*\(\s*[\'"][^\'\"]*[\'"]\s*\+\s*\w+)',
            r'(\.raw\s*\(\s*f[\'"][^\'\"]*\{[^}]*\}[^\'\"]*[\'"])',
            r'(text\s*\(\s*[\'"][^\'\"]*[\'"]\s*\+\s*\w+)',
            r'(text\s*\(\s*f[\'"][^\'\"]*\{[^}]*\}[^\'\"]*[\'"])',
            r'([\'"]WHERE\s+[^\'\"]*[\'"]\s*\+\s*\w+)',
            r'([\'"]LIKE\s+[^\'\"]*[\'"]\s*\+\s*\w+)',
            r'([\'"]ORDER\s+BY\s+[^\'\"]*[\'"]\s*\+\s*\w+)',
            r'(request\.args\.get\([^)]*\))',
            r'(request\.form\.get\([^)]*\))',
            r'(request\.(?:form|args)\[[^]]*\])',
            r'([\'\"]\s*(?:SELECT|INSERT|UPDATE|DELETE)[^\'\"]*[\'\"]\s*\+[^+]*\+[^+]*\+)',
            r'([\'\"]\s*WHERE[^\'\"]*[\'\"]\s*\+[^+]*\+)',
            r'([\'\"]\s*FROM[^\'\"]*[\'\"]\s*\+[^+]*\+)',
            r'(collection\.find\s*\(\s*\{[^}]*[\'"]:\s*(?:request\.|username|user_input|\w+_input)[^}]*\})',
            r'(\.find\s*\(\s*\{[^}]*[\'"]:\s*(?:request\.|username|user_input|\w+_input)[^}]*\})',
            r'(db\.eval\s*\(\s*f[\'"][^\'\"]*\{[^}]*\}[^\'\"]*[\'"])',
            r'(db\.eval\s*\(\s*[\'"][^\'\"]*[\'"]\s*\+\s*\w+)',
            r'(db\.eval\s*\([^)]*(?:request\.|username|user_input|\w+_input))',
            r'(\.(?:find_one|update|delete|remove|insert)\s*\(\s*\{[^}]*[\'"]:\s*(?:request\.|username|user_input|\w+_input))',
            r'(\{[^}]*[\'"]:\s*request\.(?:form|args|json)\[[^]]*\][^}]*\})',
            r'(aggregate\s*\(\s*\[[^]]*\{[^}]*[\'"]:\s*(?:request\.|username|user_input|\w+_input))',
        ]
        highlighted = code
        for pattern in patterns:
            highlighted = re.sub(pattern, lambda m: f"[SQL-INJECTION-VULNERABLE:{m.group(0)}]", highlighted, flags=re.IGNORECASE | re.DOTALL)
        return highlighted

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
        print("  Line", v["line_number"], ":", v.get("description", ""))