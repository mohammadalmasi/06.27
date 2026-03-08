from flask import request, jsonify, send_file
import re
import os
import ast
import tempfile
from urllib.request import Request, urlopen
from docx import Document
from docx.shared import RGBColor, Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH
from datetime import datetime

class StaticXSSScanner:
    """XSS detector: taint + sink analysis + pattern scan. All scan and helper methods live here."""

    def __init__(self):
        pass

    def _vuln_factory(self, *, line, call_node, code_snippet, file_path):
        attr = getattr(call_node.func, "attr", None) if isinstance(call_node.func, ast.Attribute) else None
        sink_name = attr or "call"
        return {
            "line_number": line,
            "vulnerability_type": "xss",
            "description": f"Tainted data (user input) flows to XSS sink ({sink_name}) - XSS risk",
            "severity": "high",
            "code_snippet": code_snippet,
            "remediation": "Escape/sanitize user input before output; use safe templates.",
            "confidence": 0.9,
            "file_path": file_path or "unknown",
            "cwe_references": ["79", "80", "81", "82", "83", "84", "85", "86", "87"],
            "owasp_references": ["A03:2021-Injection"],
            "rule_key": "python:S5131",
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
            sink_attrs={"render_template_string", "write", "send"},
            sink_names=set(),
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
        req = Request(fetch_url, headers={"User-Agent": "Static-XSS-Scanner/1.0"})
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
            "scan_type": "xss",
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
        """Highlight XSS vulnerability patterns for Word documents."""
        patterns = [
            r'(render_template_string\s*\([^)]*\))',
            r'(\.innerHTML\s*=\s*[^;]*)',
            r'(document\.getElementById\([^)]+\)\.innerHTML\s*=\s*[^;]+)',
            r'(\.outerHTML\s*=\s*[^;]+)',
            r'(\.insertAdjacentHTML\s*\([^)]*\))',
            r'(document\.write\s*\([^)]*\))',
            r'(eval\s*\([^)]*\))',
            r'(\$\([^)]*\)\.html\s*\([^)]*\))',
            r'(\$\([^)]*\)\.append\s*\([^)]*<[^>]*>[^)]*\))',
            r'(\{\{\s*\w+\s*\|\s*safe\s*\}\})',
            r'(Markup\s*\([^)]*\))',
            r'(URLSearchParams|location\.search|params\.get|getParameter)',
            r'(request\.args\.get\([^)]*\))',
            r'(request\.form\.get\([^)]*\))',
            r'(<script[^>]*>[^<]*</script>)',
            r'([\'"]<[^>]*>.*\{\}.*[\'\"]\s*\.format\s*\([^)]*\))',
            r'(f[\'"]<[^>]*>[^\'\"]*\{[^}]*\}[^\'\"]*[\'"])',
            r'(return\s+f[\'"]<[^>]*>[^\'\"]*\{[^}]*\}[^\'\"]*[\'"])',
            r'(setTimeout\s*\([^)]*\))',
            r'(setInterval\s*\([^)]*\))',
        ]
        highlighted = code
        for pattern in patterns:
            highlighted = re.sub(pattern, lambda m: f"[XSS-VULNERABLE:{m.group(0)}]", highlighted, flags=re.IGNORECASE)
        return highlighted


def highlight_xss_vulnerabilities_word(code):
    """Highlight XSS vulnerability patterns for Word documents."""
    return StaticXSSScanner().highlight_word(code)

def api_generate_xss_report(current_user):
    """API endpoint for generating XSS reports."""
    try:
        data = request.get_json()
        vulnerabilities = data.get("vulnerabilities", [])
        source = data.get("source", "Unknown")
        if not vulnerabilities:
            return jsonify({"error": "No vulnerabilities provided"}), 400
        doc = Document()
        title = doc.add_heading("Cross-Site Scripting (XSS) Security Analysis Report", 0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        doc.add_heading("Report Information", level=1)
        info_table = doc.add_table(rows=4, cols=2)
        info_table.style = "Table Grid"
        info_table.cell(0, 0).text = "Source"
        info_table.cell(0, 1).text = source
        info_table.cell(1, 0).text = "Report Generated"
        info_table.cell(1, 1).text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        info_table.cell(2, 0).text = "Total Vulnerabilities"
        info_table.cell(2, 1).text = str(len(vulnerabilities))
        info_table.cell(3, 0).text = "Risk Level"
        info_table.cell(3, 1).text = "High" if len(vulnerabilities) > 0 else "Low"
        doc.add_heading("Executive Summary", level=1)
        summary_text = f"""
This report presents the results of a comprehensive Cross-Site Scripting (XSS) vulnerability analysis performed on the provided code.
The analysis identified {len(vulnerabilities)} potential XSS vulnerabilities that could allow attackers to inject malicious scripts
into web applications and execute them in users' browsers.

XSS vulnerabilities can lead to session hijacking, credential theft, malware distribution, and defacement of web applications.
These vulnerabilities should be addressed immediately to prevent potential attacks against users.
        """
        doc.add_paragraph(summary_text.strip())
        doc.add_heading("Vulnerability Details", level=1)
        for i, vuln in enumerate(vulnerabilities, 1):
            doc.add_heading(f"XSS Vulnerability #{i}", level=2)
            vuln_table = doc.add_table(rows=5, cols=2)
            vuln_table.style = "Table Grid"
            vuln_table.cell(0, 0).text = "Line Number"
            vuln_table.cell(0, 1).text = str(vuln.get("line_number", "N/A"))
            vuln_table.cell(1, 0).text = "Severity"
            vuln_table.cell(1, 1).text = vuln.get("severity", "Medium").title()
            vuln_table.cell(2, 0).text = "CWE References"
            vuln_table.cell(2, 1).text = ", ".join(vuln.get("cwe_references", []))
            vuln_table.cell(3, 0).text = "OWASP References"
            vuln_table.cell(3, 1).text = ", ".join(vuln.get("owasp_references", []))
            vuln_table.cell(4, 0).text = "Description"
            vuln_table.cell(4, 1).text = vuln.get("description", "XSS vulnerability detected")
            doc.add_paragraph("Vulnerable Code:", style="Heading 3")
            code_para = doc.add_paragraph()
            code_run = code_para.add_run(vuln.get("code_snippet", ""))
            code_run.font.name = "Courier New"
            code_run.font.size = Pt(10)
            code_run.font.color.rgb = RGBColor(255, 0, 0)
            doc.add_paragraph("Remediation:", style="Heading 3")
            doc.add_paragraph(vuln.get("remediation", "Apply proper input validation and output encoding"))
            doc.add_paragraph()
        doc.add_heading("XSS Prevention Recommendations", level=1)
        recommendations = """
1. Input Validation: Validate all user inputs on both client and server side.
2. Output Encoding: Encode data before inserting it into HTML, JavaScript, CSS, or URL contexts.
3. Content Security Policy (CSP): Implement strict CSP headers to prevent script execution.
4. Use Safe APIs: Avoid innerHTML, document.write(), and eval(). Use textContent, createElement(), and JSON.parse().
5. Template Engines: Use template engines with built-in XSS protection (auto-escaping).
6. HTTPOnly Cookies: Set HTTPOnly flag on sensitive cookies to prevent JavaScript access.
7. Security Headers: Implement X-XSS-Protection, X-Frame-Options, and X-Content-Type-Options headers.
8. Regular Testing: Conduct regular security testing including automated XSS scanning.
        """
        doc.add_paragraph(recommendations.strip())
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".docx")
        doc.save(temp_file.name)
        temp_file.close()
        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name=f"xss_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx",
            mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
    except Exception as e:
        return jsonify({"error": f"Error generating XSS report: {str(e)}"}), 500


if __name__ == "__main__":
    import sys
  
    mode = sys.argv[1]
    argument = sys.argv[2]
    scanner = StaticXSSScanner()
    if mode == "0":
        if argument == "-":
            source_code = sys.stdin.read()
        else:
            with open(argument, "r", encoding="utf-8") as f:
                source_code = f.read()
        result = scanner.scan_source(source_code, argument)
    elif mode == "1":
        result = scanner.scan_file(argument)
    elif mode == "2":
        result = scanner.scan_url(argument)
    else:
        print("Unknown mode. Use 0 for source, 1 for file, 2 for URL.")
        sys.exit(1)
    vulns = result["vulnerabilities"]
    print("Vulnerabilities found:", len(vulns))
    for v in vulns:
        print("  Line", v["line_number"], ":", v.get("description", ""))
