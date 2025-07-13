#!/usr/bin/env python3
"""
CSRF (Cross-Site Request Forgery) Vulnerability Scanner
This module scans Python code for potential CSRF vulnerabilities.
"""

import re
import ast
import html
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from flask import request, jsonify


@dataclass
class CSRFVulnerability:
    """Represents a CSRF vulnerability found in code."""
    line_number: int
    severity: str
    description: str
    code_snippet: str
    confidence: float = 0.8
    cwe_id: str = "CWE-352"


class CSRFScanner:
    """Scanner for CSRF vulnerabilities in Python code."""
    
    def __init__(self):
        self.vulnerabilities: List[CSRFVulnerability] = []
        
        # High severity patterns - Missing CSRF protection
        self.high_severity_patterns = [
            # Flask forms without CSRF tokens
            (r'@app\.route.*methods=\[.*POST.*\].*def.*:.*\n.*return.*render_template.*\w+\.html', 
             "Flask route with POST method without CSRF protection"),
            
            # Django forms without CSRF tokens
            (r'@csrf_exempt.*def.*:.*\n.*if.*request\.method.*==.*POST', 
             "Django view with CSRF exemption and POST handling"),
            
            # Direct form processing without CSRF validation
            (r'if.*request\.method.*==.*POST.*:.*\n.*form_data.*=.*request\.form', 
             "Direct form processing without CSRF validation"),
            
            # Missing CSRF token in form templates
            (r'<form.*method.*=.*post.*>.*\n(?!.*csrf_token).*</form>', 
             "HTML form with POST method missing CSRF token"),
            
            # AJAX requests without CSRF headers
            (r'\.ajax.*url.*:.*\w+.*method.*:.*post.*\n(?!.*headers.*csrf).*', 
             "AJAX POST request without CSRF headers"),
            
            # Fetch API without CSRF headers
            (r'fetch.*\w+.*\n.*method.*:.*POST.*\n(?!.*headers.*csrf).*', 
             "Fetch API POST request without CSRF headers"),
            
            # Flask route with POST method (simplified pattern)
            (r'@app\.route.*methods=\[.*POST.*\]', 
             "Flask route with POST method without CSRF protection"),
            
            # Django CSRF exempt decorator
            (r'@csrf_exempt', 
             "Django view with CSRF exemption"),
            
            # Form processing without validation
            (r'request\.form\.get', 
             "Direct form processing without CSRF validation"),
        ]
        
        # Medium severity patterns - Potential CSRF issues
        self.medium_severity_patterns = [
            # Form with GET method (less critical but still a concern)
            (r'<form.*method.*=.*get.*>.*\n.*action.*=.*\w+', 
             "Form using GET method for state-changing operations"),
            
            # Missing SameSite cookie attribute
            (r'response\.set_cookie.*\w+.*\n(?!.*samesite).*', 
             "Cookie set without SameSite attribute"),
            
            # Missing Secure flag on cookies
            (r'response\.set_cookie.*\w+.*\n(?!.*secure).*', 
             "Cookie set without Secure flag"),
            
            # Form without proper validation
            (r'<form.*>.*\n.*<input.*type.*=.*submit.*>.*\n.*</form>', 
             "Form without proper input validation"),
            
            # GET method for state-changing operations
            (r'method.*=.*get.*action.*=.*delete', 
             "Form using GET method for state-changing operations"),
            
            # Cookie without security attributes
            (r'response\.set_cookie.*\w+.*httponly.*=.*True', 
             "Cookie set without Secure flag"),
        ]
        
        # Low severity patterns - Minor CSRF concerns
        self.low_severity_patterns = [
            # Form without explicit method
            (r'<form.*>.*\n.*</form>', 
             "Form without explicit method attribute"),
            
            # Form without action attribute
            (r'<form.*method.*=.*post.*>.*\n.*</form>', 
             "Form without explicit action attribute"),
            
            # Basic form structure
            (r'<input.*type.*=.*text.*>', 
             "Text input without CSRF protection context"),
            
            # Form without explicit method attribute
            (r'<form.*action.*=.*\w+.*>.*\n.*</form>', 
             "Form without explicit method attribute"),
            
            # Form without explicit action attribute
            (r'<form.*method.*=.*post.*>.*\n.*<input.*type.*=.*submit.*>.*\n.*</form>', 
             "Form without explicit action attribute"),
        ]

    def scan_code_content(self, code_content: str, filename: str = "unknown") -> Dict[str, Any]:
        """
        Scan code content for CSRF vulnerabilities.
        
        Args:
            code_content: The source code to scan
            filename: Name of the file being scanned
            
        Returns:
            Dictionary containing scan results
        """
        self.vulnerabilities = []
        
        # Perform regex-based scanning
        self._scan_with_regex(code_content)
        
        # Perform AST-based scanning
        self._scan_with_ast(code_content)
        
        # Calculate statistics
        total_vulnerabilities = len(self.vulnerabilities)
        severity_breakdown = self._calculate_severity_breakdown()
        
        return {
            'total_vulnerabilities': total_vulnerabilities,
            'severity_breakdown': severity_breakdown,
            'vulnerabilities': [self._vulnerability_to_dict(v) for v in self.vulnerabilities],
            'filename': filename,
            'scan_type': 'csrf'
        }
    
    def _scan_with_regex(self, code_content: str) -> None:
        """Scan code using regex patterns."""
        lines = code_content.split('\n')
        
        # Scan for high severity vulnerabilities
        for pattern, description in self.high_severity_patterns:
            matches = re.finditer(pattern, code_content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            for match in matches:
                line_number = code_content[:match.start()].count('\n') + 1
                code_snippet = self._extract_code_snippet(lines, line_number)
                self.vulnerabilities.append(CSRFVulnerability(
                    line_number=line_number,
                    severity='high',
                    description=description,
                    code_snippet=code_snippet,
                    confidence=0.9
                ))
        
        # Scan for medium severity vulnerabilities
        for pattern, description in self.medium_severity_patterns:
            matches = re.finditer(pattern, code_content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            for match in matches:
                line_number = code_content[:match.start()].count('\n') + 1
                code_snippet = self._extract_code_snippet(lines, line_number)
                self.vulnerabilities.append(CSRFVulnerability(
                    line_number=line_number,
                    severity='medium',
                    description=description,
                    code_snippet=code_snippet,
                    confidence=0.7
                ))
        
        # Scan for low severity vulnerabilities
        for pattern, description in self.low_severity_patterns:
            matches = re.finditer(pattern, code_content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            for match in matches:
                line_number = code_content[:match.start()].count('\n') + 1
                code_snippet = self._extract_code_snippet(lines, line_number)
                self.vulnerabilities.append(CSRFVulnerability(
                    line_number=line_number,
                    severity='low',
                    description=description,
                    code_snippet=code_snippet,
                    confidence=0.5
                ))
    
    def _scan_with_ast(self, code_content: str) -> None:
        """Scan code using AST analysis."""
        try:
            tree = ast.parse(code_content)
            visitor = CSRFASTVisitor()
            visitor.visit(tree)
            
            # Add AST-based vulnerabilities
            for vuln in visitor.vulnerabilities:
                self.vulnerabilities.append(vuln)
                
        except SyntaxError:
            # If AST parsing fails, continue with regex-only scanning
            pass
    
    def _extract_code_snippet(self, lines: List[str], line_number: int) -> str:
        """Extract a code snippet around the given line number."""
        # Show more context - 5 lines before and after
        start_line = max(0, line_number - 5)
        end_line = min(len(lines), line_number + 5)
        
        snippet_lines = []
        for i in range(start_line, end_line):
            if i < len(lines):
                # Highlight the vulnerable line
                if i == line_number - 1:  # Convert to 0-based index
                    snippet_lines.append(f"{i + 1:4d}: >>> {lines[i]} <<< VULNERABLE")
                else:
                    snippet_lines.append(f"{i + 1:4d}: {lines[i]}")
        
        return '\n'.join(snippet_lines)
    
    def _calculate_severity_breakdown(self) -> Dict[str, int]:
        """Calculate the breakdown of vulnerabilities by severity."""
        breakdown = {'high': 0, 'medium': 0, 'low': 0}
        for vuln in self.vulnerabilities:
            breakdown[vuln.severity] += 1
        return breakdown
    
    def _vulnerability_to_dict(self, vuln: CSRFVulnerability) -> Dict[str, Any]:
        """Convert vulnerability object to dictionary."""
        return {
            'line_number': vuln.line_number,
            'severity': vuln.severity,
            'description': vuln.description,
            'code_snippet': vuln.code_snippet,
            'confidence': vuln.confidence,
            'cwe_id': vuln.cwe_id,
            'remediation': self._get_remediation(vuln),
            'cwe_references': self._get_cwe_references(vuln),
            'owasp_references': self._get_owasp_references(vuln),
            'rule_key': f'CSRF-{vuln.severity.upper()}',
            'sq_category': 'csrf'
        }
    
    def _get_remediation(self, vuln: CSRFVulnerability) -> str:
        """Get remediation advice for CSRF vulnerability."""
        if 'Flask route' in vuln.description:
            return "Add CSRF protection using Flask-WTF: from flask_wtf.csrf import CSRFProtect; csrf = CSRFProtect(app); Add {{ csrf_token() }} to forms"
        elif 'Django view' in vuln.description:
            return "Remove @csrf_exempt decorator or implement proper CSRF validation using Django's built-in CSRF middleware"
        elif 'HTML form' in vuln.description:
            return "Add CSRF token to form: <input type='hidden' name='csrf_token' value='{{ csrf_token() }}'>"
        elif 'AJAX' in vuln.description:
            return "Add CSRF headers to AJAX requests: headers: {'X-CSRF-Token': $('meta[name=\"csrf-token\"]').attr('content')}"
        elif 'Fetch API' in vuln.description:
            return "Add CSRF headers to Fetch requests: headers: {'X-CSRF-Token': document.querySelector('meta[name=\"csrf-token\"]').content}"
        elif 'Cookie' in vuln.description:
            return "Set secure cookie attributes: response.set_cookie('name', 'value', secure=True, samesite='Strict', httponly=True)"
        elif 'GET method' in vuln.description:
            return "Use POST method for state-changing operations and implement proper CSRF protection"
        else:
            return "Implement proper CSRF protection using framework-specific mechanisms and validate all state-changing requests"
    
    def _get_cwe_references(self, vuln: CSRFVulnerability) -> List[str]:
        """Get CWE references for CSRF vulnerability."""
        return ["CWE-352"]
    
    def _get_owasp_references(self, vuln: CSRFVulnerability) -> List[str]:
        """Get OWASP references for CSRF vulnerability."""
        return ["OWASP Top 10 2021: A05-2021", "OWASP CSRF Prevention Cheat Sheet"]


class CSRFASTVisitor(ast.NodeVisitor):
    """AST visitor for detecting CSRF vulnerabilities."""
    
    def __init__(self):
        self.vulnerabilities: List[CSRFVulnerability] = []
        self.current_line = 0
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definitions to check for CSRF issues."""
        self.current_line = node.lineno
        
        # Check for Flask routes with POST method
        if self._is_flask_route(node):
            if self._has_post_method(node) and not self._has_csrf_protection(node):
                self.vulnerabilities.append(CSRFVulnerability(
                    line_number=node.lineno,
                    severity='high',
                    description="Flask route with POST method missing CSRF protection",
                    code_snippet=self._get_node_source(node),
                    confidence=0.85
                ))
        
        # Check for Django views with CSRF exemption
        if self._is_django_view(node):
            if self._has_csrf_exempt(node) and self._handles_post(node):
                self.vulnerabilities.append(CSRFVulnerability(
                    line_number=node.lineno,
                    severity='high',
                    description="Django view with CSRF exemption handling POST requests",
                    code_snippet=self._get_node_source(node),
                    confidence=0.85
                ))
        
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call) -> None:
        """Visit function calls to check for CSRF-related issues."""
        self.current_line = node.lineno
        
        # Check for form processing without CSRF validation
        if self._is_form_processing_call(node):
            self.vulnerabilities.append(CSRFVulnerability(
                line_number=node.lineno,
                severity='high',
                description="Form processing without CSRF validation",
                code_snippet=self._get_node_source(node),
                confidence=0.8
            ))
        
        self.generic_visit(node)
    
    def _is_flask_route(self, node: ast.FunctionDef) -> bool:
        """Check if function is a Flask route."""
        # This is a simplified check - in practice, you'd need more sophisticated analysis
        return any(
            isinstance(decorator, ast.Call) and 
            isinstance(decorator.func, ast.Attribute) and
            decorator.func.attr == 'route'
            for decorator in node.decorator_list
        )
    
    def _has_post_method(self, node: ast.FunctionDef) -> bool:
        """Check if Flask route has POST method."""
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call):
                for keyword in decorator.keywords:
                    if keyword.arg == 'methods':
                        if isinstance(keyword.value, ast.List):
                            return any(
                                isinstance(elt, ast.Constant) and elt.value == 'POST'
                                for elt in keyword.value.elts
                            )
        return False
    
    def _has_csrf_protection(self, node: ast.FunctionDef) -> bool:
        """Check if function has CSRF protection."""
        # This would need more sophisticated analysis in practice
        return False
    
    def _is_django_view(self, node: ast.FunctionDef) -> bool:
        """Check if function is a Django view."""
        # Simplified check
        return 'request' in [arg.arg for arg in node.args.args]
    
    def _has_csrf_exempt(self, node: ast.FunctionDef) -> bool:
        """Check if Django view has CSRF exemption."""
        return any(
            isinstance(decorator, ast.Name) and decorator.id == 'csrf_exempt'
            for decorator in node.decorator_list
        )
    
    def _handles_post(self, node: ast.FunctionDef) -> bool:
        """Check if function handles POST requests."""
        # Simplified check - look for request.method == 'POST'
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Compare):
                if (isinstance(stmt.left, ast.Attribute) and 
                    stmt.left.attr == 'method' and
                    any(isinstance(comp, ast.Constant) and comp.value == 'POST' 
                        for comp in stmt.comparators)):
                    return True
        return False
    
    def _is_form_processing_call(self, node: ast.Call) -> bool:
        """Check if call is form processing without CSRF validation."""
        # Simplified check
        return False
    
    def _get_node_source(self, node: ast.AST) -> str:
        """Get source code for a node."""
        # This is a simplified implementation
        return f"Line {node.lineno}: {type(node).__name__}"


def scan_code_content_for_csrf(code_content: str, filename: str = "unknown") -> Dict[str, Any]:
    """
    Convenience function to scan code for CSRF vulnerabilities.
    
    Args:
        code_content: The source code to scan
        filename: Name of the file being scanned
        
    Returns:
        Dictionary containing scan results
    """
    scanner = CSRFScanner()
    return scanner.scan_code_content(code_content, filename)


# API Functions for Flask integration
def api_scan_csrf(current_user: str) -> Dict[str, Any]:
    """API function for CSRF scanning"""
    try:
        # Handle both form data and JSON data
        if request.is_json:
            data = request.get_json()
            if 'code' in data:
                code_content = data['code']
                filename = data.get('filename', 'unknown.py')
            elif 'url' in data:
                url = data['url']
                # In a real implementation, you would fetch the content from the URL
                return jsonify({'error': 'URL scanning not implemented yet'}), 400
            else:
                return jsonify({'error': 'No code or URL provided'}), 400
        else:
            # Handle form data
            if 'code' in request.form:
                code_content = request.form['code']
                filename = request.form.get('filename', 'unknown.py')
            elif 'url' in request.form:
                url = request.form['url']
                # In a real implementation, you would fetch the content from the URL
                return jsonify({'error': 'URL scanning not implemented yet'}), 400
            else:
                return jsonify({'error': 'No code or URL provided'}), 400
        
        # Scan the code
        result = scan_code_content_for_csrf(code_content, filename)
        
        # Add highlighted code for frontend display
        result['highlighted_code'] = _highlight_csrf_vulnerabilities(code_content, result['vulnerabilities'])
        
        # Add original code for complete display
        result['original_code'] = code_content
        
        # Add summary statistics
        result['total_issues'] = result['total_vulnerabilities']
        result['high_severity'] = result['severity_breakdown']['high']
        result['medium_severity'] = result['severity_breakdown']['medium']
        result['low_severity'] = result['severity_breakdown']['low']
        
        # Add summary object
        result['summary'] = {
            'total_issues': result['total_vulnerabilities'],
            'high_severity': result['severity_breakdown']['high'],
            'medium_severity': result['severity_breakdown']['medium'],
            'low_severity': result['severity_breakdown']['low']
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'CSRF scanning error: {str(e)}'}), 500


def api_generate_csrf_report(current_user: str) -> Dict[str, Any]:
    """API function for generating CSRF report"""
    try:
        # This would implement Word report generation
        # For now, return a placeholder
        return jsonify({
            'message': 'CSRF report generation not implemented yet',
            'status': 'pending'
        })
        
    except Exception as e:
        return jsonify({'error': f'CSRF report generation error: {str(e)}'}), 500


def api_csrf_sonarqube_export(current_user: str) -> Dict[str, Any]:
    """API function for CSRF SonarQube export"""
    try:
        # This would implement SonarQube format export
        # For now, return a placeholder
        return jsonify({
            'message': 'CSRF SonarQube export not implemented yet',
            'status': 'pending'
        })
        
    except Exception as e:
        return jsonify({'error': f'CSRF SonarQube export error: {str(e)}'}), 500


def _highlight_csrf_vulnerabilities(code_content: str, vulnerabilities: List[Dict[str, Any]]) -> str:
    """Highlight CSRF vulnerabilities in the code"""
    lines = code_content.split('\n')
    highlighted_lines = []
    
    for i, line in enumerate(lines):
        line_number = i + 1
        escaped_line = html.escape(line)
        vulnerability_found = False
        
        for vuln in vulnerabilities:
            if vuln['line_number'] == line_number:
                severity = vuln['severity']
                if severity == 'high':
                    highlighted_lines.append(f'<span class="csrf-vuln-high" title="High severity CSRF vulnerability">{escaped_line}</span>')
                elif severity == 'medium':
                    highlighted_lines.append(f'<span class="csrf-vuln-medium" title="Medium severity CSRF vulnerability">{escaped_line}</span>')
                elif severity == 'low':
                    highlighted_lines.append(f'<span class="csrf-vuln-low" title="Low severity CSRF vulnerability">{escaped_line}</span>')
                vulnerability_found = True
                break
        
        if not vulnerability_found:
            highlighted_lines.append(escaped_line)
    
    return '\n'.join(highlighted_lines) 