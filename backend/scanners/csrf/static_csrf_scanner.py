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

def _get_route_methods(node):
    """Return set of HTTP methods if node has a Flask-style @app.route(methods=[...]) decorator, else None."""
    for dec in node.decorator_list:
        if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr == 'route':
            for keyword in dec.keywords:
                if keyword.arg == 'methods' and isinstance(keyword.value, ast.List):
                    methods = []
                    for el in keyword.value.elts:
                        if isinstance(el, ast.Constant):
                            methods.append(el.value)
                        elif isinstance(el, ast.Str):
                            methods.append(el.s)
                    return set(methods)
    return None


def _has_state_change(node):
    """True if function body contains .save(), .delete(), .update(), or .commit()."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
            if child.func.attr in ('save', 'delete', 'update', 'commit'):
                return True
    return False


def _has_csrf_evidence(node):
    """True if function body references CSRF (token, get_token, CSRFProtect, csrfmiddlewaretoken, etc.)."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and 'csrf' in child.id.lower():
            return True
        if isinstance(child, ast.Attribute) and isinstance(getattr(child, 'attr', None), str) and 'csrf' in child.attr.lower():
            return True
        if isinstance(child, ast.Constant) and isinstance(child.value, str) and 'csrf' in child.value.lower():
            return True
        if isinstance(child, ast.Str) and 'csrf' in child.s.lower():  # Python 3.7
            return True
    return False


def _has_csrf_code_evidence(node):
    """True if function has code (Name/Attribute) referencing CSRF; ignores docstrings/string literals."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and 'csrf' in child.id.lower():
            return True
        if isinstance(child, ast.Attribute) and isinstance(getattr(child, 'attr', None), str) and 'csrf' in child.attr.lower():
            return True
    return False


def _walk_without_nested_functions(node):
    """Yield nodes in tree but do not descend into nested FunctionDef (so we only see this function's body)."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.FunctionDef):
            continue
        yield child
        for x in _walk_without_nested_functions(child):
            yield x


def _has_request_method_get_check(node):
    """True if this function's body (not nested defs) has request.method == 'GET'."""
    for child in _walk_without_nested_functions(node):
        if isinstance(child, ast.Compare) and len(child.ops) == 1 and isinstance(child.ops[0], ast.Eq):
            left = child.left
            if isinstance(left, ast.Attribute) and left.attr == 'method':
                req = left.value
                if isinstance(req, ast.Name) and req.id == 'request':
                    if child.comparators:
                        c = child.comparators[0]
                        val = getattr(c, 'value', getattr(c, 's', None))
                        if val == 'GET':
                            return True
    return False


def _has_state_change_same_level(node):
    """True if this function's body (not nested defs) contains .save()/.delete()/.update()/.commit()."""
    for child in _walk_without_nested_functions(node):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
            if child.func.attr in ('save', 'delete', 'update', 'commit'):
                return True
    return False


def _state_change_line_same_level(node):
    """First line number of .save()/.delete()/.update()/.commit() in this function's body (not nested), or None."""
    for child in _walk_without_nested_functions(node):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
            if child.func.attr in ('save', 'delete', 'update', 'commit'):
                try:
                    return child.lineno, ast.unparse(child)
                except Exception:
                    return child.lineno, f"Line {child.lineno}"
    return None


def _has_origin_or_referer_check(node):
    """True if function body has request.headers.get('Origin') or request.headers.get('Referer')."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
            if child.func.attr != 'get':
                continue
            if not isinstance(child.func.value, ast.Attribute) or child.func.value.attr != 'headers':
                continue
            if not child.args:
                continue
            arg0 = child.args[0]
            val = getattr(arg0, 'value', getattr(arg0, 's', None))
            if val in ('Origin', 'Referer'):
                return True
    return False


def _is_fake_csrf_validator(node):
    """True if function name suggests CSRF validation but body is just return True."""
    if 'csrf' not in node.name.lower():
        return False
    if len(node.body) != 1:
        return False
    stmt = node.body[0]
    if not isinstance(stmt, ast.Return) or stmt.value is None:
        return False
    if isinstance(stmt.value, ast.Constant) and stmt.value.value is True:
        return True
    if isinstance(stmt.value, ast.NameConstant) and stmt.value.value is True:  # Python 3.7
        return True
    return False


def _build_parent_map(tree):
    """Map each node to its parent (module has no parent)."""
    parent_map = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent_map[child] = node
    return parent_map


class CSRFVisitor(ast.NodeVisitor):
    def __init__(self, filename, parent_map=None):
        self.filename = filename
        self.vulnerabilities = []
        self.parent_map = parent_map or {}

    def visit_FunctionDef(self, node):
        has_route_get = False
        route_methods = None

        # 1. Check decorators for csrf_exempt / disable_csrf
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                if dec.id in ('csrf_exempt', 'disable_csrf'):
                    self.vulnerabilities.append({
                        "line_number": node.lineno,
                        "severity": "high",
                        "code_snippet": f"@{dec.id}",
                        "confidence": 0.9,
                    })
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Attribute) and dec.func.attr == 'route':
                    route_methods = _get_route_methods(node) or set()
                    for keyword in dec.keywords:
                        if keyword.arg == 'methods':
                            if isinstance(keyword.value, ast.List):
                                methods = []
                                for el in keyword.value.elts:
                                    if isinstance(el, ast.Constant):
                                        methods.append(el.value)
                                    elif isinstance(el, ast.Str):
                                        methods.append(el.s)
                                if 'GET' in methods and 'POST' not in methods:
                                    has_route_get = True
                                break

        if route_methods is None:
            route_methods = _get_route_methods(node)

        # 2. State change inside GET-only route (decorator or request.method == "GET")
        #    Use same-level checks so we don't flag safe_code3 (GET in one nested def, save in another)
        if not has_route_get and _has_request_method_get_check(node):
            has_route_get = True  # vulnerable_code6: GET check in body

        if has_route_get and _has_state_change_same_level(node):
            res = _state_change_line_same_level(node)
            if res:
                line_no, snippet = res
                self.vulnerabilities.append({
                    "line_number": line_no,
                    "severity": "high",
                    "code_snippet": snippet,
                    "confidence": 0.8,
                })

        # 3. Fake CSRF validator (e.g. validate_csrf that always returns True) — vulnerable_code7
        if _is_fake_csrf_validator(node):
            self.vulnerabilities.append({
                "line_number": node.lineno,
                "severity": "high",
                "code_snippet": f"def {node.name}(...): return True",
                "confidence": 0.85,
            })

        # 4. Flask POST-only route with state change and no CSRF evidence — vulnerable_code5
        #    (skip if Origin/Referer-only check present — that is flagged by rule 5)
        #    Skip if nested inside a function that has CSRF code (e.g. safe_code2 with CSRFProtect)
        parent = self.parent_map.get(node)
        parent_has_csrf = isinstance(parent, ast.FunctionDef) and _has_csrf_code_evidence(parent)
        if (route_methods == {'POST'} and _has_state_change(node) and not _has_csrf_evidence(node)
                and not _has_origin_or_referer_check(node) and not parent_has_csrf):
            self.vulnerabilities.append({
                "line_number": node.lineno,
                "severity": "high",
                "code_snippet": f"POST route with state change, no CSRF check (def {node.name})",
                "confidence": 0.75,
            })

        # 5. POST route with Origin/Referer check only, no CSRF token — vulnerable_code8
        #    (flag if Origin/Referer used for "protection" with no token; state change optional)
        if (route_methods and 'POST' in route_methods and _has_origin_or_referer_check(node)
                and not _has_csrf_evidence(node) and not parent_has_csrf):
            self.vulnerabilities.append({
                "line_number": node.lineno,
                "severity": "high",
                "code_snippet": "Relies on Origin/Referer only, no CSRF token",
                "confidence": 0.8,
            })

        self.generic_visit(node)

class StaticCSRFScanner:
    """CSRF detector: Custom AST visitor to find disabled CSRF protection."""
    def __init__(self):
        pass

    def scan_source(self, source_code, source_name="<source>"):
        """Scan source code string. Returns dict with 'vulnerabilities' and 'source_name'."""
        try:
            tree = ast.parse(source_code)
            parent_map = _build_parent_map(tree)
            visitor = CSRFVisitor(source_name, parent_map=parent_map)
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