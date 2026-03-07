"""
Generic taint + sink analyzer for Python AST.
Reusable for SQL injection, XSS, and other vulnerability types.
Pass in taint sources, sinks, and a factory to build vulnerability objects.
"""
import ast


class TaintAnalyzer:
    """
    Taint + sink analysis.
    - Taint sources: where untrusted data enters (e.g. input(), request.args).
    - Sinks: dangerous operations (e.g. cursor.execute(query), innerHTML = x).
    If tainted data reaches a sink -> report via vulnerability_factory.
    """
    def __init__(
        self,
        filename,
        source_code,
        taint_source_attrs,
        taint_source_names,
        request_like_names,
        sink_attrs,
        sink_names,
        vulnerability_factory,
        sink_arg_index=0,
    ):
        self.filename = filename
        self.source_code = source_code
        self.taint_source_attrs = frozenset(taint_source_attrs)
        self.taint_source_names = frozenset(taint_source_names)
        self.request_like_names = frozenset(request_like_names)
        self.sink_attrs = frozenset(sink_attrs)
        self.sink_names = frozenset(sink_names)
        self.vulnerability_factory = vulnerability_factory
        self.sink_arg_index = sink_arg_index
        self.vulnerabilities = []
        self._assignments = []
        self._sink_calls = []
        self._tainted = set()

    def analyze(self, tree):
        self._collect_assignments_and_sinks(tree)
        self._compute_tainted_fixpoint()
        self._report_tainted_sinks()

    def _collect_assignments_and_sinks(self, node):
        if isinstance(node, ast.Assign):
            targets = []
            for t in node.targets:
                if isinstance(t, ast.Name):
                    targets.append(t.id)
            if targets:
                self._assignments.append((getattr(node, "lineno", 0), targets, node.value))
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            self._assignments.append((getattr(node, "lineno", 0), [node.target.id], node.value))
        elif isinstance(node, ast.Call):
            line = getattr(node, "lineno", 0)
            if isinstance(node.func, ast.Attribute):
                attr = getattr(node.func, "attr", None)
                if attr in self.sink_attrs and node.args:
                    self._sink_calls.append((line, node, self.sink_arg_index))
            elif isinstance(node.func, ast.Name):
                name = getattr(node.func, "id", None)
                if name in self.sink_names and node.args:
                    self._sink_calls.append((line, node, self.sink_arg_index))
        for child in ast.iter_child_nodes(node):
            self._collect_assignments_and_sinks(child)

    def _is_taint_source_call(self, node):
        if not isinstance(node, ast.Call):
            return False
        if isinstance(node.func, ast.Name):
            return getattr(node.func, "id", None) in self.taint_source_names
        if isinstance(node.func, ast.Attribute):
            attr = getattr(node.func, "attr", None)
            if attr not in self.taint_source_attrs:
                return False
            val = node.func.value
            if isinstance(val, ast.Name):
                return val.id in self.request_like_names
            if isinstance(val, ast.Attribute) and isinstance(getattr(val, "value", None), ast.Name):
                return getattr(val.value, "id", None) in self.request_like_names
            if attr in ("get", "getlist", "get_json", "get_data"):
                return True
        if isinstance(node.func, ast.Subscript):
            return self._is_request_like(node.func.value)
        return False

    def _is_request_like(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.request_like_names
        if isinstance(node, ast.Attribute):
            if getattr(node, "attr", None) in self.taint_source_attrs:
                return self._is_request_like(node.value)
        return False

    def _expr_tainted(self, node):
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return getattr(node, "id", None) in self._tainted
        if isinstance(node, ast.Call):
            if self._is_taint_source_call(node):
                return True
            for a in node.args:
                if self._expr_tainted(a):
                    return True
            for k in getattr(node, "keywords", []) or []:
                if self._expr_tainted(k.value):
                    return True
            return False
        if isinstance(node, ast.BinOp) and isinstance(getattr(node, "op", None), ast.Add):
            return self._expr_tainted(node.left) or self._expr_tainted(node.right)
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue) and self._expr_tainted(v.value):
                    return True
            return False
        if isinstance(node, ast.Attribute):
            return self._expr_tainted(node.value) if hasattr(node, "value") else False
        if isinstance(node, ast.Subscript):
            if self._is_request_like(node.value):
                return True
            return self._expr_tainted(node.value) or self._expr_tainted(
                node.slice if isinstance(node.slice, ast.AST) else None
            )
        if isinstance(node, (ast.List, ast.Tuple)):
            for e in getattr(node, "elts", []) or []:
                if self._expr_tainted(e):
                    return True
            return False
        return False

    def _compute_tainted_fixpoint(self):
        changed = True
        while changed:
            changed = False
            for _line, targets, value in self._assignments:
                if not self._expr_tainted(value):
                    continue
                for name in targets:
                    if name not in self._tainted:
                        self._tainted.add(name)
                        changed = True

    def _report_tainted_sinks(self):
        for line, call_node, arg_idx in self._sink_calls:
            if arg_idx >= len(call_node.args):
                continue
            arg = call_node.args[arg_idx]
            if not self._expr_tainted(arg):
                continue
            snippet = self._get_code_snippet(call_node)
            vuln = self.vulnerability_factory(line=line, call_node=call_node, code_snippet=snippet, file_path=self.filename)
            if vuln is not None:
                self.vulnerabilities.append(vuln)

    def _get_code_snippet(self, node):
        try:
            return ast.unparse(node)
        except AttributeError:
            return f"Line {getattr(node, 'lineno', 'unknown')}"
