"""
Generic taint + sink analyzer for Python AST.
Reusable for SQL injection, XSS, and other vulnerability types.
Pass in taint sources, sinks, and a factory to build vulnerability objects.
"""
import ast
import symtable

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
        sanitizer_names,
        vulnerability_factory,
        sink_arg_index=0,
        returns_are_sinks=False,
        taint_source_vars=None,
        sink_patterns=None,
    ):
        self.filename = filename
        self.source_code = source_code
        self.taint_source_attrs = frozenset(taint_source_attrs)
        self.taint_source_names = frozenset(taint_source_names)
        self.request_like_names = frozenset(request_like_names)
        self.sink_attrs = frozenset(sink_attrs)
        self.sink_names = frozenset(sink_names)
        self.sanitizer_names = frozenset(sanitizer_names) if sanitizer_names else frozenset()
        self.vulnerability_factory = vulnerability_factory
        self.sink_arg_index = sink_arg_index
        self.returns_are_sinks = returns_are_sinks
        self.taint_source_vars = frozenset(taint_source_vars) if taint_source_vars else frozenset()
        self.sink_patterns = frozenset(sink_patterns) if sink_patterns else frozenset()
        self.vulnerabilities = []
        self._assignments = []
        self._sink_calls = []
        self._tainted = set()

    def analyze(self, tree):
        try:
            self.st = symtable.symtable(self.source_code, self.filename, "exec")
        except Exception:
            self.st = None

        self._collect_assignments_and_sinks(tree)
        self._compute_tainted_fixpoint()
        self._report_tainted_sinks()

    def _collect_assignments_and_sinks(self, node, current_st=None):
        if current_st is None:
            current_st = getattr(self, "st", None)

        new_st = current_st
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if current_st is not None:
                for child in current_st.get_children():
                    if child.get_name() == node.name and child.get_lineno() == node.lineno:
                        new_st = child
                        break
        
        scope_id = id(new_st) if new_st else 0

        if isinstance(node, ast.Assign):
            targets = []
            for t in node.targets:
                if isinstance(t, ast.Name):
                    targets.append(t.id)
            if targets:
                self._assignments.append((getattr(node, "lineno", 0), targets, node.value, scope_id))
            
            if self.sink_patterns:
                try:
                    code_str = ast.unparse(node)
                    if any(p in code_str for p in self.sink_patterns):
                        self._sink_calls.append((getattr(node, "lineno", 0), node, -1, scope_id))
                except:
                    pass
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            self._assignments.append((getattr(node, "lineno", 0), [node.target.id], node.value, scope_id))
            if self.sink_patterns:
                try:
                    code_str = ast.unparse(node)
                    if any(p in code_str for p in self.sink_patterns):
                        self._sink_calls.append((getattr(node, "lineno", 0), node, -1, scope_id))
                except:
                    pass
        elif isinstance(node, ast.Return) and self.returns_are_sinks:
            self._sink_calls.append((getattr(node, "lineno", 0), node, -1, scope_id))
        elif isinstance(node, ast.Call):
            line = getattr(node, "lineno", 0)
            if isinstance(node.func, ast.Attribute):
                attr = getattr(node.func, "attr", None)
                if attr in self.sink_attrs and node.args:
                    self._sink_calls.append((line, node, self.sink_arg_index, scope_id))
            elif isinstance(node.func, ast.Name):
                name = getattr(node.func, "id", None)
                if name in self.sink_names and node.args:
                    self._sink_calls.append((line, node, self.sink_arg_index, scope_id))
        for child in ast.iter_child_nodes(node):
            self._collect_assignments_and_sinks(child, new_st)

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

    def _expr_tainted(self, node, scope_id):
        if node is None:
            return False
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if self.sink_patterns and any(p in node.value for p in self.sink_patterns):
                return True
        if isinstance(node, ast.Name):
            if getattr(node, "id", None) in self.taint_source_vars:
                return True
            return (getattr(node, "id", None), scope_id) in self._tainted
        if isinstance(node, ast.Call):
            # Check if this function cleans the data
            if isinstance(node.func, ast.Name) and getattr(node.func, "id", None) in self.sanitizer_names:
                return False
            if isinstance(node.func, ast.Attribute) and getattr(node.func, "attr", None) in self.sanitizer_names:
                return False
                
            if self._is_taint_source_call(node):
                return True
            for a in node.args:
                if self._expr_tainted(a, scope_id):
                    return True
            for k in getattr(node, "keywords", []) or []:
                if self._expr_tainted(k.value, scope_id):
                    return True
            return False
        if isinstance(node, ast.BinOp) and isinstance(getattr(node, "op", None), (ast.Add, ast.Mod)):
            return self._expr_tainted(node.left, scope_id) or self._expr_tainted(node.right, scope_id)
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue) and self._expr_tainted(v.value, scope_id):
                    return True
            return False
        if isinstance(node, ast.Attribute):
            return self._expr_tainted(node.value, scope_id) if hasattr(node, "value") else False
        if isinstance(node, ast.Subscript):
            if self._is_request_like(node.value):
                return True
            return self._expr_tainted(node.value, scope_id) or self._expr_tainted(
                node.slice if isinstance(node.slice, ast.AST) else None, scope_id
            )
        if isinstance(node, (ast.List, ast.Tuple)):
            for e in getattr(node, "elts", []) or []:
                if self._expr_tainted(e, scope_id):
                    return True
            return False
        if isinstance(node, ast.Dict):
            for value in getattr(node, "values", []) or []:
                if self._expr_tainted(value, scope_id):
                    return True
            return False
        return False

    def _compute_tainted_fixpoint(self):
        changed = True
        while changed:
            changed = False
            for _line, targets, value, scope_id in self._assignments:
                if not self._expr_tainted(value, scope_id):
                    continue
                for name in targets:
                    if (name, scope_id) not in self._tainted:
                        self._tainted.add((name, scope_id))
                        changed = True

    def _report_tainted_sinks(self):
        for line, call_node, arg_idx, scope_id in self._sink_calls:
            if isinstance(call_node, ast.Call):
                if arg_idx >= len(call_node.args):
                    continue
                arg = call_node.args[arg_idx]
            elif isinstance(call_node, ast.Return):
                arg = call_node.value
            elif isinstance(call_node, (ast.Assign, ast.AugAssign)):
                arg = call_node.value
            else:
                continue

            if not self._expr_tainted(arg, scope_id):
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
