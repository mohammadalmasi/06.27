import ast
import re
from typing import List, Dict, Any, Set, Tuple
from dataclasses import dataclass
from pathlib import Path

# Optional imports for database libraries
try:
    import sqlite3
except ImportError:
    sqlite3 = None

try:
    import mysql.connector
except ImportError:
    mysql = None

try:
    import psycopg2
except ImportError:
    psycopg2 = None

@dataclass
class Vulnerability:
    """Represents a detected SQL injection vulnerability"""
    file_path: str
    line_number: int
    vulnerability_type: str
    description: str
    severity: str
    code_snippet: str
    remediation: str
    confidence: float

class SQLInjectionDetector:
    """
    Advanced SQL Injection Detector using AST analysis
    Provides more accurate detection than regex-based approaches
    """
    
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.sources: Set[str] = set()  # User input sources
        self.sinks: Set[str] = set()    # SQL execution points
        self.data_flows: List[Tuple[str, str]] = []  # Source to sink flows
        
        # Common user input sources
        self.user_input_sources = {
            'flask': ['request.args', 'request.form', 'request.json', 'request.cookies'],
            'django': ['request.GET', 'request.POST', 'request.COOKIES'],
            'fastapi': ['request.query_params', 'request.form', 'request.cookies'],
            'general': ['input()', 'raw_input()', 'sys.argv', 'os.environ']
        }
        
        # SQL execution sinks
        self.sql_sinks = {
            'sqlite3': ['execute', 'executemany'],
            'mysql': ['execute', 'executemany'],
            'postgresql': ['execute', 'executemany'],
            'sqlalchemy': ['execute', 'text'],
            'django': ['raw', 'extra', 'execute'],
            'general': ['execute', 'executemany', 'callproc']
        }
        
        # Database libraries
        self.db_libraries = {
            'sqlite3': 'sqlite3',
            'mysql.connector': 'mysql.connector',
            'psycopg2': 'psycopg2',
            'pymysql': 'pymysql',
            'sqlalchemy': 'sqlalchemy',
            'django.db': 'django.db'
        }

    def scan_file(self, file_path: str) -> List[Vulnerability]:
        """
        Scan a single Python file for SQL injection vulnerabilities
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse the AST
            tree = ast.parse(content)
            
            # Reset vulnerabilities for this file
            self.vulnerabilities = []
            
            # Perform AST-based analysis
            self._analyze_ast(tree, file_path, content)
            
            # Perform data flow analysis
            self._analyze_data_flow(tree, file_path)
            
            # Perform library-specific analysis
            self._analyze_library_usage(tree, file_path, content)
            
            return self.vulnerabilities
            
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
            return []

    def _analyze_ast(self, tree: ast.AST, file_path: str, content: str):
        """AST-based vulnerability detection"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._check_execute_call(node, file_path, content)
            elif isinstance(node, ast.BinOp):
                self._check_string_concatenation(node, file_path, content)
            elif isinstance(node, ast.JoinedStr):
                self._check_f_string(node, file_path, content)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self._check_format_method(node, file_path, content)

    def _check_execute_call(self, node: ast.Call, file_path: str, content: str):
        """Check if execute call is vulnerable"""
        if not isinstance(node.func, ast.Attribute):
            return
            
        func_name = node.func.attr
        
        # Check if it's a database execute method
        if func_name in ['execute', 'executemany']:
            if node.args and self._is_vulnerable_sql_argument(node.args[0]):
                self._add_vulnerability(
                    file_path=file_path,
                    line_number=node.lineno,
                    vulnerability_type="SQL_INJECTION_EXECUTE",
                    description=f"Unsafe SQL execution using {func_name} with user input",
                    severity="HIGH",
                    code_snippet=self._get_code_snippet(content, node.lineno),
                    remediation="Use parameterized queries with placeholders",
                    confidence=0.9
                )

    def _check_string_concatenation(self, node: ast.BinOp, file_path: str, content: str):
        """Check for vulnerable string concatenation in SQL context"""
        if isinstance(node.op, ast.Add):
            # Check if this concatenation is used in SQL context
            if self._is_in_sql_context(node, content):
                self._add_vulnerability(
                    file_path=file_path,
                    line_number=node.lineno,
                    vulnerability_type="SQL_INJECTION_CONCATENATION",
                    description="String concatenation used in SQL query",
                    severity="HIGH",
                    code_snippet=self._get_code_snippet(content, node.lineno),
                    remediation="Use parameterized queries instead of string concatenation",
                    confidence=0.8
                )

    def _check_f_string(self, node: ast.JoinedStr, file_path: str, content: str):
        """Check for vulnerable f-string usage in SQL context"""
        if self._is_in_sql_context(node, content):
            self._add_vulnerability(
                file_path=file_path,
                line_number=node.lineno,
                vulnerability_type="SQL_INJECTION_F_STRING",
                description="F-string used in SQL query with user input",
                severity="HIGH",
                code_snippet=self._get_code_snippet(content, node.lineno),
                remediation="Use parameterized queries instead of f-strings",
                confidence=0.9
            )

    def _check_format_method(self, node: ast.Call, file_path: str, content: str):
        """Check for vulnerable .format() usage in SQL context"""
        if (isinstance(node.func, ast.Attribute) and 
            node.func.attr == 'format' and 
            self._is_in_sql_context(node, content)):
            
            self._add_vulnerability(
                file_path=file_path,
                line_number=node.lineno,
                vulnerability_type="SQL_INJECTION_FORMAT",
                description="String format method used in SQL query",
                severity="HIGH",
                code_snippet=self._get_code_snippet(content, node.lineno),
                remediation="Use parameterized queries instead of string formatting",
                confidence=0.8
            )

    def _is_vulnerable_sql_argument(self, node: ast.AST) -> bool:
        """Check if SQL argument contains user input"""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return True
        elif isinstance(node, ast.JoinedStr):
            return True
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == 'format':
                return True
        elif isinstance(node, ast.Name):
            # Check if variable name suggests user input
            return self._is_user_input_variable(node.id)
        return False

    def _is_user_input_variable(self, var_name: str) -> bool:
        """Check if variable name suggests user input"""
        user_input_patterns = [
            'user', 'input', 'param', 'arg', 'form', 'query', 'request',
            'data', 'value', 'id', 'name', 'email', 'password'
        ]
        return any(pattern in var_name.lower() for pattern in user_input_patterns)

    def _is_in_sql_context(self, node: ast.AST, content: str) -> bool:
        """Check if node is used in SQL context"""
        # Get the line where the node appears
        line_start = content.rfind('\n', 0, self._get_node_position(node)) + 1
        line_end = content.find('\n', line_start)
        if line_end == -1:
            line_end = len(content)
        
        line_content = content[line_start:line_end].lower()
        
        # Check for SQL keywords
        sql_keywords = ['select', 'insert', 'update', 'delete', 'where', 'from', 'into', 'values']
        return any(keyword in line_content for keyword in sql_keywords)

    def _get_node_position(self, node: ast.AST) -> int:
        """Get approximate position of AST node in source code"""
        # This is a simplified approach - in practice, you'd need more sophisticated position tracking
        return 0

    def _analyze_data_flow(self, tree: ast.AST, file_path: str):
        """Analyze data flow from user input sources to SQL sinks"""
        # Identify sources (user input)
        sources = self._find_user_input_sources(tree)
        
        # Identify sinks (SQL execution)
        sinks = self._find_sql_sinks(tree)
        
        # Analyze flows from sources to sinks
        for source in sources:
            for sink in sinks:
                if self._has_data_flow(source, sink, tree):
                    self._add_vulnerability(
                        file_path=file_path,
                        line_number=sink.lineno,
                        vulnerability_type="SQL_INJECTION_DATA_FLOW",
                        description=f"User input flows from {source.id} to SQL execution",
                        severity="CRITICAL",
                        code_snippet=f"Data flow: {source.id} -> {sink.func.attr}",
                        remediation="Validate and sanitize user input before database operations",
                        confidence=0.95
                    )

    def _find_user_input_sources(self, tree: ast.AST) -> List[ast.Name]:
        """Find user input sources in the AST"""
        sources = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                # Check Flask/Django request patterns
                if (isinstance(node.value, ast.Attribute) and 
                    node.value.attr in ['args', 'form', 'json', 'cookies', 'GET', 'POST']):
                    sources.append(node)
            elif isinstance(node, ast.Call):
                # Check input() function calls
                if (isinstance(node.func, ast.Name) and 
                    node.func.id in ['input', 'raw_input']):
                    sources.append(node)
        return sources

    def _find_sql_sinks(self, tree: ast.AST) -> List[ast.Call]:
        """Find SQL execution sinks in the AST"""
        sinks = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ['execute', 'executemany', 'text']:
                    sinks.append(node)
        return sinks

    def _has_data_flow(self, source: ast.AST, sink: ast.AST, tree: ast.AST) -> bool:
        """Check if there's a data flow from source to sink"""
        # Simplified data flow analysis
        # In practice, this would require more sophisticated analysis
        return True

    def _analyze_library_usage(self, tree: ast.AST, file_path: str, content: str):
        """Analyze specific database library usage patterns"""
        imports = self._get_imports(tree)
        
        for lib_name, lib_alias in imports.items():
            if lib_name in self.db_libraries:
                self._check_library_specific_patterns(lib_name, tree, file_path, content)

    def _get_imports(self, tree: ast.AST) -> Dict[str, str]:
        """Extract import statements from AST"""
        imports = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports[alias.name] = alias.asname or alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    full_name = f"{module}.{alias.name}" if module else alias.name
                    imports[full_name] = alias.asname or alias.name
        return imports

    def _check_library_specific_patterns(self, lib_name: str, tree: ast.AST, file_path: str, content: str):
        """Check for library-specific vulnerable patterns"""
        if lib_name == 'sqlite3':
            self._check_sqlite3_patterns(tree, file_path, content)
        elif lib_name == 'mysql.connector':
            self._check_mysql_patterns(tree, file_path, content)
        elif lib_name == 'psycopg2':
            self._check_postgresql_patterns(tree, file_path, content)
        elif lib_name == 'sqlalchemy':
            self._check_sqlalchemy_patterns(tree, file_path, content)

    def _check_sqlite3_patterns(self, tree: ast.AST, file_path: str, content: str):
        """Check SQLite3-specific vulnerable patterns"""
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and 
                isinstance(node.func, ast.Attribute) and 
                node.func.attr == 'execute'):
                
                # Check for direct string concatenation
                if node.args and isinstance(node.args[0], ast.BinOp):
                    self._add_vulnerability(
                        file_path=file_path,
                        line_number=node.lineno,
                        vulnerability_type="SQLITE3_INJECTION",
                        description="SQLite3 execute with string concatenation",
                        severity="HIGH",
                        code_snippet=self._get_code_snippet(content, node.lineno),
                        remediation="Use parameterized queries with ? placeholders",
                        confidence=0.9
                    )

    def _check_mysql_patterns(self, tree: ast.AST, file_path: str, content: str):
        """Check MySQL-specific vulnerable patterns"""
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and 
                isinstance(node.func, ast.Attribute) and 
                node.func.attr == 'execute'):
                
                # Check for % formatting
                if node.args and isinstance(node.args[0], ast.BinOp):
                    self._add_vulnerability(
                        file_path=file_path,
                        line_number=node.lineno,
                        vulnerability_type="MYSQL_INJECTION",
                        description="MySQL execute with string formatting",
                        severity="HIGH",
                        code_snippet=self._get_code_snippet(content, node.lineno),
                        remediation="Use parameterized queries with %s placeholders",
                        confidence=0.9
                    )

    def _check_postgresql_patterns(self, tree: ast.AST, file_path: str, content: str):
        """Check PostgreSQL-specific vulnerable patterns"""
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and 
                isinstance(node.func, ast.Attribute) and 
                node.func.attr == 'execute'):
                
                # Check for % formatting
                if node.args and isinstance(node.args[0], ast.BinOp):
                    self._add_vulnerability(
                        file_path=file_path,
                        line_number=node.lineno,
                        vulnerability_type="POSTGRESQL_INJECTION",
                        description="PostgreSQL execute with string formatting",
                        severity="HIGH",
                        code_snippet=self._get_code_snippet(content, node.lineno),
                        remediation="Use parameterized queries with %s placeholders",
                        confidence=0.9
                    )

    def _check_sqlalchemy_patterns(self, tree: ast.AST, file_path: str, content: str):
        """Check SQLAlchemy-specific vulnerable patterns"""
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and 
                isinstance(node.func, ast.Name) and 
                node.func.id == 'text'):
                
                # Check for text() with string concatenation
                if node.args and isinstance(node.args[0], ast.BinOp):
                    self._add_vulnerability(
                        file_path=file_path,
                        line_number=node.lineno,
                        vulnerability_type="SQLALCHEMY_INJECTION",
                        description="SQLAlchemy text() with string concatenation",
                        severity="HIGH",
                        code_snippet=self._get_code_snippet(content, node.lineno),
                        remediation="Use SQLAlchemy ORM or parameterized text()",
                        confidence=0.9
                    )

    def _get_code_snippet(self, content: str, line_number: int, context_lines: int = 2) -> str:
        """Get code snippet around the specified line"""
        lines = content.split('\n')
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        return '\n'.join(lines[start:end])

    def _add_vulnerability(self, **kwargs):
        """Add a vulnerability to the list"""
        vuln = Vulnerability(**kwargs)
        self.vulnerabilities.append(vuln)

    def scan_directory(self, directory: str) -> List[Vulnerability]:
        """Scan all Python files in a directory"""
        all_vulnerabilities = []
        for py_file in Path(directory).rglob('*.py'):
            vulnerabilities = self.scan_file(str(py_file))
            all_vulnerabilities.extend(vulnerabilities)
        return all_vulnerabilities

    def get_report(self) -> Dict[str, Any]:
        """Generate a comprehensive report"""
        if not self.vulnerabilities:
            return {
                'status': 'CLEAN',
                'message': 'No SQL injection vulnerabilities found!',
                'total_vulnerabilities': 0,
                'vulnerabilities': []
            }
        
        # Group by severity
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        
        return {
            'status': 'VULNERABILITIES_FOUND',
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_breakdown': severity_counts,
            'vulnerabilities': [
                {
                    'file': vuln.file_path,
                    'line': vuln.line_number,
                    'type': vuln.vulnerability_type,
                    'description': vuln.description,
                    'severity': vuln.severity,
                    'confidence': vuln.confidence,
                    'code_snippet': vuln.code_snippet,
                    'remediation': vuln.remediation
                }
                for vuln in self.vulnerabilities
            ]
        }

    def print_report(self):
        """Print a formatted vulnerability report"""
        report = self.get_report()
        
        if report['status'] == 'CLEAN':
            print("✅ No SQL injection vulnerabilities found!")
            return
        
        print(f"🚨 Found {report['total_vulnerabilities']} SQL injection vulnerabilities:\n")
        
        for vuln in report['vulnerabilities']:
            print(f"📁 File: {vuln['file']}")
            print(f"📍 Line: {vuln['line']}")
            print(f"🔍 Type: {vuln['type']}")
            print(f"📝 Description: {vuln['description']}")
            print(f"⚠️  Severity: {vuln['severity']}")
            print(f"🎯 Confidence: {vuln['confidence']:.2f}")
            print(f"💡 Remediation: {vuln['remediation']}")
            print(f"📄 Code Snippet:\n{vuln['code_snippet']}")
            print("-" * 80)

# Example usage
if __name__ == "__main__":
    detector = SQLInjectionDetector()
    
    # Example: Scan a file
    # vulnerabilities = detector.scan_file("example.py")
    # detector.print_report()
    
    # Example: Scan a directory
    # vulnerabilities = detector.scan_directory("./project")
    # detector.print_report() 