#!/usr/bin/env python3
"""
Enhanced SQL Injection Detector with SonarQube Security Standards Integration
Based on SonarQube's security approach for vulnerability detection and categorization

This enhanced detector provides:
- SonarQube-style security categorization
- CWE and OWASP Top 10 compliance mapping
- Vulnerability probability scoring
- Enhanced remediation guidance
- Better confidence scoring
"""

import ast
import re
from typing import List, Dict, Any, Set, Tuple, Optional
from dataclasses import dataclass, field
from pathlib import Path
import json
from datetime import datetime

from sonarqube_security_standards import (
    SecurityStandards, 
    VulnerabilityProbability, 
    SQCategory, 
    SQLInjectionPatterns,
    ComplianceMapper,
    RemediationGuidance
)

# Import the original detector
from sql_injection_detector import SQLInjectionDetector, Vulnerability


@dataclass
class EnhancedVulnerability:
    """Enhanced vulnerability with SonarQube security standards"""
    file_path: str
    line_number: int
    column_number: int = 0
    vulnerability_type: str = ""
    description: str = ""
    severity: str = ""
    code_snippet: str = ""
    remediation: str = ""
    confidence: float = 0.0
    
    # SonarQube-inspired fields
    security_standards: SecurityStandards = field(default_factory=lambda: SecurityStandards(set(), set(), set(), set(), SQCategory.OTHERS, 0.0))
    cwe_references: List[str] = field(default_factory=list)
    owasp_references: List[str] = field(default_factory=list)
    sq_category: str = ""
    vulnerability_probability: str = ""
    remediation_guidance: Dict[str, Any] = field(default_factory=dict)
    pattern_analysis: Dict[str, Any] = field(default_factory=dict)
    
    # Additional metadata
    detected_at: str = field(default_factory=lambda: datetime.now().isoformat())
    rule_key: str = ""
    affected_lines: List[int] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column_number": self.column_number,
            "vulnerability_type": self.vulnerability_type,
            "description": self.description,
            "severity": self.severity,
            "code_snippet": self.code_snippet,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "security_standards": self.security_standards.to_dict(),
            "cwe_references": self.cwe_references,
            "owasp_references": self.owasp_references,
            "sq_category": self.sq_category,
            "vulnerability_probability": self.vulnerability_probability,
            "remediation_guidance": self.remediation_guidance,
            "pattern_analysis": self.pattern_analysis,
            "detected_at": self.detected_at,
            "rule_key": self.rule_key,
            "affected_lines": self.affected_lines
        }


class EnhancedSQLInjectionDetector(SQLInjectionDetector):
    """Enhanced SQL injection detector with SonarQube security standards"""
    
    def __init__(self):
        super().__init__()
        self.enhanced_vulnerabilities: List[EnhancedVulnerability] = []
        self.pattern_analyzer = SQLInjectionPatterns()
        self.compliance_mapper = ComplianceMapper()
        self.remediation_guidance = RemediationGuidance()
        
        # Rule definitions (SonarQube-style)
        self.rules = {
            "python:S2077": {
                "key": "python:S2077",
                "name": "SQL queries should not be vulnerable to injection attacks",
                "type": "VULNERABILITY",
                "severity": "HIGH",
                "category": SQCategory.SQL_INJECTION,
                "cwe": ["89", "564", "943"],
                "owasp": ["A03:2021-Injection"],
                "description": "SQL queries should use parameterized queries to prevent injection attacks"
            },
            "python:S2078": {
                "key": "python:S2078",
                "name": "NoSQL queries should not be vulnerable to injection attacks",
                "type": "VULNERABILITY",
                "severity": "HIGH",
                "category": SQCategory.SQL_INJECTION,
                "cwe": ["89", "943"],
                "owasp": ["A03:2021-Injection"],
                "description": "NoSQL queries should use parameterized queries to prevent injection attacks"
            },
            "python:S2079": {
                "key": "python:S2079",
                "name": "Dynamic SQL construction should be avoided",
                "type": "VULNERABILITY",
                "severity": "MAJOR",
                "category": SQCategory.SQL_INJECTION,
                "cwe": ["89"],
                "owasp": ["A03:2021-Injection"],
                "description": "Dynamic SQL construction using string concatenation is dangerous"
            }
        }
    
    def scan_file(self, file_path: str) -> List[EnhancedVulnerability]:
        """Enhanced file scanning with SonarQube security standards"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse the AST
            tree = ast.parse(content)
            
            # Reset vulnerabilities for this file
            self.enhanced_vulnerabilities = []
            
            # Perform enhanced AST analysis
            self._enhanced_analyze_ast(tree, file_path, content)
            
            # Perform pattern-based analysis
            self._pattern_based_analysis(content, file_path)
            
            # Perform data flow analysis
            self._enhanced_data_flow_analysis(tree, file_path)
            
            # Post-process vulnerabilities
            self._post_process_vulnerabilities(content)
            
            return self.enhanced_vulnerabilities
            
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
            return []
    
    def _enhanced_analyze_ast(self, tree: ast.AST, file_path: str, content: str):
        """Enhanced AST analysis with security standards"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._enhanced_check_execute_call(node, file_path, content)
                self._enhanced_check_nosql_call(node, file_path, content)
            elif isinstance(node, ast.BinOp):
                self._enhanced_check_string_concatenation(node, file_path, content)
            elif isinstance(node, ast.JoinedStr):
                self._enhanced_check_f_string(node, file_path, content)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self._enhanced_check_format_method(node, file_path, content)
    
    def _enhanced_check_execute_call(self, node: ast.Call, file_path: str, content: str):
        """Enhanced execute call analysis"""
        if not isinstance(node.func, ast.Attribute):
            return
            
        func_name = node.func.attr
        
        if func_name in ['execute', 'executemany', 'query']:
            if node.args and self._is_vulnerable_sql_argument(node.args[0]):
                # Analyze the code snippet for patterns
                code_snippet = self._get_code_snippet(content, node.lineno, context_lines=3)
                pattern_analysis = self.pattern_analyzer.analyze_code_snippet(code_snippet)
                confidence = self.pattern_analyzer.calculate_confidence(pattern_analysis)
                
                # Create security standards
                security_standards = SecurityStandards.from_vulnerability_type("sql_injection", confidence)
                
                # Get remediation guidance
                remediation_guidance = self.remediation_guidance.get_remediation("sql_injection")
                
                # Determine rule key
                rule_key = "python:S2077"  # SQL injection rule
                
                # Create enhanced vulnerability
                vuln = EnhancedVulnerability(
                    file_path=file_path,
                    line_number=node.lineno,
                    column_number=getattr(node, 'col_offset', 0),
                    vulnerability_type="SQL_INJECTION_EXECUTE",
                    description=f"Unsafe SQL execution using {func_name} with user input",
                    severity=self._map_severity(confidence),
                    code_snippet=code_snippet,
                    remediation="Use parameterized queries with placeholders",
                    confidence=confidence,
                    security_standards=security_standards,
                    cwe_references=list(security_standards.cwe),
                    owasp_references=list(security_standards.owasp_top10_2021),
                    sq_category=security_standards.sq_category.key,
                    vulnerability_probability=security_standards.sq_category.vulnerability.name,
                    remediation_guidance=remediation_guidance,
                    pattern_analysis=pattern_analysis,
                    rule_key=rule_key,
                    affected_lines=self._get_affected_lines(node, content)
                )
                
                self.enhanced_vulnerabilities.append(vuln)
    
    def _enhanced_check_string_concatenation(self, node: ast.BinOp, file_path: str, content: str):
        """Enhanced string concatenation analysis"""
        if isinstance(node.op, ast.Add):
            if self._is_in_sql_context(node, content):
                code_snippet = self._get_code_snippet(content, node.lineno, context_lines=3)
                pattern_analysis = self.pattern_analyzer.analyze_code_snippet(code_snippet)
                confidence = self.pattern_analyzer.calculate_confidence(pattern_analysis)
                
                security_standards = SecurityStandards.from_vulnerability_type("sql_injection", confidence)
                remediation_guidance = self.remediation_guidance.get_remediation("sql_injection")
                
                vuln = EnhancedVulnerability(
                    file_path=file_path,
                    line_number=node.lineno,
                    column_number=getattr(node, 'col_offset', 0),
                    vulnerability_type="SQL_INJECTION_CONCATENATION",
                    description="String concatenation used in SQL query",
                    severity=self._map_severity(confidence),
                    code_snippet=code_snippet,
                    remediation="Use parameterized queries instead of string concatenation",
                    confidence=confidence,
                    security_standards=security_standards,
                    cwe_references=list(security_standards.cwe),
                    owasp_references=list(security_standards.owasp_top10_2021),
                    sq_category=security_standards.sq_category.key,
                    vulnerability_probability=security_standards.sq_category.vulnerability.name,
                    remediation_guidance=remediation_guidance,
                    pattern_analysis=pattern_analysis,
                    rule_key="python:S2079",
                    affected_lines=self._get_affected_lines(node, content)
                )
                
                self.enhanced_vulnerabilities.append(vuln)
    
    def _enhanced_check_f_string(self, node: ast.JoinedStr, file_path: str, content: str):
        """Enhanced f-string analysis"""
        if self._is_in_sql_context(node, content):
            code_snippet = self._get_code_snippet(content, node.lineno, context_lines=3)
            pattern_analysis = self.pattern_analyzer.analyze_code_snippet(code_snippet)
            confidence = self.pattern_analyzer.calculate_confidence(pattern_analysis)
            
            security_standards = SecurityStandards.from_vulnerability_type("sql_injection", confidence)
            remediation_guidance = self.remediation_guidance.get_remediation("sql_injection")
            
            vuln = EnhancedVulnerability(
                file_path=file_path,
                line_number=node.lineno,
                column_number=getattr(node, 'col_offset', 0),
                vulnerability_type="SQL_INJECTION_F_STRING",
                description="F-string used in SQL query with user input",
                severity=self._map_severity(confidence),
                code_snippet=code_snippet,
                remediation="Use parameterized queries instead of f-strings",
                confidence=confidence,
                security_standards=security_standards,
                cwe_references=list(security_standards.cwe),
                owasp_references=list(security_standards.owasp_top10_2021),
                sq_category=security_standards.sq_category.key,
                vulnerability_probability=security_standards.sq_category.vulnerability.name,
                remediation_guidance=remediation_guidance,
                pattern_analysis=pattern_analysis,
                rule_key="python:S2079",
                affected_lines=self._get_affected_lines(node, content)
            )
            
            self.enhanced_vulnerabilities.append(vuln)
    
    def _enhanced_check_format_method(self, node: ast.Call, file_path: str, content: str):
        """Enhanced format method analysis"""
        if (isinstance(node.func, ast.Attribute) and 
            node.func.attr == 'format' and 
            self._is_in_sql_context(node, content)):
            
            code_snippet = self._get_code_snippet(content, node.lineno, context_lines=3)
            pattern_analysis = self.pattern_analyzer.analyze_code_snippet(code_snippet)
            confidence = self.pattern_analyzer.calculate_confidence(pattern_analysis)
            
            security_standards = SecurityStandards.from_vulnerability_type("sql_injection", confidence)
            remediation_guidance = self.remediation_guidance.get_remediation("sql_injection")
            
            vuln = EnhancedVulnerability(
                file_path=file_path,
                line_number=node.lineno,
                column_number=getattr(node, 'col_offset', 0),
                vulnerability_type="SQL_INJECTION_FORMAT",
                description="String format method used in SQL query",
                severity=self._map_severity(confidence),
                code_snippet=code_snippet,
                remediation="Use parameterized queries instead of string formatting",
                confidence=confidence,
                security_standards=security_standards,
                cwe_references=list(security_standards.cwe),
                owasp_references=list(security_standards.owasp_top10_2021),
                sq_category=security_standards.sq_category.key,
                vulnerability_probability=security_standards.sq_category.vulnerability.name,
                remediation_guidance=remediation_guidance,
                pattern_analysis=pattern_analysis,
                rule_key="python:S2079",
                affected_lines=self._get_affected_lines(node, content)
            )
            
            self.enhanced_vulnerabilities.append(vuln)
    
    def _enhanced_check_nosql_call(self, node: ast.Call, file_path: str, content: str):
        """Enhanced NoSQL injection detection"""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            
            # Check for MongoDB operations
            if func_name in ['find', 'find_one', 'update', 'insert', 'delete', 'aggregate']:
                if node.args and self._is_vulnerable_nosql_argument(node.args[0]):
                    code_snippet = self._get_code_snippet(content, node.lineno, context_lines=3)
                    pattern_analysis = self.pattern_analyzer.analyze_code_snippet(code_snippet)
                    confidence = self.pattern_analyzer.calculate_confidence(pattern_analysis)
                    
                    security_standards = SecurityStandards.from_vulnerability_type("nosql_injection", confidence)
                    remediation_guidance = self.remediation_guidance.get_remediation("nosql_injection")
                    
                    vuln = EnhancedVulnerability(
                        file_path=file_path,
                        line_number=node.lineno,
                        column_number=getattr(node, 'col_offset', 0),
                        vulnerability_type="NOSQL_INJECTION",
                        description=f"NoSQL injection vulnerability in {func_name} operation",
                        severity=self._map_severity(confidence),
                        code_snippet=code_snippet,
                        remediation="Use parameterized queries and input validation",
                        confidence=confidence,
                        security_standards=security_standards,
                        cwe_references=list(security_standards.cwe),
                        owasp_references=list(security_standards.owasp_top10_2021),
                        sq_category=security_standards.sq_category.key,
                        vulnerability_probability=security_standards.sq_category.vulnerability.name,
                        remediation_guidance=remediation_guidance,
                        pattern_analysis=pattern_analysis,
                        rule_key="python:S2078",
                        affected_lines=self._get_affected_lines(node, content)
                    )
                    
                    self.enhanced_vulnerabilities.append(vuln)
    
    def _pattern_based_analysis(self, content: str, file_path: str):
        """Pattern-based vulnerability analysis"""
        lines = content.split('\n')
        pattern_analysis = self.pattern_analyzer.analyze_code_snippet(content)
        
        # Process high-risk patterns
        for pattern_match in pattern_analysis.get("high_risk", []):
            line_number = self._get_line_number_from_position(content, pattern_match["start"])
            
            security_standards = SecurityStandards.from_vulnerability_type("sql_injection", 0.9)
            remediation_guidance = self.remediation_guidance.get_remediation("sql_injection")
            
            vuln = EnhancedVulnerability(
                file_path=file_path,
                line_number=line_number,
                vulnerability_type="SQL_INJECTION_PATTERN",
                description=f"High-risk SQL injection pattern detected: {pattern_match['category']}",
                severity=self._map_severity(0.9),
                code_snippet=self._get_code_snippet(content, line_number),
                remediation="Use parameterized queries and input validation",
                confidence=0.9,
                security_standards=security_standards,
                cwe_references=list(security_standards.cwe),
                owasp_references=list(security_standards.owasp_top10_2021),
                sq_category=security_standards.sq_category.key,
                vulnerability_probability=security_standards.sq_category.vulnerability.name,
                remediation_guidance=remediation_guidance,
                pattern_analysis={"match": pattern_match},
                rule_key="python:S2077"
            )
            
            self.enhanced_vulnerabilities.append(vuln)
    
    def _enhanced_data_flow_analysis(self, tree: ast.AST, file_path: str):
        """Enhanced data flow analysis"""
        # Find user input sources
        user_inputs = self._find_user_input_sources(tree)
        
        # Find SQL sinks
        sql_sinks = self._find_sql_sinks(tree)
        
        # Analyze data flow from sources to sinks
        for source in user_inputs:
            for sink in sql_sinks:
                if self._has_data_flow(source, sink, tree):
                    # Found a data flow from user input to SQL execution
                    security_standards = SecurityStandards.from_vulnerability_type("sql_injection", 0.8)
                    remediation_guidance = self.remediation_guidance.get_remediation("sql_injection")
                    
                    vuln = EnhancedVulnerability(
                        file_path=file_path,
                        line_number=sink.lineno,
                        vulnerability_type="SQL_INJECTION_DATA_FLOW",
                        description="Data flow from user input to SQL execution detected",
                        severity="HIGH",
                        code_snippet=self._get_code_snippet(open(file_path).read(), sink.lineno),
                        remediation="Sanitize user input before using in SQL queries",
                        confidence=0.8,
                        security_standards=security_standards,
                        cwe_references=list(security_standards.cwe),
                        owasp_references=list(security_standards.owasp_top10_2021),
                        sq_category=security_standards.sq_category.key,
                        vulnerability_probability=security_standards.sq_category.vulnerability.name,
                        remediation_guidance=remediation_guidance,
                        rule_key="python:S2077"
                    )
                    
                    self.enhanced_vulnerabilities.append(vuln)
    
    def _post_process_vulnerabilities(self, content: str):
        """Post-process vulnerabilities to remove duplicates and enhance data"""
        # Remove duplicates based on line number and type
        unique_vulns = []
        seen = set()
        
        for vuln in self.enhanced_vulnerabilities:
            key = (vuln.file_path, vuln.line_number, vuln.vulnerability_type)
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        self.enhanced_vulnerabilities = unique_vulns
        
        # Sort by line number
        self.enhanced_vulnerabilities.sort(key=lambda x: x.line_number)
    
    def _map_severity(self, confidence: float) -> str:
        """Map confidence to severity level (UI-compatible)"""
        if confidence >= 0.9:
            return "HIGH"  # Changed from CRITICAL to HIGH for UI compatibility
        elif confidence >= 0.7:
            return "MEDIUM"  # Changed from HIGH to MEDIUM for UI compatibility
        elif confidence >= 0.5:
            return "LOW"  # Changed from MEDIUM to LOW for UI compatibility
        else:
            return "LOW"
    
    def _get_affected_lines(self, node: ast.AST, content: str) -> List[int]:
        """Get all lines affected by this node"""
        if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
            return list(range(node.lineno, (node.end_lineno or node.lineno) + 1))
        elif hasattr(node, 'lineno'):
            return [node.lineno]
        else:
            return []
    
    def _get_line_number_from_position(self, content: str, position: int) -> int:
        """Get line number from character position"""
        return content[:position].count('\n') + 1
    
    def get_enhanced_report(self) -> Dict[str, Any]:
        """Generate enhanced vulnerability report"""
        if not self.enhanced_vulnerabilities:
            return {
                "summary": {
                    "total_vulnerabilities": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "high_severity": 0,
                    "medium_severity": 0,
                    "low_severity": 0,
                    "scan_date": datetime.now().isoformat(),
                    "average_confidence": 0.0
                },
                "compliance": {
                    "cwe_distribution": {},
                    "owasp_top10_distribution": {}
                },
                "vulnerabilities": []
            }
        
        # Calculate statistics
        total_vulns = len(self.enhanced_vulnerabilities)
        high_count = sum(1 for v in self.enhanced_vulnerabilities if v.severity == "HIGH")
        medium_count = sum(1 for v in self.enhanced_vulnerabilities if v.severity == "MEDIUM")
        low_count = sum(1 for v in self.enhanced_vulnerabilities if v.severity == "LOW")
        
        # Severity counts are now UI-compatible
        high_severity_count = high_count
        medium_severity_count = medium_count
        low_severity_count = low_count
        
        # Group by CWE
        cwe_counts = {}
        for vuln in self.enhanced_vulnerabilities:
            for cwe in vuln.cwe_references:
                cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        
        # Group by OWASP Top 10
        owasp_counts = {}
        for vuln in self.enhanced_vulnerabilities:
            for owasp in vuln.owasp_references:
                owasp_counts[owasp] = owasp_counts.get(owasp, 0) + 1
        
        report = {
            "summary": {
                "total_vulnerabilities": total_vulns,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                # UI-compatible severity counts
                "high_severity": high_severity_count,
                "medium_severity": medium_severity_count,
                "low_severity": low_severity_count,
                "scan_date": datetime.now().isoformat(),
                "average_confidence": sum(v.confidence for v in self.enhanced_vulnerabilities) / total_vulns
            },
            "compliance": {
                "cwe_distribution": cwe_counts,
                "owasp_top10_distribution": owasp_counts
            },
            "vulnerabilities": [vuln.to_dict() for vuln in self.enhanced_vulnerabilities]
        }
        
        return report
    
    def export_sonarqube_format(self, output_file: str):
        """Export vulnerabilities in SonarQube-compatible format"""
        sonar_issues = []
        
        for vuln in self.enhanced_vulnerabilities:
            sonar_issue = {
                "engineId": "python-security-scanner",
                "ruleId": vuln.rule_key,
                "severity": vuln.severity,
                "type": "VULNERABILITY",
                "primaryLocation": {
                    "message": vuln.description,
                    "filePath": vuln.file_path,
                    "textRange": {
                        "startLine": vuln.line_number,
                        "endLine": vuln.line_number
                    }
                },
                "cwe": vuln.cwe_references,
                "owasp": vuln.owasp_references,
                "confidence": vuln.confidence
            }
            sonar_issues.append(sonar_issue)
        
        with open(output_file, 'w') as f:
            json.dump({"issues": sonar_issues}, f, indent=2)
    
    def print_enhanced_report(self):
        """Print enhanced vulnerability report"""
        report = self.get_enhanced_report()
        
        print("=" * 80)
        print("ENHANCED SQL INJECTION VULNERABILITY REPORT")
        print("=" * 80)
        
        if report.get("summary"):
            summary = report["summary"]
            print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
            print(f"High: {summary['high']}")
            print(f"Medium: {summary['medium']}")
            print(f"Low: {summary['low']}")
            print(f"Average Confidence: {summary['average_confidence']:.2f}")
            print()
            
            print("CWE Distribution:")
            for cwe, count in report["compliance"]["cwe_distribution"].items():
                print(f"  CWE-{cwe}: {count} vulnerabilities")
            print()
            
            print("OWASP Top 10 Distribution:")
            for owasp, count in report["compliance"]["owasp_top10_distribution"].items():
                print(f"  {owasp}: {count} vulnerabilities")
            print()
        
        print("VULNERABILITIES:")
        print("-" * 80)
        
        for vuln in self.enhanced_vulnerabilities:
            print(f"File: {vuln.file_path}")
            print(f"Line: {vuln.line_number}")
            print(f"Type: {vuln.vulnerability_type}")
            print(f"Severity: {vuln.severity}")
            print(f"Confidence: {vuln.confidence:.2f}")
            print(f"CWE: {', '.join(vuln.cwe_references)}")
            print(f"OWASP: {', '.join(vuln.owasp_references)}")
            print(f"Description: {vuln.description}")
            print(f"Remediation: {vuln.remediation}")
            print(f"Code Snippet:")
            print(f"  {vuln.code_snippet}")
            print("-" * 80) 