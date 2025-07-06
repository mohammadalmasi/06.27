#!/usr/bin/env python3
"""
SonarQube-inspired Security Standards for SQL Injection Detection
Based on SonarQube's SecurityStandards.java implementation

This module provides security categorization, vulnerability probability scoring,
and compliance mapping for SQL injection vulnerabilities.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Union
from enum import Enum
import re


class VulnerabilityProbability(Enum):
    """Vulnerability probability levels from SonarQube"""
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    
    def __str__(self):
        return self.name


class SQCategory(Enum):
    """Security categories from SonarQube"""
    BUFFER_OVERFLOW = ("buffer-overflow", VulnerabilityProbability.HIGH)
    SQL_INJECTION = ("sql-injection", VulnerabilityProbability.HIGH)
    RCE = ("rce", VulnerabilityProbability.MEDIUM)
    OBJECT_INJECTION = ("object-injection", VulnerabilityProbability.LOW)
    COMMAND_INJECTION = ("command-injection", VulnerabilityProbability.HIGH)
    PATH_TRAVERSAL_INJECTION = ("path-traversal-injection", VulnerabilityProbability.HIGH)
    LDAP_INJECTION = ("ldap-injection", VulnerabilityProbability.LOW)
    XPATH_INJECTION = ("xpath-injection", VulnerabilityProbability.LOW)
    LOG_INJECTION = ("log-injection", VulnerabilityProbability.LOW)
    XXE = ("xxe", VulnerabilityProbability.MEDIUM)
    XSS = ("xss", VulnerabilityProbability.HIGH)
    DOS = ("dos", VulnerabilityProbability.MEDIUM)
    SSRF = ("ssrf", VulnerabilityProbability.MEDIUM)
    CSRF = ("csrf", VulnerabilityProbability.HIGH)
    HTTP_RESPONSE_SPLITTING = ("http-response-splitting", VulnerabilityProbability.LOW)
    OPEN_REDIRECT = ("open-redirect", VulnerabilityProbability.MEDIUM)
    WEAK_CRYPTOGRAPHY = ("weak-cryptography", VulnerabilityProbability.MEDIUM)
    AUTH = ("auth", VulnerabilityProbability.HIGH)
    INSECURE_CONF = ("insecure-conf", VulnerabilityProbability.LOW)
    FILE_MANIPULATION = ("file-manipulation", VulnerabilityProbability.LOW)
    ENCRYPTION_OF_SENSITIVE_DATA = ("encrypt-data", VulnerabilityProbability.LOW)
    TRACEABILITY = ("traceability", VulnerabilityProbability.LOW)
    PERMISSION = ("permission", VulnerabilityProbability.MEDIUM)
    OTHERS = ("others", VulnerabilityProbability.LOW)
    
    def __init__(self, key: str, vulnerability: VulnerabilityProbability):
        self.key = key
        self.vulnerability = vulnerability


class OwaspTop10(Enum):
    """OWASP Top 10 categories"""
    A01_BROKEN_ACCESS_CONTROL = "A01:2021-Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021-Cryptographic Failures"
    A03_INJECTION = "A03:2021-Injection"
    A04_INSECURE_DESIGN = "A04:2021-Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021-Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021-Vulnerable and Outdated Components"
    A07_IDENTIFICATION_FAILURES = "A07:2021-Identification and Authentication Failures"
    A08_SOFTWARE_INTEGRITY_FAILURES = "A08:2021-Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021-Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021-Server-Side Request Forgery"


@dataclass
class SecurityStandards:
    """Security standards container inspired by SonarQube's implementation"""
    standards: Set[str]
    cwe: Set[str]
    owasp_top10: Set[str]
    owasp_top10_2021: Set[str]
    sq_category: SQCategory
    confidence: float
    
    @classmethod
    def from_vulnerability_type(cls, vulnerability_type: str, confidence: float = 0.8) -> 'SecurityStandards':
        """Create SecurityStandards from vulnerability type"""
        standards = set()
        cwe = set()
        owasp_top10 = set()
        owasp_top10_2021 = set()
        sq_category = SQCategory.OTHERS
        
        if "sql" in vulnerability_type.lower():
            standards.add("sql-injection")
            cwe.update(["89", "564", "943"])  # CWE-89: SQL Injection, CWE-564: Unused Variable, CWE-943: Improper Neutralization of Special Elements in Data Query Logic
            owasp_top10.add("A1")  # Legacy OWASP Top 10
            owasp_top10_2021.add("A03")  # OWASP Top 10 2021
            sq_category = SQCategory.SQL_INJECTION
        elif "nosql" in vulnerability_type.lower():
            standards.add("nosql-injection")
            cwe.update(["89", "943"])
            owasp_top10.add("A1")
            owasp_top10_2021.add("A03")
            sq_category = SQCategory.SQL_INJECTION
        elif "command" in vulnerability_type.lower():
            standards.add("command-injection")
            cwe.update(["77", "78", "88", "214"])
            owasp_top10.add("A1")
            owasp_top10_2021.add("A03")
            sq_category = SQCategory.COMMAND_INJECTION
            
        return cls(
            standards=standards,
            cwe=cwe,
            owasp_top10=owasp_top10,
            owasp_top10_2021=owasp_top10_2021,
            sq_category=sq_category,
            confidence=confidence
        )
    
    def to_dict(self) -> Dict[str, Union[str, List[str], float]]:
        """Convert to dictionary for serialization"""
        return {
            "standards": list(self.standards),
            "cwe": list(self.cwe),
            "owasp_top10": list(self.owasp_top10),
            "owasp_top10_2021": list(self.owasp_top10_2021),
            "sq_category": self.sq_category.key,
            "vulnerability_probability": self.sq_category.vulnerability.name,
            "confidence": self.confidence
        }


class SQLInjectionPatterns:
    """SQL injection pattern detection based on SonarQube's approach"""
    
    # High-risk patterns (immediate SQL injection)
    HIGH_RISK_PATTERNS = {
        # String concatenation patterns
        "string_concat": [
            r'(\+\s*[\'"][^\'"]*[\'"]|\+\s*\w+)',  # + "something" or + variable
            r'([\'"][^\'"]*[\'"]|\w+)\s*\+',       # "something" + or variable +
        ],
        
        # F-string patterns
        "f_string": [
            r'f[\'"][^\'"]*\{[^}]*\}[^\'"]*[\'"]',  # f"...{variable}..."
        ],
        
        # String formatting patterns
        "string_format": [
            r'%\s*[(\[]?[^))\]]*[)\]]?',           # % formatting
            r'\.format\s*\([^)]*\)',               # .format() method
        ],
        
        # Direct SQL execution patterns
        "direct_execution": [
            r'(execute|executemany|query)\s*\([^)]*\+[^)]*\)',  # execute with concatenation
            r'(execute|executemany|query)\s*\([^)]*f[\'"][^)]*\)',  # execute with f-string
        ],
        
        # Dynamic SQL construction
        "dynamic_sql": [
            r'(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+[^;]*\+',  # SQL keywords with concat
            r'(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+[^;]*\{[^}]*\}',  # SQL with f-string
        ]
    }
    
    # Medium-risk patterns (potential SQL injection)
    MEDIUM_RISK_PATTERNS = {
        # Input validation bypasses
        "input_validation": [
            r'(request\.(args|form|json|cookies|headers)\[[\'"]\w+[\'"]\])',  # Direct user input
            r'(input|raw_input)\s*\(',  # Console input
            r'os\.environ\[[\'"]\w+[\'"]\]',  # Environment variables
        ],
        
        # Parameterized query misuse
        "param_misuse": [
            r'execute\s*\([^)]*%s[^)]*\+',  # Parameterized with concatenation
            r'execute\s*\([^)]*\?\s*[^)]*\+',  # SQLite param with concat
        ]
    }
    
    # Low-risk patterns (suspicious but might be safe)
    LOW_RISK_PATTERNS = {
        # Safe patterns that might be misused
        "potentially_safe": [
            r'execute\s*\([^)]*,\s*[\[\(]',  # execute with parameters
            r'execute\s*\([^)]*\?\s*[^+]*\)',  # SQLite parameterized
        ]
    }
    
    @classmethod
    def analyze_code_snippet(cls, code: str) -> Dict[str, List[Dict]]:
        """Analyze code snippet for SQL injection patterns"""
        results = {
            "high_risk": [],
            "medium_risk": [],
            "low_risk": []
        }
        
        # Check high-risk patterns
        for category, patterns in cls.HIGH_RISK_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    results["high_risk"].append({
                        "category": category,
                        "pattern": pattern,
                        "match": match.group(),
                        "start": match.start(),
                        "end": match.end()
                    })
        
        # Check medium-risk patterns
        for category, patterns in cls.MEDIUM_RISK_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    results["medium_risk"].append({
                        "category": category,
                        "pattern": pattern,
                        "match": match.group(),
                        "start": match.start(),
                        "end": match.end()
                    })
        
        # Check low-risk patterns
        for category, patterns in cls.LOW_RISK_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    results["low_risk"].append({
                        "category": category,
                        "pattern": pattern,
                        "match": match.group(),
                        "start": match.start(),
                        "end": match.end()
                    })
        
        return results
    
    @classmethod
    def calculate_confidence(cls, analysis_results: Dict[str, List[Dict]]) -> float:
        """Calculate confidence score based on pattern analysis"""
        high_risk_count = len(analysis_results["high_risk"])
        medium_risk_count = len(analysis_results["medium_risk"])
        low_risk_count = len(analysis_results["low_risk"])
        
        if high_risk_count > 0:
            return min(0.9 + (high_risk_count - 1) * 0.02, 0.99)
        elif medium_risk_count > 0:
            return min(0.6 + (medium_risk_count - 1) * 0.05, 0.85)
        elif low_risk_count > 0:
            return min(0.3 + (low_risk_count - 1) * 0.02, 0.5)
        else:
            return 0.0


class ComplianceMapper:
    """Map vulnerabilities to compliance standards"""
    
    CWE_MAPPINGS = {
        "sql_injection": ["89", "564", "943"],
        "nosql_injection": ["89", "943"],
        "command_injection": ["77", "78", "88", "214"],
        "path_traversal": ["22"],
        "xss": ["79", "80", "81", "82", "83", "84", "85", "86", "87"],
        "xxe": ["611", "827"],
        "csrf": ["352"],
        "ssrf": ["918"],
        "dos": ["400", "624"],
        "weak_crypto": ["295", "297", "321", "322", "323", "324", "325", "326", "327", "328", "330", "780"],
        "auth": ["798", "640", "620", "549", "522", "521", "263", "262", "261", "259", "308"],
        "insecure_conf": ["102", "215", "346", "614", "489", "942"]
    }
    
    OWASP_TOP10_2021_MAPPINGS = {
        "sql_injection": ["A03:2021-Injection"],
        "nosql_injection": ["A03:2021-Injection"],
        "command_injection": ["A03:2021-Injection"],
        "xss": ["A03:2021-Injection"],
        "xxe": ["A03:2021-Injection"],
        "path_traversal": ["A01:2021-Broken Access Control"],
        "csrf": ["A01:2021-Broken Access Control"],
        "ssrf": ["A10:2021-Server-Side Request Forgery"],
        "weak_crypto": ["A02:2021-Cryptographic Failures"],
        "auth": ["A07:2021-Identification and Authentication Failures"],
        "insecure_conf": ["A05:2021-Security Misconfiguration"]
    }
    
    @classmethod
    def map_vulnerability(cls, vuln_type: str) -> Dict[str, List[str]]:
        """Map vulnerability type to compliance standards"""
        vuln_key = vuln_type.lower().replace(" ", "_").replace("-", "_")
        
        return {
            "cwe": cls.CWE_MAPPINGS.get(vuln_key, []),
            "owasp_top10_2021": cls.OWASP_TOP10_2021_MAPPINGS.get(vuln_key, []),
            "sq_category": SQCategory.SQL_INJECTION.key if "sql" in vuln_key else SQCategory.OTHERS.key
        }


class RemediationGuidance:
    """Provide remediation guidance based on SonarQube's approach"""
    
    REMEDIATION_TEMPLATES = {
        "sql_injection": {
            "title": "SQL Injection Vulnerability",
            "description": "User input is directly concatenated into SQL queries without proper sanitization",
            "remediation": [
                "Use parameterized queries or prepared statements",
                "Implement input validation and sanitization",
                "Use ORM frameworks with built-in protection",
                "Apply the principle of least privilege for database access",
                "Use stored procedures with parameterized inputs"
            ],
            "examples": {
                "vulnerable": "cursor.execute(\"SELECT * FROM users WHERE id = \" + user_id)",
                "safe": "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))"
            }
        },
        "nosql_injection": {
            "title": "NoSQL Injection Vulnerability",
            "description": "User input is directly embedded in NoSQL queries without proper validation",
            "remediation": [
                "Use parameterized queries or query builders",
                "Validate and sanitize all user inputs",
                "Use whitelist validation for expected inputs",
                "Implement proper access controls",
                "Use database-specific security features"
            ],
            "examples": {
                "vulnerable": "collection.find({\"username\": user_input})",
                "safe": "collection.find({\"username\": {\"$eq\": user_input}})"
            }
        }
    }
    
    @classmethod
    def get_remediation(cls, vuln_type: str) -> Dict[str, Union[str, List[str], Dict[str, str]]]:
        """Get remediation guidance for vulnerability type"""
        vuln_key = vuln_type.lower().replace(" ", "_").replace("-", "_")
        
        if "sql" in vuln_key and "nosql" not in vuln_key:
            return cls.REMEDIATION_TEMPLATES["sql_injection"]
        elif "nosql" in vuln_key:
            return cls.REMEDIATION_TEMPLATES["nosql_injection"]
        else:
            return {
                "title": "Security Vulnerability",
                "description": "Potential security vulnerability detected",
                "remediation": [
                    "Review the code for security issues",
                    "Implement proper input validation",
                    "Follow secure coding practices",
                    "Use security-focused libraries and frameworks"
                ],
                "examples": {
                    "vulnerable": "// Review this code for security issues",
                    "safe": "// Implement proper security measures"
                }
            } 