#!/usr/bin/env python3
"""
Demonstration script for the Enhanced SQL Injection Detector
This script shows how to use the SonarQube-inspired security standards
for SQL injection detection.
"""

import os
import sys
from pathlib import Path

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from enhanced_sql_injection_detector import EnhancedSQLInjectionDetector
from sonarqube_security_standards import SecurityStandards, SQCategory, VulnerabilityProbability
import json
import tempfile


def demo_vulnerable_code_examples():
    """Demonstrate detection on various vulnerable code examples"""
    
    print("=" * 80)
    print("ENHANCED SQL INJECTION DETECTOR DEMONSTRATION")
    print("Based on SonarQube Security Standards")
    print("=" * 80)
    print()
    
    # Initialize the enhanced detector
    detector = EnhancedSQLInjectionDetector()
    
    # Test cases with different vulnerability types
    test_cases = [
        {
            "name": "String Concatenation Vulnerability",
            "code": """
import sqlite3
from flask import request

def vulnerable_login():
    username = request.form['username']
    password = request.form['password']
    
    # VULNERABLE: Direct string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()
""",
            "expected_cwe": ["89", "564", "943"],
            "expected_owasp": ["A03:2021-Injection"]
        },
        
        {
            "name": "F-String Vulnerability",
            "code": """
import sqlite3
from flask import request

def vulnerable_search():
    search_term = request.args.get('q', '')
    
    # VULNERABLE: F-string interpolation
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
""",
            "expected_cwe": ["89", "564", "943"],
            "expected_owasp": ["A03:2021-Injection"]
        },
        
        {
            "name": "String Format Vulnerability",
            "code": """
import sqlite3
from flask import request

def vulnerable_update():
    user_id = request.form['user_id']
    email = request.form['email']
    
    # VULNERABLE: String formatting
    query = "UPDATE users SET email = '%s' WHERE id = %s" % (email, user_id)
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()
""",
            "expected_cwe": ["89", "564", "943"],
            "expected_owasp": ["A03:2021-Injection"]
        },
        
        {
            "name": "NoSQL Injection Vulnerability",
            "code": """
from pymongo import MongoClient
from flask import request

def vulnerable_nosql_query():
    client = MongoClient()
    db = client.myapp
    collection = db.users
    
    username = request.form['username']
    
    # VULNERABLE: NoSQL injection
    result = collection.find({"username": username})
    return list(result)
""",
            "expected_cwe": ["89", "943"],
            "expected_owasp": ["A03:2021-Injection"]
        },
        
        {
            "name": "Safe Parameterized Query (Should be clean)",
            "code": """
import sqlite3
from flask import request

def safe_login():
    username = request.form['username']
    password = request.form['password']
    
    # SAFE: Parameterized query
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query, (username, password))
    return cursor.fetchone()
""",
            "expected_cwe": [],
            "expected_owasp": []
        }
    ]
    
    all_results = []
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"Test Case {i}: {test_case['name']}")
        print("-" * 60)
        
        # Create temporary file with the test code
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
            temp_file.write(test_case['code'])
            temp_file_path = temp_file.name
        
        try:
            # Scan the code
            vulnerabilities = detector.scan_file(temp_file_path)
            
            # Generate report
            report = detector.get_enhanced_report()
            
            test_result = {
                "test_case": test_case['name'],
                "vulnerabilities_found": len(vulnerabilities),
                "report": report,
                "vulnerabilities": [vuln.to_dict() for vuln in vulnerabilities]
            }
            
            all_results.append(test_result)
            
            if vulnerabilities:
                print(f"✗ Found {len(vulnerabilities)} vulnerabilities")
                
                for vuln in vulnerabilities:
                    print(f"  • Type: {vuln.vulnerability_type}")
                    print(f"  • Severity: {vuln.severity}")
                    print(f"  • Confidence: {vuln.confidence:.2f}")
                    print(f"  • CWE: {', '.join(vuln.cwe_references)}")
                    print(f"  • OWASP: {', '.join(vuln.owasp_references)}")
                    print(f"  • Description: {vuln.description}")
                    print(f"  • Rule: {vuln.rule_key}")
                    print()
                
                # Verify expected results
                found_cwes = set()
                found_owasps = set()
                for vuln in vulnerabilities:
                    found_cwes.update(vuln.cwe_references)
                    found_owasps.update(vuln.owasp_references)
                
                expected_cwes = set(test_case['expected_cwe'])
                expected_owasps = set(test_case['expected_owasp'])
                
                if expected_cwes.issubset(found_cwes) and expected_owasps.issubset(found_owasps):
                    print("✓ Expected vulnerabilities detected correctly")
                else:
                    print("⚠ Unexpected detection results")
                    print(f"  Expected CWEs: {expected_cwes}")
                    print(f"  Found CWEs: {found_cwes}")
                    print(f"  Expected OWASP: {expected_owasps}")
                    print(f"  Found OWASP: {found_owasps}")
            else:
                print("✓ No vulnerabilities found")
                if test_case['expected_cwe']:
                    print("⚠ Expected vulnerabilities but none found")
                else:
                    print("✓ Correctly identified as safe code")
            
        finally:
            # Clean up temporary file
            os.unlink(temp_file_path)
        
        print()
    
    # Generate summary report
    print("=" * 80)
    print("SUMMARY REPORT")
    print("=" * 80)
    
    total_tests = len(test_cases)
    total_vulnerabilities = sum(result['vulnerabilities_found'] for result in all_results)
    
    print(f"Total test cases: {total_tests}")
    print(f"Total vulnerabilities found: {total_vulnerabilities}")
    
    # Group by severity
    severity_counts = {}
    cwe_counts = {}
    owasp_counts = {}
    
    for result in all_results:
        for vuln in result['vulnerabilities']:
            severity = vuln.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            for cwe in vuln.get('cwe_references', []):
                cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
            
            for owasp in vuln.get('owasp_references', []):
                owasp_counts[owasp] = owasp_counts.get(owasp, 0) + 1
    
    print("\nSeverity Distribution:")
    for severity, count in sorted(severity_counts.items()):
        print(f"  {severity}: {count}")
    
    print("\nCWE Distribution:")
    for cwe, count in sorted(cwe_counts.items()):
        print(f"  CWE-{cwe}: {count}")
    
    print("\nOWASP Top 10 Distribution:")
    for owasp, count in sorted(owasp_counts.items()):
        print(f"  {owasp}: {count}")
    
    # Export detailed results
    output_file = "enhanced_scanner_demo_results.json"
    with open(output_file, 'w') as f:
        json.dump({
            "summary": {
                "total_tests": total_tests,
                "total_vulnerabilities": total_vulnerabilities,
                "severity_distribution": severity_counts,
                "cwe_distribution": cwe_counts,
                "owasp_distribution": owasp_counts
            },
            "test_results": all_results
        }, f, indent=2)
    
    print(f"\nDetailed results exported to: {output_file}")


def demo_security_standards():
    """Demonstrate security standards functionality"""
    
    print("\n" + "=" * 80)
    print("SECURITY STANDARDS DEMONSTRATION")
    print("=" * 80)
    
    # Show available security categories
    print("\nAvailable SonarQube Security Categories:")
    for category in SQCategory:
        print(f"  {category.key}: {category.vulnerability.name} probability")
    
    # Show vulnerability probabilities
    print("\nVulnerability Probability Levels:")
    for prob in VulnerabilityProbability:
        print(f"  {prob.name}: {prob.value}")
    
    # Demonstrate security standards creation
    print("\nCreating Security Standards for SQL Injection:")
    sql_standards = SecurityStandards.from_vulnerability_type("sql_injection", 0.9)
    standards_dict = sql_standards.to_dict()
    
    print(f"  Standards: {standards_dict['standards']}")
    print(f"  CWE: {standards_dict['cwe']}")
    print(f"  OWASP Top 10 2021: {standards_dict['owasp_top10_2021']}")
    print(f"  SQ Category: {standards_dict['sq_category']}")
    print(f"  Vulnerability Probability: {standards_dict['vulnerability_probability']}")
    print(f"  Confidence: {standards_dict['confidence']}")


def demo_sonarqube_export():
    """Demonstrate SonarQube export functionality"""
    
    print("\n" + "=" * 80)
    print("SONARQUBE EXPORT DEMONSTRATION")
    print("=" * 80)
    
    # Create a sample vulnerability for export
    detector = EnhancedSQLInjectionDetector()
    
    # Create temporary file with vulnerable code
    vulnerable_code = """
import sqlite3
from flask import request

def vulnerable_function():
    user_id = request.form['user_id']
    query = "SELECT * FROM users WHERE id = " + user_id
    
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
        temp_file.write(vulnerable_code)
        temp_file_path = temp_file.name
    
    try:
        # Scan the code
        vulnerabilities = detector.scan_file(temp_file_path)
        
        if vulnerabilities:
            # Export to SonarQube format
            output_file = "sonarqube_export_demo.json"
            detector.export_sonarqube_format(output_file)
            
            print(f"SonarQube export saved to: {output_file}")
            
            # Show the exported format
            with open(output_file, 'r') as f:
                export_data = json.load(f)
            
            print("\nSample SonarQube Issue Format:")
            if export_data.get('issues'):
                sample_issue = export_data['issues'][0]
                print(json.dumps(sample_issue, indent=2))
        else:
            print("No vulnerabilities found to export")
    
    finally:
        # Clean up temporary file
        os.unlink(temp_file_path)


def main():
    """Main demonstration function"""
    
    print("Starting Enhanced SQL Injection Detector Demonstration...")
    print("This demo showcases SonarQube-inspired security standards integration")
    print()
    
    try:
        # Run demonstrations
        demo_vulnerable_code_examples()
        demo_security_standards()
        demo_sonarqube_export()
        
        print("\n" + "=" * 80)
        print("DEMONSTRATION COMPLETED SUCCESSFULLY")
        print("=" * 80)
        print("\nKey Features Demonstrated:")
        print("✓ Enhanced vulnerability detection with confidence scoring")
        print("✓ SonarQube-style security categorization")
        print("✓ CWE and OWASP Top 10 compliance mapping")
        print("✓ Detailed remediation guidance")
        print("✓ SonarQube-compatible export format")
        print("✓ Comprehensive reporting with security standards")
        
    except Exception as e:
        print(f"Error during demonstration: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main() 