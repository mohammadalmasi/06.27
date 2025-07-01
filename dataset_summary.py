#!/usr/bin/env python3
"""
SQL Injection Dataset Summary
Generates statistics and summary information about the SQL injection vulnerable code dataset.
"""

import json
import os
from collections import Counter

def load_dataset():
    """Load the main JSON dataset."""
    try:
        with open('sql_injection_dataset.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("Error: sql_injection_dataset.json not found!")
        return None

def analyze_dataset(dataset):
    """Analyze the dataset and generate statistics."""
    if not dataset:
        return
    
    print("=" * 60)
    print("SQL INJECTION VULNERABLE CODE DATASET SUMMARY")
    print("=" * 60)
    
    # Basic statistics
    total_examples = dataset['metadata']['total_examples']
    categories = dataset['metadata']['categories']
    
    print(f"\n📊 BASIC STATISTICS:")
    print(f"   Total Examples: {total_examples}")
    print(f"   Categories: {len(categories)}")
    print(f"   Payload Types: {len(dataset['payloads'])}")
    print(f"   Mitigation Strategies: {len(dataset['mitigation_strategies'])}")
    
    # Analyze examples by category
    print(f"\n📁 EXAMPLES BY CATEGORY:")
    category_counts = Counter()
    language_counts = Counter()
    severity_counts = Counter()
    
    for example in dataset['examples']:
        category_counts[example['category']] += 1
        language_counts[example['language']] += 1
        severity_counts[example['severity']] += 1
    
    for category, count in category_counts.most_common():
        print(f"   {category}: {count} examples")
    
    # Analyze by language
    print(f"\n💻 EXAMPLES BY LANGUAGE:")
    for language, count in language_counts.most_common():
        print(f"   {language}: {count} examples")
    
    # Analyze by severity
    print(f"\n⚠️  EXAMPLES BY SEVERITY:")
    for severity, count in severity_counts.most_common():
        print(f"   {severity}: {count} examples")
    
    # Payload statistics
    print(f"\n🎯 PAYLOAD STATISTICS:")
    for payload_type, payloads in dataset['payloads'].items():
        print(f"   {payload_type}: {len(payloads)} payloads")
    
    # Show some example payloads
    print(f"\n🔍 SAMPLE PAYLOADS:")
    for payload_type, payloads in dataset['payloads'].items():
        print(f"   {payload_type.upper()}:")
        for i, payload in enumerate(payloads[:3]):  # Show first 3
            print(f"     {i+1}. {payload}")
        if len(payloads) > 3:
            print(f"     ... and {len(payloads) - 3} more")
        print()

def analyze_code_files():
    """Analyze the vulnerable code files in the directory structure."""
    print("=" * 60)
    print("VULNERABLE CODE FILES ANALYSIS")
    print("=" * 60)
    
    vulnerable_dir = "vulnerable_code_examples"
    if not os.path.exists(vulnerable_dir):
        print(f"   Directory '{vulnerable_dir}' not found!")
        return
    
    language_stats = {}
    total_files = 0
    
    for language_dir in os.listdir(vulnerable_dir):
        lang_path = os.path.join(vulnerable_dir, language_dir)
        if os.path.isdir(lang_path):
            files = [f for f in os.listdir(lang_path) if f.endswith(('.py', '.php', '.java', '.js', '.cs'))]
            language_stats[language_dir] = len(files)
            total_files += len(files)
    
    print(f"\n📁 CODE FILES BY LANGUAGE:")
    for language, count in language_stats.items():
        print(f"   {language}: {count} files")
    
    print(f"\n   Total Code Files: {total_files}")

def show_mitigation_strategies(dataset):
    """Display the mitigation strategies."""
    print("=" * 60)
    print("MITIGATION STRATEGIES")
    print("=" * 60)
    
    print(f"\n🛡️  RECOMMENDED MITIGATION STRATEGIES:")
    for i, strategy in enumerate(dataset['mitigation_strategies'], 1):
        print(f"   {i:2d}. {strategy}")

def show_sample_examples(dataset):
    """Show sample examples from the dataset."""
    print("=" * 60)
    print("SAMPLE VULNERABILITY EXAMPLES")
    print("=" * 60)
    
    print(f"\n🔍 SAMPLE EXAMPLES:")
    for i, example in enumerate(dataset['examples'][:5], 1):  # Show first 5
        print(f"\n   Example {i}:")
        print(f"     Category: {example['category']}")
        print(f"     Language: {example['language']}")
        print(f"     Type: {example['vulnerability_type']}")
        print(f"     Severity: {example['severity']}")
        print(f"     Code: {example['code']}")
        print(f"     Payload: {example['payload']}")
        print(f"     Description: {example['description']}")

def generate_usage_example():
    """Generate a usage example for the dataset."""
    print("=" * 60)
    print("USAGE EXAMPLE")
    print("=" * 60)
    
    usage_code = '''
# Example: Using the SQL Injection Dataset

import json

# Load the dataset
with open('sql_injection_dataset.json', 'r') as f:
    dataset = json.load(f)

# Find all critical vulnerabilities
critical_vulns = [ex for ex in dataset['examples'] if ex['severity'] == 'Critical']
print(f"Found {len(critical_vulns)} critical vulnerabilities")

# Get all Python examples
python_examples = [ex for ex in dataset['examples'] if 'Python' in ex['language']]
print(f"Found {len(python_examples)} Python examples")

# Get authentication bypass payloads
auth_payloads = dataset['payloads']['authentication_bypass']
print(f"Found {len(auth_payloads)} authentication bypass payloads")

# Test a vulnerable function (example)
def test_vulnerable_login(username, password):
    # This is a simplified example - in real testing you'd use the actual vulnerable code
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"Generated query: {query}")
    return "Vulnerable query executed"

# Test with a payload
payload = dataset['payloads']['authentication_bypass'][0]
result = test_vulnerable_login(payload, "password")
print(f"Test result: {result}")
'''
    
    print(usage_code)

def main():
    """Main function to run the dataset analysis."""
    print("🔍 Analyzing SQL Injection Vulnerable Code Dataset...")
    
    # Load and analyze the main dataset
    dataset = load_dataset()
    if dataset:
        analyze_dataset(dataset)
        show_mitigation_strategies(dataset)
        show_sample_examples(dataset)
    
    # Analyze code files
    analyze_code_files()
    
    # Show usage example
    generate_usage_example()
    
    print("\n" + "=" * 60)
    print("✅ DATASET ANALYSIS COMPLETE")
    print("=" * 60)
    print("\n📚 This dataset contains intentionally vulnerable code for educational purposes.")
    print("⚠️  NEVER use this code in production environments!")
    print("🎯 Use this dataset for security research, testing, and education.")

if __name__ == "__main__":
    main() 