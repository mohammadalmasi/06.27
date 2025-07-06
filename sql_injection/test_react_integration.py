#!/usr/bin/env python3
"""
Test React Integration with Enhanced SonarQube API
This script tests the API endpoint that React will call to ensure it returns correct vulnerability counts.
"""

import requests
import json
import sys
import os

# Test code with SQL injection vulnerabilities
TEST_CODE = '''
import sqlite3
from flask import request

def vulnerable_login():
    username = request.form['username']
    password = request.form['password']
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()

def f_string_vulnerability():
    user_id = request.form['id']
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()

def format_vulnerability():
    name = request.form['name'] 
    query = "SELECT * FROM products WHERE name = '%s'" % name
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
'''

def test_api_login():
    """Test API login to get JWT token"""
    try:
        login_response = requests.post(
            'http://localhost:5001/api/login',
            json={
                'username': 'admin',
                'password': 'a'
            },
            timeout=10
        )
        
        if login_response.status_code == 200:
            data = login_response.json()
            return data.get('token')
        else:
            print(f"❌ Login failed: {login_response.text}")
            return None
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to Flask API. Make sure the server is running on http://localhost:5001")
        return None
    except Exception as e:
        print(f"❌ Login error: {e}")
        return None

def test_enhanced_scan_api(token):
    """Test the enhanced scan API that React calls"""
    try:
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}'
        }
        
        payload = {
            'scan_type': 'code',
            'code': TEST_CODE
        }
        
        print("🔍 Testing Enhanced API endpoint...")
        response = requests.post(
            'http://localhost:5001/api/enhanced-scan',
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            
            print("✅ Enhanced API Response:")
            print(f"   Total Issues: {data.get('total_issues', 0)}")
            print(f"   High Severity: {data.get('high_severity', 0)}")
            print(f"   Medium Severity: {data.get('medium_severity', 0)}")
            print(f"   Low Severity: {data.get('low_severity', 0)}")
            print()
            
            # Check if we got valid counts
            total = data.get('total_issues', 0)
            high = data.get('high_severity', 0)
            medium = data.get('medium_severity', 0)
            low = data.get('low_severity', 0)
            
            if total > 0:
                print("🎉 SUCCESS! React should now show vulnerability counts correctly!")
                print(f"   Expected in React UI:")
                print(f"   - Total Issues: {total}")
                print(f"   - High Severity: {high}")
                print(f"   - Medium Severity: {medium}")
                print(f"   - Low Severity: {low}")
                
                # Show summary structure too
                if 'summary' in data:
                    summary = data['summary']
                    print(f"   Summary also available:")
                    print(f"   - Critical: {summary.get('critical', 0)}")
                    print(f"   - High: {summary.get('high', 0)}")
                    print(f"   - Medium: {summary.get('medium', 0)}")
                    print(f"   - Low: {summary.get('low', 0)}")
                
                return True
            else:
                print("❌ API returned 0 vulnerabilities - something is still wrong!")
                print(f"Full response: {json.dumps(data, indent=2)}")
                return False
                
        else:
            print(f"❌ API Error ({response.status_code}): {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ API Test Error: {e}")
        return False

def main():
    print("🧪 Testing React Integration with Enhanced SonarQube API")
    print("=" * 60)
    
    # Step 1: Login to get token
    print("1. Testing API Login...")
    token = test_api_login()
    if not token:
        print("❌ Cannot proceed without authentication token")
        sys.exit(1)
    
    print("✅ Login successful!")
    print()
    
    # Step 2: Test enhanced scan API
    print("2. Testing Enhanced Scan API...")
    success = test_enhanced_scan_api(token)
    
    if success:
        print()
        print("✅ Integration Test PASSED!")
        print("🚀 Your React frontend should now show correct vulnerability counts!")
        print()
        print("📝 What was fixed:")
        print("   - React now calls /api/enhanced-scan instead of /api/scan")
        print("   - API payload changed from FormData to JSON")
        print("   - Response structure updated to include UI-compatible fields")
        print("   - Summary cards read from correct response fields")
        
    else:
        print()
        print("❌ Integration Test FAILED!")
        print("🔧 Check the API server and enhanced detector implementation")
    
    print()
    print("🔄 Next Steps:")
    print("   1. Make sure your React dev server is running")
    print("   2. Try scanning some vulnerable code in the React UI")
    print("   3. You should now see non-zero counts!")

if __name__ == "__main__":
    main() 