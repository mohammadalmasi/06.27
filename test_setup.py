#!/usr/bin/env python3
"""
Test script to verify the SQL injection scanner setup
"""

import requests
import json
import time

def test_backend_api():
    """Test the backend API endpoint"""
    url = "http://localhost:5001/api/scan"
    
    # Test vulnerable code
    test_code = '''
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchall()
'''
    
    try:
        print("Testing backend API...")
        response = requests.post(
            url,
            data={'code': test_code},
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Backend API is working!")
            print(f"Found {result['summary']['total_vulnerabilities']} vulnerabilities")
            
            if result['vulnerabilities']:
                print("\nVulnerabilities found:")
                for vuln in result['vulnerabilities']:
                    print(f"- Line {vuln['line_number']}: {vuln['description']}")
                    print(f"  Severity: {vuln['severity']}")
                    print(f"  Confidence: {vuln['confidence']}")
            
            return True
        else:
            print(f"❌ Backend API error: {response.status_code}")
            print(response.text)
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to backend. Make sure Flask server is running on port 5001")
        return False
    except Exception as e:
        print(f"❌ Error testing backend: {e}")
        return False

def test_frontend():
    """Test if the frontend is accessible"""
    try:
        print("\nTesting frontend...")
        response = requests.get("http://localhost:3000", timeout=5)
        
        if response.status_code == 200:
            print("✅ Frontend is accessible!")
            return True
        else:
            print(f"❌ Frontend error: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to frontend. Make sure React server is running on port 3000")
        return False
    except Exception as e:
        print(f"❌ Error testing frontend: {e}")
        return False

def main():
    print("🔍 SQL Injection Scanner Setup Test")
    print("=" * 40)
    
    backend_ok = test_backend_api()
    frontend_ok = test_frontend()
    
    print("\n" + "=" * 40)
    if backend_ok and frontend_ok:
        print("🎉 Setup complete! Both frontend and backend are working.")
        print("\n📋 Next steps:")
        print("1. Open http://localhost:3000 in your browser")
        print("2. Try scanning some code for SQL injection vulnerabilities")
        print("3. Test different input methods (URL, file upload, paste code)")
    else:
        print("⚠️  Setup incomplete. Please check the error messages above.")
        print("\n🔧 Troubleshooting:")
        if not backend_ok:
            print("- Make sure Flask backend is running: cd sql_injection && python app.py")
        if not frontend_ok:
            print("- Make sure React frontend is running: cd frontend && npm start")

if __name__ == "__main__":
    main() 