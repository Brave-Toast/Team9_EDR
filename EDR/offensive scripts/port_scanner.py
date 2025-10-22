#!/usr/bin/env python3
"""
Simple Port Scanner

A simple multi-threaded port scanner to check for open ports on a target IP.
Can scan a single port or a list of common ports.

For educational purposes only.
"""

import socket
import threading
import time

def scan_port(target_ip, port, results, timeout=3):
    """
    Tries to connect to a specific port and updates the results dictionary.
    This function is designed to be run in a thread.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                results[port] = "OPEN"
                print(f"Port {port}: OPEN")
            else:
                results[port] = "CLOSED"
    except socket.error:
        results[port] = "ERROR"

def scan_single_port(target_ip, port):
    """Scans a single port and prints the result."""
    print(f"Scanning {target_ip}:{port}...\n")
    results = {}
    scan_port(target_ip, port, results)
    
    if results.get(port) == "OPEN":
        print(f"\nSUCCESS: Port {port} is open on {target_ip}")
    else:
        print(f"\nPort {port} is closed or filtered on {target_ip}")

def scan_common_ports(target_ip):
    """Scans a list of common ports using multiple threads."""
    common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 3000, 8080]
    print(f"Scanning common ports on {target_ip}...\n")
    
    results = {}
    threads = []
    
    for port in common_ports:
        thread = threading.Thread(target=scan_port, args=(target_ip, port, results))
        threads.append(thread)
        thread.start()
        time.sleep(0.05) # A small delay to avoid overwhelming the network
    
    for thread in threads:
        thread.join()
        
    print("\n=== Scan Results ===")
    open_ports = sorted([port for port, status in results.items() if status == "OPEN"])
    
    if open_ports:
        print(f"Found {len(open_ports)} open ports:")
        for port in open_ports:
            print(f"  Port {port}: OPEN")
    else:
        print("No open ports found among the common ports.")

def main():
    """
    Main function to parse user input and initiate the port scan.
    """
    print("Simple Port Scanner")
    print("Educational use only!\n")
    
    target_input = input("Enter IP and port (e.g., 192.168.86.130:3000) or just an IP: ")
    
    try:
        if ":" in target_input:
            target_ip, port_str = target_input.split(":", 1)
            port = int(port_str)
            scan_single_port(target_ip, port)
        else:
            target_ip = target_input
            scan_common_ports(target_ip)
            
    except ValueError:
        print("Invalid port number. Please enter a number between 1 and 65535.")
    except OSError as e:
        print(f"An error occurred: {e}")
    
    print("\nScan finished.")

if __name__ == "__main__":
    main()
