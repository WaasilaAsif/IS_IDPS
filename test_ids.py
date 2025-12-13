"""
Test script to verify IDS is working correctly.
Generates real network connections to external IPs to trigger detection.
"""
import socket
import time
import random
import requests
from concurrent.futures import ThreadPoolExecutor

# Non-whitelisted IPs to test (public DNS/web servers)
TEST_IPS = [
    ("1.0.0.1", 80),      # Cloudflare DNS (but not in whitelist as /24)
    ("9.9.9.9", 53),      # Quad9 DNS (not whitelisted)
    ("208.67.222.222", 53),  # OpenDNS (not whitelisted)
]

def test_port_scan():
    """Simulate port scan by connecting to multiple ports"""
    print("\n[TEST 1] Simulating port scan (connecting to various ports)...")
    target_ip = "9.9.9.9"  # Quad9 DNS (not whitelisted)
    ports = [21, 22, 23, 25, 80, 443, 3389, 8080, 3306, 5432]
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect((target_ip, port))
            sock.close()
            print(f"  ✓ Connected to {target_ip}:{port}")
        except:
            print(f"  ✗ Attempted connection to {target_ip}:{port}")
        time.sleep(0.3)
    print("  ✓ Port scan test complete")

def test_dns_queries():
    """Simulate multiple DNS queries (UDP traffic)"""
    print("\n[TEST 2] Simulating DNS query flood...")
    domains = [
        "example.com", "test.com", "malicious-test.com", 
        "scan-test.net", "probe-test.org", "attack-sim.com",
        "ddos-test.io", "exploit-test.net", "vuln-scan.com"
    ]
    
    for domain in domains:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            # Send to non-whitelisted DNS server
            sock.sendto(b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00', ("9.9.9.9", 53))
            sock.close()
            print(f"  Sent DNS query for {domain}")
        except Exception as e:
            print(f"  ✗ DNS query failed: {e}")
        time.sleep(0.2)
    print("  ✓ DNS flood test complete")

def test_http_connections():
    """Simulate multiple HTTP connections"""
    print("\n[TEST 3] Simulating HTTP connection flood...")
    urls = [
        "http://1.0.0.1",
        "http://9.9.9.9", 
        "http://208.67.222.222",
    ]
    
    for url in urls * 3:  # Repeat 3 times
        try:
            requests.get(url, timeout=1)
            print(f"  ✓ HTTP request to {url}")
        except:
            print(f"  ✗ HTTP request attempted to {url}")
        time.sleep(0.2)
    print("  ✓ HTTP flood test complete")

def test_rapid_connections():
    """Simulate rapid connection attempts"""
    print("\n[TEST 4] Simulating rapid connection attempts...")
    
    def make_connection(target):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect(target)
            sock.close()
            return f"✓ Connected to {target}"
        except:
            return f"✗ Attempted {target}"
    
    targets = [("9.9.9.9", 53), ("208.67.222.222", 53), ("1.0.0.1", 80)] * 5
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(make_connection, targets)
        for result in results:
            print(f"  {result}")
            time.sleep(0.1)
    
    print("  ✓ Rapid connection test complete")

def main():
    print("="*60)
    print("IDS Testing Script")
    print("="*60)
    print("\nThis script will generate real network traffic to non-whitelisted IPs")
    print("to test your IDS detection capabilities.")
    print("\nTarget IPs (non-whitelisted):")
    print("  - 9.9.9.9 (Quad9 DNS)")
    print("  - 208.67.222.222 (OpenDNS)")
    print("  - 1.0.0.1 (Cloudflare)")
    print("\nMake sure the following are running:")
    print("  1. src/sniffer.py (capturing packets)")
    print("  2. src/realtime_detect.py (detecting threats)")
    print("  3. dashboard/app.py (viewing alerts)")
    print("\n" + "="*60)
    
    input("\nPress ENTER to start testing...")
    
    try:
        test_port_scan()
        time.sleep(3)
        
        test_dns_queries()
        time.sleep(3)
        
        test_http_connections()
        time.sleep(3)
        
        test_rapid_connections()
        
        print("\n" + "="*60)
        print("✓ All tests completed!")
        print("="*60)
        print("\nWait ~5 seconds, then check your dashboard at http://localhost:8501")
        print("You should see alerts for non-whitelisted IPs in 'Recent Alerts'.")
        print("\nNote: Detection depends on:")
        print("  - The model recognizing unusual traffic patterns")
        print("  - IPs not being in the whitelist")
        print("  - Sufficient traffic volume to trigger ML model")
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        print("\nMake sure:")
        print("  - You have internet connectivity")
        print("  - The sniffer is running")
        print("  - Firewall allows outbound connections")

if __name__ == "__main__":
    main()
