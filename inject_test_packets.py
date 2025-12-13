"""
Real-time test: Inject packets into CSV while everything is running
"""
import pandas as pd
from datetime import datetime
import os

DATA_PATH = 'data/captured_packets.csv'

# Create test packets that will trigger detection
# Using known malicious IPs from AbuseIPDB (high abuse scores)
now = datetime.now().isoformat()
test_packets = [
    # Known malicious IPs with high abuse scores (will be blocked)
    {'timestamp': now, 'src_ip': '185.220.101.1', 'dst_ip': '192.168.10.138', 'src_port': 12345, 'dst_port': 22, 'protocol': 'TCP', 'packet_length': 60},
    {'timestamp': now, 'src_ip': '185.220.101.1', 'dst_ip': '192.168.10.138', 'src_port': 12346, 'dst_port': 23, 'protocol': 'TCP', 'packet_length': 60},
    {'timestamp': now, 'src_ip': '185.220.101.2', 'dst_ip': '192.168.10.138', 'src_port': 54321, 'dst_port': 445, 'protocol': 'TCP', 'packet_length': 60},
]

print("="*70)
print("INJECTING TEST PACKETS INTO captured_packets.csv")
print("="*70)
print("\nMake sure realtime_detect.py is running!")
print("\nInjecting suspicious packets:")

df = pd.DataFrame(test_packets)
for idx, packet in enumerate(test_packets):
    print(f"  {idx+1}. {packet['src_ip']}:{packet['src_port']} -> {packet['dst_ip']}:{packet['dst_port']} ({packet['protocol']} {packet['packet_length']}B)")

# Append to CSV
df.to_csv(DATA_PATH, mode='a', header=False, index=False)

print("\n✓ Packets injected!")
print("\nWait 2-3 seconds, then check:")
print("  1. Terminal running realtime_detect.py (should show ALERT messages)")
print("  2. Dashboard at http://localhost:8501 (Recent Alerts section)")
print("  3. data/alerts.log file")
print("\n" + "="*70)
