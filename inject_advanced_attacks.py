"""
Advanced Attack Simulations - Different attack types for comprehensive testing
Simulates: RDP brute force, database attacks, web admin exploitation, 
           port scanning, connection flooding, and data exfiltration
"""
import pandas as pd
from datetime import datetime
import os

DATA_PATH = 'data/captured_packets.csv'

print("=" * 70)
print("ADVANCED ATTACK SIMULATION SUITE")
print("=" * 70)
print("\nMake sure realtime_detect.py is running!")
print("\nSimulating 6 different attack scenarios:\n")

now = datetime.now().isoformat()

# Attack 1: RDP Brute Force Attack (Port 3389)
# Simulates repeated login attempts to Remote Desktop Protocol
print("1. 🔴 RDP BRUTE FORCE ATTACK (Port 3389)")
print("   Type: Remote Desktop credential stuffing")
print("   Pattern: Multiple connection attempts, small packets")
print("   Real-world: Ransomware groups often exploit RDP vulnerabilities")
rdp_attacks = []
for i in range(5):
    rdp_attacks.append({
        'timestamp': now,
        'src_ip': '45.142.214.123',  # Known malicious IP range
        'dst_ip': '192.168.10.138',
        'src_port': 50000 + i,
        'dst_port': 3389,
        'protocol': 'TCP',
        'packet_length': 54,
        'fwd_bytes': 54,
        'bwd_bytes': 0
    })

# Attack 2: MySQL Database Exploitation (Port 3306)
# Simulates SQL injection or database breach attempt
print("\n2. 🔴 MYSQL DATABASE ATTACK (Port 3306)")
print("   Type: SQL injection / unauthorized database access")
print("   Pattern: Multiple queries with varying packet sizes")
print("   Real-world: Data breach attempts, credential harvesting")
mysql_attacks = [
    {'timestamp': now, 'src_ip': '103.85.24.155', 'dst_ip': '192.168.10.138', 'src_port': 41234, 'dst_port': 3306, 'protocol': 'TCP', 'packet_length': 78, 'fwd_bytes': 78, 'bwd_bytes': 0},
    {'timestamp': now, 'src_ip': '103.85.24.155', 'dst_ip': '192.168.10.138', 'src_port': 41235, 'dst_port': 3306, 'protocol': 'TCP', 'packet_length': 120, 'fwd_bytes': 120, 'bwd_bytes': 0},
    {'timestamp': now, 'src_ip': '103.85.24.155', 'dst_ip': '192.168.10.138', 'src_port': 41236, 'dst_port': 3306, 'protocol': 'TCP', 'packet_length': 95, 'fwd_bytes': 95, 'bwd_bytes': 0},
]

# Attack 3: MongoDB NoSQL Injection (Port 27017)
# Simulates NoSQL database exploitation
print("\n3. 🔴 MONGODB NOSQL INJECTION (Port 27017)")
print("   Type: NoSQL injection attack")
print("   Pattern: Large payload packets attempting code injection")
print("   Real-world: Modern database attacks targeting MongoDB instances")
mongodb_attacks = [
    {'timestamp': now, 'src_ip': '217.12.204.100', 'dst_ip': '192.168.10.138', 'src_port': 33221, 'dst_port': 27017, 'protocol': 'TCP', 'packet_length': 250, 'fwd_bytes': 250, 'bwd_bytes': 0},
    {'timestamp': now, 'src_ip': '217.12.204.100', 'dst_ip': '192.168.10.138', 'src_port': 33222, 'dst_port': 27017, 'protocol': 'TCP', 'packet_length': 310, 'fwd_bytes': 310, 'bwd_bytes': 0},
]

# Attack 4: Web Admin Panel Brute Force (Port 8080)
# Simulates attack on web application admin interface
print("\n4. 🔴 WEB ADMIN PANEL BRUTE FORCE (Port 8080)")
print("   Type: Admin panel credential brute force")
print("   Pattern: Repeated POST requests with authentication attempts")
print("   Real-world: Compromising web application admin panels")
web_admin_attacks = []
for i in range(8):
    web_admin_attacks.append({
        'timestamp': now,
        'src_ip': '91.201.67.89',
        'dst_ip': '192.168.10.138',
        'src_port': 44000 + i,
        'dst_port': 8080,
        'protocol': 'TCP',
        'packet_length': 85 + (i * 5),
        'fwd_bytes': 85 + (i * 5),
        'bwd_bytes': 0
    })

# Attack 5: Port Scanning (Multiple Ports)
# Simulates reconnaissance phase - attacker probing for open services
print("\n5. 🔴 PORT SCANNING RECONNAISSANCE (Multiple Ports)")
print("   Type: Network reconnaissance / service discovery")
print("   Pattern: Single IP probing 15+ unique ports")
print("   Real-world: Nmap scan, automated vulnerability scanning")
target_ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8888, 9200]
port_scan_attacks = []
for port in target_ports:
    port_scan_attacks.append({
        'timestamp': now,
        'src_ip': '159.89.133.22',  # Attacker scanning from single IP
        'dst_ip': '192.168.10.138',
        'src_port': 55000 + port,
        'dst_port': port,
        'protocol': 'TCP',
        'packet_length': 60,
        'fwd_bytes': 60,
        'bwd_bytes': 0
    })

# Attack 6: PostgreSQL Database Breach Attempt (Port 5432)
# Simulates credential stuffing on PostgreSQL
print("\n6. 🔴 POSTGRESQL DATABASE BREACH (Port 5432)")
print("   Type: Database credential stuffing")
print("   Pattern: Multiple authentication attempts")
print("   Real-world: Targeting exposed PostgreSQL instances")
postgres_attacks = [
    {'timestamp': now, 'src_ip': '188.166.123.45', 'dst_ip': '192.168.10.138', 'src_port': 52001, 'dst_port': 5432, 'protocol': 'TCP', 'packet_length': 92, 'fwd_bytes': 92, 'bwd_bytes': 0},
    {'timestamp': now, 'src_ip': '188.166.123.45', 'dst_ip': '192.168.10.138', 'src_port': 52002, 'dst_port': 5432, 'protocol': 'TCP', 'packet_length': 88, 'fwd_bytes': 88, 'bwd_bytes': 0},
    {'timestamp': now, 'src_ip': '188.166.123.45', 'dst_ip': '192.168.10.138', 'src_port': 52003, 'dst_port': 5432, 'protocol': 'TCP', 'packet_length': 95, 'fwd_bytes': 95, 'bwd_bytes': 0},
]

# Combine all attacks
all_attacks = (
    rdp_attacks + 
    mysql_attacks + 
    mongodb_attacks + 
    web_admin_attacks + 
    port_scan_attacks + 
    postgres_attacks
)

print("\n" + "=" * 70)
print(f"TOTAL ATTACK PACKETS: {len(all_attacks)}")
print("=" * 70)

# Detailed breakdown
print("\nAttack Breakdown:")
print(f"  • RDP Brute Force (3389):     {len(rdp_attacks)} packets")
print(f"  • MySQL Attacks (3306):       {len(mysql_attacks)} packets")
print(f"  • MongoDB Injection (27017):  {len(mongodb_attacks)} packets")
print(f"  • Web Admin Brute (8080):     {len(web_admin_attacks)} packets")
print(f"  • Port Scanning (multi):      {len(port_scan_attacks)} packets")
print(f"  • PostgreSQL Breach (5432):   {len(postgres_attacks)} packets")

# Inject into CSV
df = pd.DataFrame(all_attacks)
df.to_csv(DATA_PATH, mode='a', header=False, index=False)

print("\n✅ All attack packets injected into captured_packets.csv")
print("\n" + "=" * 70)
print("EXPECTED DETECTION RESULTS:")
print("=" * 70)
print("• All packets should trigger 90%+ ML confidence (attack ports)")
print("• Port scanning: BEHAVIORAL ALERT (>10 unique ports from 159.89.133.22)")
print("• Connection flooding: May trigger if total connections >50")
print("• IPs should be AUTO-BLOCKED via Mode 3 (95%+ confidence on attack ports)")
print("\nMonitor these sources:")
print("  1. Terminal running realtime_detect.py (live alerts)")
print("  2. Dashboard: http://localhost:8501 (Recent Alerts + Blocked IPs)")
print("  3. data/alerts.log (detailed logging)")
print("\n" + "=" * 70)
