import pandas as pd
import joblib
import os
from time import sleep
from sklearn.preprocessing import LabelEncoder
import subprocess
import sys
import ipaddress

sys.path.append(os.path.join(os.path.dirname(__file__)))
from threat_intel import check_ip_abuse

DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'captured_packets.csv')
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'rf_model.joblib')
PROTO_ENCODER_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'proto_encoder.joblib')
LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'alerts.log')

ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')

clf = joblib.load(MODEL_PATH)
le_proto = joblib.load(PROTO_ENCODER_PATH)

blocked_ips = set()
alert_counter = {}  # Track alerts per IP for rate limiting
connection_tracker = {}  # Track connections per IP for behavioral detection
port_scan_tracker = {}  # Track unique ports per IP

# Whitelist: Trusted IP ranges and services (narrowed to specific legitimate services only)
WHITELIST_RANGES = [
    # Google - Core services and DNS only (not entire Google Cloud)
    '142.250.0.0/15',      # Google services (Search, YouTube, Gmail)
    '172.217.0.0/16',      # Google services
    '216.58.192.0/19',     # Google services
    '8.8.8.0/24',          # Google Public DNS
    '8.8.4.0/24',          # Google Public DNS secondary
    '108.177.0.0/16',      # Google CDN
    
    # Facebook/Meta - Social media endpoints only
    '157.240.0.0/16',      # Facebook CDN
    '31.13.0.0/16',        # Facebook core
    '69.63.0.0/16',        # Facebook infrastructure
    '66.220.0.0/16',       # Facebook services
    '173.252.0.0/16',      # Facebook/Instagram
    
    # Microsoft - Only core services (Office 365, consumer services, not Azure VMs)
    '13.107.0.0/16',       # Microsoft 365
    '40.96.0.0/13',        # Outlook.com
    '40.104.0.0/15',       # Microsoft services
    '52.96.0.0/14',        # Office 365
    '104.40.0.0/13',       # Microsoft CDN
    '137.116.0.0/16',      # Microsoft core
    '168.61.0.0/16',       # Microsoft services
    '199.30.16.0/20',      # Microsoft edge
    
    # GitHub - Code hosting only
    '140.82.0.0/16',       # GitHub core
    '185.199.0.0/16',      # GitHub Pages
    '192.30.252.0/22',     # GitHub API
    
    # Cloudflare - CDN and DNS only
    '104.16.0.0/13',       # Cloudflare CDN (narrowed from /12)
    '172.64.0.0/13',       # Cloudflare CDN
    '1.1.1.0/24',          # Cloudflare DNS
    '1.0.0.0/24',          # Cloudflare DNS secondary
    
    # Akamai CDN - Legitimate CDN ranges only
    '104.64.0.0/11',       # Akamai CDN (narrowed from /10)
    '23.0.0.0/12',         # Akamai edge servers (narrowed from /8)
    
    # Fastly CDN - Reddit, StackOverflow, etc.
    '151.101.0.0/16',      # Fastly CDN
    '146.75.0.0/16',       # Fastly (Reddit)
    '199.232.0.0/16',      # Fastly edge
    
    # Public DNS Servers - Only actual DNS IPs
    '9.9.9.9/32',          # Quad9 DNS primary
    '9.9.9.10/32',         # Quad9 DNS secondary
    '208.67.222.222/32',   # OpenDNS primary
    '208.67.220.220/32',   # OpenDNS secondary
    
    # Private networks (local/internal only)
    '192.168.0.0/16',      # Private network class C
    '10.0.0.0/8',          # Private network class A
    '172.16.0.0/12',       # Private network class B
]

def is_whitelisted(ip):
    """Check if an IP address is in the whitelist"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for range_str in WHITELIST_RANGES:
            if ip_obj in ipaddress.ip_network(range_str):
                return True
    except ValueError:
        pass
    return False

# Map protocol string to NSL-KDD protocol_type
PROTOCOL_MAP = {'TCP': 'tcp', 'UDP': 'udp', 'ICMP': 'icmp'}

def preprocess_row(row):
    # Map protocol to protocol_type string
    proto_type = PROTOCOL_MAP.get(str(row['protocol']).upper(), 'other')
    protocol_type_encoded = le_proto.transform([proto_type])[0] if proto_type in le_proto.classes_ else 0
    
    # Use actual flow bytes if available (CICIDS2017 format)
    src_bytes = int(row.get('fwd_bytes', row.get('packet_length', 0))) if pd.notnull(row.get('fwd_bytes', row.get('packet_length', 0))) else 0
    dst_bytes = int(row.get('bwd_bytes', 0)) if pd.notnull(row.get('bwd_bytes', 0)) else 0
    
    # Return a dict with all needed values
    return pd.Series({
        **row.to_dict(),
        'protocol_type': protocol_type_encoded,
        'src_bytes': src_bytes,
        'dst_bytes': dst_bytes
    })

def block_ip(ip):
    if ip in blocked_ips:
        return
    try:
        cmd = f'netsh advfirewall firewall add rule name="IDS_Block_{ip}" dir=in action=block remoteip={ip} enable=yes'
        subprocess.run(cmd, shell=True, check=True)
        blocked_ips.add(ip)
        with open(LOG_PATH, 'a') as f:
            f.write(f"AUTO-BLOCKED IP: {ip}\n")
        print(f"AUTO-BLOCKED IP: {ip}")
    except Exception as e:
        with open(LOG_PATH, 'a') as f:
            f.write(f"Failed to block IP {ip}: {e}\n")
        print(f"Failed to block IP {ip}: {e}")

def main():
    print('Starting real-time detection with threat intelligence and auto-blocking...')
    
    # Start from the current end of the file to avoid processing old data
    if os.path.exists(DATA_PATH):
        df = pd.read_csv(DATA_PATH)
        last_seen = len(df)
        print(f'Skipping {last_seen} existing packets, monitoring for new traffic...')
    else:
        last_seen = 0
    
    while True:
        if not os.path.exists(DATA_PATH):
            sleep(2)
            continue
        df = pd.read_csv(DATA_PATH)
        if len(df) == 0 or last_seen >= len(df):
            sleep(2)
            continue
        
        new_rows = df.iloc[last_seen:]
        print(f'Processing {len(new_rows)} new packets...')
        new_rows = new_rows.apply(preprocess_row, axis=1)
        
        # Behavioral detection
        for idx, row in new_rows.iterrows():
            src_ip = row.get('src_ip')
            dst_port = row.get('dst_port', 0)
            src_bytes = row.get('src_bytes', 0)
            dst_bytes = row.get('dst_bytes', 0)
            
            if src_ip and not is_whitelisted(src_ip):
                # Track connections per IP
                if src_ip not in connection_tracker:
                    connection_tracker[src_ip] = {'count': 0, 'ports': set(), 'total_bytes': 0}
                connection_tracker[src_ip]['count'] += 1
                connection_tracker[src_ip]['total_bytes'] += (src_bytes + dst_bytes)
                if dst_port:
                    connection_tracker[src_ip]['ports'].add(dst_port)
        
        # Define suspicious ports (attack-prone services)
        ATTACK_PORTS = {22, 23, 445, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 8080, 8888}
        
        # HTTP/HTTPS ports for behavioral analysis
        WEB_PORTS = {80, 443}
        
        # Safe ports (DNS, email, etc.) - skip ML entirely
        SAFE_PORTS = {53, 853, 5353, 123, 443, 80, 993, 995, 587, 465, 110, 143, 5222, 8443}
        
        # Only run ML on suspicious traffic
        suspicious_indices = []
        for idx, row in new_rows.iterrows():
            src_ip = row.get('src_ip')
            src_port = row.get('src_port', 0)
            dst_port = row.get('dst_port', 0)
            protocol = row.get('protocol', '')
            src_bytes = row.get('src_bytes', 0)
            dst_bytes = row.get('dst_bytes', 0)
            
            # Skip whitelisted IPs
            if is_whitelisted(src_ip):
                continue
            
            # Skip safe services (DNS, NTP, mail servers) - check both src and dst ports
            if src_port in SAFE_PORTS or dst_port in SAFE_PORTS:
                continue
            
            # Behavioral anomalies (port scanning, connection flooding)
            if src_ip in connection_tracker:
                conn_data = connection_tracker[src_ip]
                
                # Port scan detection: >10 unique ports in short time
                if len(conn_data['ports']) > 10:
                    alert = f"ALERT: Port scan detected from {src_ip} - {len(conn_data['ports'])} unique ports"
                    print(alert)
                    with open(LOG_PATH, 'a') as f:
                        f.write(alert + '\n')
                    alert_counter[src_ip] = alert_counter.get(src_ip, 0) + 1
                    suspicious_indices.append(idx)
                    continue
                
                # Connection flood: >50 connections
                if conn_data['count'] > 50:
                    alert = f"ALERT: Connection flood from {src_ip} - {conn_data['count']} connections"
                    print(alert)
                    with open(LOG_PATH, 'a') as f:
                        f.write(alert + '\n')
                    alert_counter[src_ip] = alert_counter.get(src_ip, 0) + 1
                    suspicious_indices.append(idx)
                    continue
                
                # Unusual HTTP/HTTPS: Very large data exfiltration (>100MB)
                if dst_port in WEB_PORTS and conn_data['total_bytes'] > 100_000_000:
                    alert = f"ALERT: Large data transfer from {src_ip} via port {dst_port} - {conn_data['total_bytes']:,} bytes"
                    print(alert)
                    with open(LOG_PATH, 'a') as f:
                        f.write(alert + '\n')
                    alert_counter[src_ip] = alert_counter.get(src_ip, 0) + 1
                    suspicious_indices.append(idx)
                    continue
            
            # HTTP/HTTPS behavioral anomalies: tiny repeated packets (DDoS pattern)
            if dst_port in WEB_PORTS:
                if src_bytes < 100 and dst_bytes < 100:
                    # Count tiny packets from this IP
                    if src_ip not in connection_tracker:
                        connection_tracker[src_ip] = {'tiny_packets': 0}
                    if 'tiny_packets' not in connection_tracker[src_ip]:
                        connection_tracker[src_ip]['tiny_packets'] = 0
                    connection_tracker[src_ip]['tiny_packets'] += 1
                    
                    # Alert on >20 tiny packets (possible DDoS/keepalive flood)
                    if connection_tracker[src_ip]['tiny_packets'] > 20:
                        alert = f"ALERT: Suspicious tiny packet flood from {src_ip} on port {dst_port} - {connection_tracker[src_ip]['tiny_packets']} packets"
                        print(alert)
                        with open(LOG_PATH, 'a') as f:
                            f.write(alert + '\n')
                        alert_counter[src_ip] = alert_counter.get(src_ip, 0) + 1
                        connection_tracker[src_ip]['tiny_packets'] = 0  # Reset
                        continue
                
                # Skip normal HTTP/HTTPS from ML
                continue
            
            # Only use ML for attack-prone ports or unusual protocols
            if dst_port in ATTACK_PORTS or protocol not in ['TCP', 'UDP']:
                suspicious_indices.append(idx)
        
        # If no suspicious traffic, continue
        if not suspicious_indices:
            last_seen = len(df)
            sleep(2)
            continue
        
        # Run ML only on suspicious packets
        suspicious_rows = new_rows.loc[suspicious_indices]
        X = suspicious_rows[['protocol_type', 'src_bytes', 'dst_bytes']]
        preds = clf.predict(X)
        probs = clf.predict_proba(X)
        
        for i, (idx, row) in enumerate(suspicious_rows.iterrows()):
            pred = preds[i]
            if pred != 0:
                src_ip = row['src_ip']
                confidence = probs[i][pred]
                
                # High confidence threshold for ML-only detection
                if confidence < 0.90:
                    continue
                
                alert = f"ALERT: Suspicious activity detected (confidence: {confidence:.1%}): {row.to_dict()} | Predicted label: {pred}"
                print(alert)
                with open(LOG_PATH, 'a') as f:
                    f.write(alert + '\n')
                
                # Track alerts per IP for rate limiting
                alert_counter[src_ip] = alert_counter.get(src_ip, 0) + 1
                
                # Threat intelligence check (skip if rate limited)
                should_block = False
                block_reason = ""
                score = 0
                
                if ABUSEIPDB_API_KEY:
                    try:
                        abuse_result = check_ip_abuse(src_ip, ABUSEIPDB_API_KEY)
                        if 'error' not in abuse_result:
                            with open(LOG_PATH, 'a') as f:
                                f.write(f"AbuseIPDB: {abuse_result}\n")
                            print(f"AbuseIPDB: {abuse_result}")
                            score = abuse_result.get('abuseConfidenceScore', 0)
                        else:
                            # Rate limited or error
                            print(f"AbuseIPDB unavailable: {abuse_result.get('error', 'Unknown error')}")
                    except Exception as e:
                        print(f"AbuseIPDB error: {e}")
                
                # BLOCKING LOGIC
                # Option 1: High AbuseIPDB score
                if score >= 50:
                    should_block = True
                    block_reason = f"High abuse score: {score}"
                # Option 2: Medium score + multiple alerts
                elif score >= 25 and alert_counter[src_ip] >= 2:
                    should_block = True
                    block_reason = f"Medium abuse score ({score}) + {alert_counter[src_ip]} alerts"
                # Option 3: ML-only blocking (very high confidence + attack-prone port)
                elif confidence >= 0.95 and row.get('dst_port', 0) in ATTACK_PORTS:
                    should_block = True
                    block_reason = f"ML high confidence ({confidence:.1%}) on dangerous port {row.get('dst_port', 0)}"
                # Option 4: Rate limiting (many alerts, low/no score)
                elif alert_counter[src_ip] >= 5:
                    should_block = True
                    block_reason = f"Rate limit exceeded: {alert_counter[src_ip]} alerts, score: {score}"
                
                if should_block:
                    block_ip(src_ip)
                    msg = f"AUTO-BLOCKED: {src_ip} - Reason: {block_reason}"
                    print(msg)
                    with open(LOG_PATH, 'a') as f:
                        f.write(msg + '\n')
        
        last_seen = len(df)
        sleep(2)

if __name__ == '__main__':
    main() 