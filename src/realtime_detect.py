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

# Whitelist: Trusted IP ranges and services
WHITELIST_RANGES = [
    # Google
    '142.250.0.0/15',
    '172.217.0.0/16',
    '216.58.192.0/19',
    '8.8.8.0/24',          # Google DNS
    '8.8.4.0/24',          # Google DNS
    '108.177.0.0/16',      # Google services
    
    # Microsoft/Azure
    '4.0.0.0/8',
    '13.0.0.0/8',
    '20.0.0.0/8',
    '23.0.0.0/8',
    '40.0.0.0/8',
    '51.0.0.0/8',          # Azure EU
    '52.0.0.0/8',
    '104.40.0.0/13',
    '137.116.0.0/16',
    '168.61.0.0/16',
    '191.232.0.0/13',
    '199.30.16.0/20',
    
    # GitHub
    '140.82.0.0/16',
    '185.199.0.0/16',
    '192.30.252.0/22',
    
    # Cloudflare
    '104.16.0.0/12',
    '172.64.0.0/13',
    '1.1.1.0/24',
    '1.0.0.0/24',
    
    # Amazon AWS
    '3.0.0.0/8',
    '15.0.0.0/8',
    '18.0.0.0/8',
    '35.0.0.0/8',
    '54.0.0.0/8',
    
    # Akamai CDN
    '96.0.0.0/9',
    '104.64.0.0/10',
    
    # Fastly CDN
    '151.101.0.0/16',
    '199.232.0.0/16',
    
    # Common DNS Servers
    '9.9.9.0/24',          # Quad9 DNS
    '208.67.220.0/22',     # OpenDNS
    '101.0.0.0/8',         # Asia Pacific DNS providers
    '103.0.0.0/8',         # Asia Pacific providers
    '57.0.0.0/8',          # Apple/telecom services
    
    # Private networks (local)
    '192.168.0.0/16',
    '10.0.0.0/8',
    '172.16.0.0/12',
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
    # Use src_bytes and dst_bytes as packet_length (approximation)
    src_bytes = int(row['packet_length']) if pd.notnull(row['packet_length']) else 0
    dst_bytes = 0  # Real-time, we don't know dst_bytes, so set to 0
    
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
        X = new_rows[['protocol_type', 'src_bytes', 'dst_bytes']]
        preds = clf.predict(X)
        
        for i, pred in enumerate(preds):
            if pred != 0:
                row = new_rows.iloc[i]
                src_ip = row['src_ip']
                
                # Skip whitelisted IPs
                if is_whitelisted(src_ip):
                    continue
                
                alert = f"ALERT: Suspicious activity detected: {row.to_dict()} | Predicted label: {pred}"
                print(alert)
                with open(LOG_PATH, 'a') as f:
                    f.write(alert + '\n')
                # Threat intelligence check
                if ABUSEIPDB_API_KEY:
                    abuse_result = check_ip_abuse(src_ip, ABUSEIPDB_API_KEY)
                    with open(LOG_PATH, 'a') as f:
                        f.write(f"AbuseIPDB: {abuse_result}\n")
                    print(f"AbuseIPDB: {abuse_result}")
                    if abuse_result.get('abuseConfidenceScore', 0) >= 50:
                        block_ip(src_ip)
        last_seen = len(df)
        sleep(2)

if __name__ == '__main__':
    main() 