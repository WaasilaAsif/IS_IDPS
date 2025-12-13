"""
Debug script to manually test the detection logic
"""
import pandas as pd
import joblib
import os
import ipaddress

MODEL_PATH = 'models/rf_model.joblib'
PROTO_ENCODER_PATH = 'models/proto_encoder.joblib'
DATA_PATH = 'data/captured_packets.csv'

clf = joblib.load(MODEL_PATH)
le_proto = joblib.load(PROTO_ENCODER_PATH)

# Load whitelist
WHITELIST_RANGES = [
    '4.0.0.0/8', '13.0.0.0/8', '20.0.0.0/8', '23.0.0.0/8',
    '40.0.0.0/8', '52.0.0.0/8', '3.0.0.0/8', '15.0.0.0/8',
    '18.0.0.0/8', '35.0.0.0/8', '54.0.0.0/8', '96.0.0.0/9',
    '104.16.0.0/12', '104.40.0.0/13', '104.64.0.0/10',
    '142.250.0.0/15', '172.217.0.0/16', '216.58.192.0/19',
    '140.82.0.0/16', '185.199.0.0/16', '192.30.252.0/22',
    '172.64.0.0/13', '1.1.1.0/24', '1.0.0.0/24',
    '151.101.0.0/16', '199.232.0.0/16',
    '192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12',
    '8.8.8.0/24', '8.8.4.0/24',
    '137.116.0.0/16', '168.61.0.0/16', '191.232.0.0/13', '199.30.16.0/20',
]

def is_whitelisted(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for range_str in WHITELIST_RANGES:
            if ip_obj in ipaddress.ip_network(range_str):
                return True
    except ValueError:
        pass
    return False

PROTOCOL_MAP = {'TCP': 'tcp', 'UDP': 'udp', 'ICMP': 'icmp'}

# Search for test packets
print("Searching for test packets (45.45.45.45, 89.89.89.89, 77.77.77.77)...")
df = pd.read_csv(DATA_PATH)
test_packets = df[df['src_ip'].isin(['45.45.45.45', '89.89.89.89', '77.77.77.77'])]

if len(test_packets) == 0:
    print("❌ No test packets found in CSV!")
else:
    print(f"✓ Found {len(test_packets)} test packets\n")
    
    for idx, row in test_packets.iterrows():
        src_ip = row['src_ip']
        
        # Check whitelist
        if is_whitelisted(src_ip):
            print(f"❌ {src_ip} is WHITELISTED (should not be!)")
            continue
        else:
            print(f"✓ {src_ip} is NOT whitelisted")
        
        # Preprocess
        proto_type = PROTOCOL_MAP.get(str(row['protocol']).upper(), 'other')
        protocol_type_encoded = le_proto.transform([proto_type])[0] if proto_type in le_proto.classes_ else 0
        src_bytes = int(row['packet_length'])
        dst_bytes = 0
        
        # Predict
        X = [[protocol_type_encoded, src_bytes, dst_bytes]]
        pred = clf.predict(X)[0]
        
        print(f"  Protocol: {row['protocol']} -> encoded: {protocol_type_encoded}")
        print(f"  Size: {src_bytes} bytes")
        print(f"  Prediction: {pred} {'(NORMAL - NO ALERT)' if pred == 0 else '(ATTACK - SHOULD ALERT!)'}")
        print()

print("\n" + "="*70)
print("If predictions show 'ATTACK' but no alerts appeared,")
print("then realtime_detect.py is not processing these packets.")
print("Check the 'python' terminal to see if there are any errors.")
