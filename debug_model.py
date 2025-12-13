"""
Debug script to see what the model predicts for test traffic
"""
import pandas as pd
import joblib
import os

MODEL_PATH = 'models/rf_model.joblib'
PROTO_ENCODER_PATH = 'models/proto_encoder.joblib'
DATA_PATH = 'data/captured_packets.csv'

clf = joblib.load(MODEL_PATH)
le_proto = joblib.load(PROTO_ENCODER_PATH)

# Load last 50 packets
df = pd.read_csv(DATA_PATH).tail(50)

# Filter for test IPs
test_ips = ['9.9.9.9', '208.67.222.222', '1.0.0.1']
test_packets = df[df['src_ip'].isin(test_ips) | df['dst_ip'].isin(test_ips)]

print(f"Found {len(test_packets)} packets with test IPs")
print("\nTest packets:")
print(test_packets[['timestamp', 'src_ip', 'dst_ip', 'protocol', 'packet_length']])

if len(test_packets) > 0:
    # Preprocess
    PROTOCOL_MAP = {'TCP': 'tcp', 'UDP': 'udp', 'ICMP': 'icmp'}
    
    for idx, row in test_packets.iterrows():
        proto_type = PROTOCOL_MAP.get(str(row['protocol']).upper(), 'other')
        protocol_type_encoded = le_proto.transform([proto_type])[0] if proto_type in le_proto.classes_ else 0
        src_bytes = int(row['packet_length']) if pd.notnull(row['packet_length']) else 0
        dst_bytes = 0
        
        X = [[protocol_type_encoded, src_bytes, dst_bytes]]
        pred = clf.predict(X)[0]
        
        print(f"\nPacket: {row['src_ip']} -> {row['dst_ip']}")
        print(f"  Protocol: {row['protocol']} (encoded: {protocol_type_encoded})")
        print(f"  Bytes: src={src_bytes}, dst={dst_bytes}")
        print(f"  Prediction: {pred} {'(NORMAL)' if pred == 0 else '(ATTACK)'}")
else:
    print("\nNo test traffic found in recent packets!")
    print("Make sure to run test_ids.py and wait a few seconds.")
