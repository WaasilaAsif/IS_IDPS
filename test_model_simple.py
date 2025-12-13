"""
Simple test: Create a fake suspicious packet and test if detection works
"""
import pandas as pd
import joblib
import os

MODEL_PATH = 'models/rf_model.joblib'
PROTO_ENCODER_PATH = 'models/proto_encoder.joblib'
DATA_PATH = 'data/captured_packets.csv'
LOG_PATH = 'data/alerts.log'

clf = joblib.load(MODEL_PATH)
le_proto = joblib.load(PROTO_ENCODER_PATH)

# Create test packets manually
test_data = [
    {'timestamp': '2025-12-13T18:40:00', 'src_ip': '9.9.9.9', 'dst_ip': '192.168.10.138', 
     'src_port': 12345, 'dst_port': 22, 'protocol': 'TCP', 'packet_length': 60},
    {'timestamp': '2025-12-13T18:40:01', 'src_ip': '9.9.9.9', 'dst_ip': '192.168.10.138', 
     'src_port': 12346, 'dst_port': 23, 'protocol': 'TCP', 'packet_length': 60},
    {'timestamp': '2025-12-13T18:40:02', 'src_ip': '9.9.9.9', 'dst_ip': '192.168.10.138', 
     'src_port': 12347, 'dst_port': 80, 'protocol': 'TCP', 'packet_length': 60},
]

PROTOCOL_MAP = {'TCP': 'tcp', 'UDP': 'udp', 'ICMP': 'icmp'}

print("Testing model predictions on simulated suspicious packets:\n")
print("="*70)

for packet in test_data:
    proto_type = PROTOCOL_MAP.get(str(packet['protocol']).upper(), 'other')
    protocol_type_encoded = le_proto.transform([proto_type])[0] if proto_type in le_proto.classes_ else 0
    src_bytes = int(packet['packet_length'])
    dst_bytes = 0
    
    X = [[protocol_type_encoded, src_bytes, dst_bytes]]
    pred = clf.predict(X)[0]
    proba = clf.predict_proba(X)[0]
    
    print(f"Packet: {packet['src_ip']}:{packet['src_port']} -> {packet['dst_ip']}:{packet['dst_port']}")
    print(f"  Protocol: {packet['protocol']} | Size: {packet['packet_length']} bytes")
    print(f"  Features: protocol_type={protocol_type_encoded}, src_bytes={src_bytes}, dst_bytes={dst_bytes}")
    print(f"  Prediction: {pred} {'(NORMAL ✗)' if pred == 0 else '(ATTACK ✓)'}")
    print(f"  Confidence: {max(proba)*100:.1f}%")
    print("-"*70)

print("\n🔍 DIAGNOSIS:")
print("="*70)
print("If all packets show 'NORMAL', the model is too simplistic.")
print("It was trained on NSL-KDD with only 3 features (protocol, src_bytes, dst_bytes)")
print("which isn't enough to distinguish attacks from normal traffic.")
print("\nRECOMMENDATIONS:")
print("1. Lower the threshold (detect more as suspicious)")
print("2. Add manual rules for port scans, floods, etc.")
print("3. Retrain with more features or synthetic attack data")
