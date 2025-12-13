import scapy.all as scapy
import pandas as pd
import os
from datetime import datetime
from collections import defaultdict
import time

DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'captured_packets.csv')

# Flow tracking: key = (src_ip, dst_ip, src_port, dst_port)
flows = defaultdict(lambda: {'fwd_bytes': 0, 'bwd_bytes': 0, 'fwd_packets': 0, 'bwd_packets': 0, 'start_time': time.time()})

features = [
    'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packet_length', 'fwd_bytes', 'bwd_bytes'
]

def extract_features(packet):
    if not packet.haslayer(scapy.IP):
        return None
    ip_layer = packet[scapy.IP]
    proto = ip_layer.proto
    protocol = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, str(proto))
    src_port = dst_port = None
    if protocol == 'TCP' and packet.haslayer(scapy.TCP):
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
    elif protocol == 'UDP' and packet.haslayer(scapy.UDP):
        src_port = packet[scapy.UDP].sport
        dst_port = packet[scapy.UDP].dport
    
    # Track flows (forward and backward)
    flow_key_fwd = (ip_layer.src, ip_layer.dst, src_port, dst_port)
    flow_key_bwd = (ip_layer.dst, ip_layer.src, dst_port, src_port)
    
    packet_len = len(packet)
    
    # Check if this is forward or backward direction
    if flow_key_fwd in flows:
        flows[flow_key_fwd]['fwd_bytes'] += packet_len
        flows[flow_key_fwd]['fwd_packets'] += 1
        fwd_bytes = flows[flow_key_fwd]['fwd_bytes']
        bwd_bytes = flows[flow_key_fwd]['bwd_bytes']
    elif flow_key_bwd in flows:
        flows[flow_key_bwd]['bwd_bytes'] += packet_len
        flows[flow_key_bwd]['bwd_packets'] += 1
        fwd_bytes = flows[flow_key_bwd]['fwd_bytes']
        bwd_bytes = flows[flow_key_bwd]['bwd_bytes']
    else:
        # New flow
        flows[flow_key_fwd]['fwd_bytes'] = packet_len
        flows[flow_key_fwd]['fwd_packets'] = 1
        fwd_bytes = packet_len
        bwd_bytes = 0
    
    return {
        'timestamp': datetime.now().isoformat(),
        'src_ip': ip_layer.src,
        'dst_ip': ip_layer.dst,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol,
        'packet_length': packet_len,
        'fwd_bytes': fwd_bytes,
        'bwd_bytes': bwd_bytes
    }

def packet_callback(packet):
    feat = extract_features(packet)
    if feat:
        df = pd.DataFrame([feat])
        if not os.path.exists(DATA_PATH):
            df.to_csv(DATA_PATH, index=False, mode='w', header=True)
        else:
            df.to_csv(DATA_PATH, index=False, mode='a', header=False)
        print(feat)

if __name__ == '__main__':
    print('Starting packet capture... Press Ctrl+C to stop.')
    scapy.sniff(prn=packet_callback, store=0) 