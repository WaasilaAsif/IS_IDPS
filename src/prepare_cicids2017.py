import pandas as pd
import os
import numpy as np

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
OUTPUT_PATH = os.path.join(DATA_DIR, 'cicids2017_preprocessed.csv')

print("Processing CICIDS2017 dataset...")

# Find CSV files
csv_files = [
    os.path.join(root, f)
    for root, _, files in os.walk(DATA_DIR)
    for f in files
    if f.endswith('.csv') and any(day in f.lower() for day in ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'])
]

if not csv_files:
    print("ERROR: No CSV files found")
    exit(1)

print(f"Found {len(csv_files)} CSV files.")

# Read and combine all CSVs at once (faster)
combined_df = pd.concat((pd.read_csv(f, encoding='utf-8', low_memory=False) for f in csv_files), ignore_index=True)
combined_df.columns = combined_df.columns.str.strip()
print(f"Total rows: {len(combined_df)}")

# Detect label column
label_col = 'Label' if 'Label' in combined_df.columns else ' Label'

# CICIDS2017 doesn't have Protocol column - we'll infer or default to TCP
# Find forward/backward length columns
fwd_col = 'Total Length of Fwd Packets'
bwd_col = 'Total Length of Bwd Packets'
dst_port_col = 'Destination Port'

# Select only relevant features
features = [fwd_col, bwd_col, dst_port_col, label_col]
combined_df = combined_df[features]

# Infer protocol from common port numbers (simplified)
def infer_protocol(port):
    try:
        port = int(port)
        # UDP ports
        if port in [53, 67, 68, 123, 161, 162, 514]:
            return 'udp'
        # ICMP doesn't use ports, but if port is 0 or very low, might be ICMP
        elif port == 0:
            return 'icmp'
        else:
            return 'tcp'  # Most traffic is TCP
    except:
        return 'tcp'

print("Inferring protocols from destination ports...")
combined_df['protocol_type'] = combined_df[dst_port_col].apply(infer_protocol)

# Map labels (BENIGN -> normal, others -> attack)
combined_df['label'] = combined_df[label_col].apply(lambda x: 'normal' if str(x).strip() == 'BENIGN' else 'attack')

# Rename byte columns
combined_df = combined_df.rename(columns={
    fwd_col: 'src_bytes',
    bwd_col: 'dst_bytes'
})

# Ensure numeric columns
combined_df['src_bytes'] = pd.to_numeric(combined_df['src_bytes'], errors='coerce').fillna(0).astype(int)
combined_df['dst_bytes'] = pd.to_numeric(combined_df['dst_bytes'], errors='coerce').fillna(0).astype(int)

# Keep only necessary columns
processed_df = combined_df[['protocol_type', 'src_bytes', 'dst_bytes', 'label']].dropna()

# Optional: sample if too large
if len(processed_df) > 500_000:
    processed_df = processed_df.sample(n=500_000, random_state=42)

# Save
processed_df.to_csv(OUTPUT_PATH, index=False)
print(f"✓ Processed dataset saved to {OUTPUT_PATH}")
print(processed_df['label'].value_counts())
print(processed_df['protocol_type'].value_counts())
