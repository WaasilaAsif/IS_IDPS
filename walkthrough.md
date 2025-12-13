
# 🛡️ AI-IDPS Project Walkthrough

> **A Complete Technical Guide to the AI-Powered Intrusion Detection & Prevention System**

This document provides a detailed, sequential walkthrough of the entire AI-IDPS project. By reading this guide, you will fully understand the project architecture, how each component works, and how they interact to create a real-time network threat detection system.

---

## 📋 Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture Diagram](#2-architecture-diagram)
3. [Project Structure](#3-project-structure)
4. [Root-Level Files](#4-root-level-files)
5. [Source Code (src/)](#5-source-code-src)
6. [Dashboard (dashboard/)](#6-dashboard-dashboard)
7. [Data Directory (data/)](#7-data-directory-data)
8. [Models Directory (models/)](#8-models-directory-models)
9. [Complete Workflow](#9-complete-workflow)
10. [Data Flow Diagram](#10-data-flow-diagram)
11. [Tips for Developers](#11-tips-for-developers)

---

## 1. Project Overview

### What is AI-IDPS?

AI-IDPS (AI-Powered Intrusion Detection & Prevention System) is a lightweight, machine learning-enhanced security tool designed to:

- **Monitor** live network traffic on your home or lab network
- **Detect** suspicious or malicious activity using a trained Random Forest classifier
- **Alert** users via a real-time web dashboard
- **Block** high-risk IP addresses automatically using Windows firewall rules
- **Integrate** with AbuseIPDB for external threat intelligence

### Technology Stack

| Component | Technology |
|-----------|------------|
| **Packet Sniffing** | Scapy (Python) |
| **Machine Learning** | scikit-learn (Random Forest) |
| **Data Processing** | Pandas |
| **Dashboard** | Streamlit |
| **Threat Intelligence** | AbuseIPDB API |
| **Programming Language** | Python 3.11 |

---

## 2. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AI-IDPS ARCHITECTURE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│    ┌──────────────┐       ┌──────────────┐       ┌──────────────────┐      │
│    │   SNIFFER    │──────▶│   DETECTOR   │──────▶│   ALERT/BLOCK    │      │
│    │ (sniffer.py) │       │(realtime_    │       │   (firewall +    │      │
│    │              │       │ detect.py)   │       │    logs)         │      │
│    └──────┬───────┘       └──────┬───────┘       └────────┬─────────┘      │
│           │                      │                        │                 │
│           ▼                      ▼                        ▼                 │
│    ┌──────────────┐       ┌──────────────┐       ┌──────────────────┐      │
│    │ captured_    │       │ rf_model.    │       │   alerts.log     │      │
│    │ packets.csv  │       │ joblib       │       │                  │      │
│    └──────────────┘       └──────────────┘       └────────┬─────────┘      │
│           │                      │                        │                 │
│           └──────────────────────┼────────────────────────┘                 │
│                                  │                                          │
│                                  ▼                                          │
│                         ┌──────────────────┐                               │
│                         │    DASHBOARD     │                               │
│                         │    (app.py)      │                               │
│                         │  localhost:8501  │                               │
│                         └──────────────────┘                               │
│                                                                             │
│    ┌──────────────┐       ┌──────────────┐                                 │
│    │ dataset_     │──────▶│ train_       │  ◀── One-time setup             │
│    │ prep.py      │       │ model.py     │                                 │
│    └──────────────┘       └──────────────┘                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Project Structure

```
IS_IDPS/
│
├── 📄 README.md               # Project overview
├── 📄 requirements.txt        # Python dependencies
├── 📄 setup.md                # Detailed setup instructions
├── 📄 walkthrough.md          # This file
│
├── 📁 dashboard/              # Web interface
│   └── 📄 app.py              # Streamlit dashboard application
│
├── 📁 data/                   # All data files
│   ├── 📄 captured_packets.csv       # Live captured network packets
│   ├── 📄 nsl_kdd_preprocessed.csv   # Preprocessed training data
│   └── 📁 NSL_KDD-master/            # Raw NSL-KDD dataset
│       ├── 📄 KDDTrain+.csv          # Training dataset
│       ├── 📄 KDDTest+.csv           # Test dataset
│       ├── 📄 Field Names.csv        # Feature descriptions
│       ├── 📄 Attack Types.csv       # Attack category mappings
│       └── ... (other dataset files)
│
├── 📁 models/                 # Trained ML models
│   ├── 📄 rf_model.joblib            # Random Forest classifier
│   └── 📄 proto_encoder.joblib       # Protocol type encoder
│
└── 📁 src/                    # Core source code
    ├── 📄 dataset_prep.py     # Dataset download & preprocessing
    ├── 📄 train_model.py      # ML model training
    ├── 📄 sniffer.py          # Live packet capture
    ├── 📄 realtime_detect.py  # Real-time threat detection
    └── 📄 threat_intel.py     # AbuseIPDB integration
```

---

## 4. Root-Level Files

### 4.1 `README.md`

**Purpose:** Main project documentation providing an overview, features list, quickstart guide, and troubleshooting tips.

**Contents:**
- Project overview and features
- Architecture diagram
- Local installation steps
- Security and ethics notice
- Contributing guidelines

---

### 4.2 `requirements.txt`

**Purpose:** Lists all Python package dependencies required to run the project.

**Dependencies Explained:**

| Package | Version | Purpose |
|---------|---------|---------|
| `scapy` | Latest | Low-level packet capture and network analysis |
| `pandas` | Latest | Data manipulation and CSV handling |
| `scikit-learn` | Latest | Machine learning (Random Forest classifier) |
| `streamlit` | Latest | Web dashboard framework |
| `matplotlib` | Latest | Data visualization (charts) |
| `plotly` | Latest | Interactive visualizations |
| `requests` | Latest | HTTP requests for AbuseIPDB API |
| `geoip2` | Latest | Geographic IP lookup (optional) |
| `joblib` | Latest | Model serialization/deserialization |
| `flask` | Latest | Web framework (backup/alternative) |
| `tensorflow` | Latest | Deep learning framework (optional/future) |
| `h5py` | Latest | HDF5 file support for TensorFlow |

**Installation:**
```bash
pip install -r requirements.txt
```

---

### 4.3 `setup.md`

**Purpose:** Comprehensive step-by-step setup guide for Windows, Linux, and macOS users.

**Covers:**
- Python installation (specifically 3.11 for ML compatibility)
- Virtual environment setup
- Dependency installation
- API key configuration
- Running each component
- Troubleshooting common issues

---

## 5. Source Code (src/)

This directory contains the core logic of the AI-IDPS system. The files are listed in the order they should be understood/executed.

---

### 5.1 `dataset_prep.py`

**Purpose:** Downloads and preprocesses the NSL-KDD dataset, which is used to train the intrusion detection model.

**Location:** `src/dataset_prep.py`

#### Key Components:

**Constants:**
```python
DATA_DIR = '../data'                                              # Output directory
NSL_URL = 'https://github.com/defcom17/NSL_KDD/archive/refs/heads/master.zip'
```

**FEATURES Array (42 columns):**
The NSL-KDD dataset contains 42 features describing network connections:

| Category | Features |
|----------|----------|
| **Basic** | `duration`, `protocol_type`, `service`, `flag` |
| **Content** | `src_bytes`, `dst_bytes`, `land`, `wrong_fragment`, `urgent` |
| **Traffic** | `count`, `srv_count`, `serror_rate`, `same_srv_rate`, etc. |
| **Host-based** | `dst_host_count`, `dst_host_srv_count`, etc. |
| **Label** | `label` (normal, neptune, smurf, etc.) |

#### Functions:

**`download_and_extract()`**
```python
def download_and_extract():
    # Downloads NSL-KDD dataset from GitHub
    # Extracts ZIP file to data/ directory
```
- **Input:** None (uses hardcoded URL)
- **Output:** Extracted files in `data/NSL_KDD-master/`
- **Side Effect:** Creates directory structure and files

**`preprocess()`**
```python
def preprocess():
    # Loads KDDTrain+.txt with proper column names
    # Saves as nsl_kdd_preprocessed.csv
```
- **Input:** `data/NSL_KDD-master/KDDTrain+.txt`
- **Output:** `data/nsl_kdd_preprocessed.csv`
- **Side Effect:** Creates preprocessed CSV file

#### Workflow:
```
Run dataset_prep.py
        │
        ▼
┌───────────────────┐
│ Check if dataset  │
│ exists locally    │
└────────┬──────────┘
         │
    No ──┴── Yes
    │         │
    ▼         │
Download &    │
Extract       │
    │         │
    └────┬────┘
         ▼
┌───────────────────┐
│ Load KDDTrain+.txt│
│ Add column names  │
└────────┬──────────┘
         ▼
┌───────────────────┐
│ Save preprocessed │
│ CSV file          │
└───────────────────┘
```

#### Usage:
```bash
python src/dataset_prep.py
```

---

### 5.2 `train_model.py`

**Purpose:** Trains a Random Forest classifier on the preprocessed NSL-KDD dataset and saves the model for real-time detection.

**Location:** `src/train_model.py`

#### Key Components:

**File Paths:**
```python
DATA_PATH = '../data/nsl_kdd_preprocessed.csv'    # Training data
MODEL_PATH = '../models/rf_model.joblib'          # Saved model
```

**Selected Features:**
```python
features = ['protocol_type', 'src_bytes', 'dst_bytes']
```

> 🔑 **Why only 3 features?** These are the only features available during real-time packet capture. Other NSL-KDD features require deep packet inspection or historical data.

#### Processing Steps:

1. **Load Data:**
   ```python
   df = pd.read_csv(DATA_PATH)
   ```

2. **Encode Categorical Variables:**
   ```python
   le_proto = LabelEncoder()
   df['protocol_type'] = le_proto.fit_transform(df['protocol_type'])
   # Converts: tcp=0, udp=1, icmp=2
   ```

3. **Encode Labels:**
   ```python
   label_le = LabelEncoder()
   df['label'] = label_le.fit_transform(df['label'])
   # Converts: normal=0, neptune=1, smurf=2, etc.
   ```

4. **Train/Test Split:**
   ```python
   X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
   ```

5. **Train Model:**
   ```python
   clf = RandomForestClassifier(n_estimators=100, random_state=42)
   clf.fit(X_train, y_train)
   ```

6. **Evaluate & Save:**
   ```python
   print(classification_report(y_test, y_pred))
   joblib.dump(clf, MODEL_PATH)
   joblib.dump(le_proto, 'proto_encoder.joblib')
   ```

#### Outputs:
| File | Description |
|------|-------------|
| `models/rf_model.joblib` | Trained Random Forest model (~100 decision trees) |
| `models/proto_encoder.joblib` | LabelEncoder for protocol_type conversion |

#### Model Performance:
The model is evaluated using classification metrics (precision, recall, F1-score) printed to console.

#### Usage:
```bash
python src/train_model.py
```

---

### 5.3 `sniffer.py`

**Purpose:** Captures live network packets using Scapy and extracts relevant features for analysis.

**Location:** `src/sniffer.py`

#### Key Components:

**Output Path:**
```python
DATA_PATH = '../data/captured_packets.csv'
```

**Feature Extraction:**
```python
features = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packet_length']
```

#### Functions:

**`extract_features(packet)`**

Extracts network features from a raw Scapy packet object.

```python
def extract_features(packet):
    # Returns None if no IP layer exists
    if not packet.haslayer(scapy.IP):
        return None
    
    # Extract IP layer information
    ip_layer = packet[scapy.IP]
    
    # Map protocol number to name
    # 6 = TCP, 17 = UDP, 1 = ICMP
    protocol = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, str(proto))
    
    # Extract ports based on protocol
    if protocol == 'TCP':
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
    elif protocol == 'UDP':
        src_port = packet[scapy.UDP].sport
        dst_port = packet[scapy.UDP].dport
    
    return {
        'timestamp': datetime.now().isoformat(),
        'src_ip': ip_layer.src,
        'dst_ip': ip_layer.dst,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol,
        'packet_length': len(packet)
    }
```

**Input:** Raw Scapy packet object
**Output:** Dictionary with extracted features (or `None`)

---

**`packet_callback(packet)`**

Callback function called for each captured packet.

```python
def packet_callback(packet):
    feat = extract_features(packet)
    if feat:
        df = pd.DataFrame([feat])
        # Append to CSV (create if doesn't exist)
        df.to_csv(DATA_PATH, mode='a', header=not os.path.exists(DATA_PATH))
        print(feat)  # Console output for debugging
```

**Side Effects:**
- Appends packet data to `data/captured_packets.csv`
- Prints each captured packet to console

---

**Main Execution:**
```python
if __name__ == '__main__':
    print('Starting packet capture... Press Ctrl+C to stop.')
    scapy.sniff(prn=packet_callback, store=0)
```

- `prn=packet_callback`: Calls our function for each packet
- `store=0`: Don't store packets in memory (memory efficient)

#### Captured Data Format:

| Column | Type | Example |
|--------|------|---------|
| `timestamp` | ISO 8601 | `2025-12-13T17:14:29.942962` |
| `src_ip` | IPv4 | `10.7.116.127` |
| `dst_ip` | IPv4 | `239.255.255.250` |
| `src_port` | Integer | `1900` |
| `dst_port` | Integer | `1900` |
| `protocol` | String | `UDP`, `TCP`, `ICMP` |
| `packet_length` | Integer | `179` |

#### Usage:
```bash
python src/sniffer.py
# Runs continuously until Ctrl+C
```

> ⚠️ **Permission Note:** On Linux, requires root privileges or `CAP_NET_RAW` capability. On Windows, requires Npcap or WinPcap installed.

---

### 5.4 `threat_intel.py`

**Purpose:** Integrates with the AbuseIPDB API to check if an IP address has been reported for malicious activity.

**Location:** `src/threat_intel.py`

#### Function:

**`check_ip_abuse(ip, api_key)`**

Queries the AbuseIPDB API for reputation data on a given IP address.

```python
def check_ip_abuse(ip, api_key):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90  # Check reports from last 90 days
    }
    # ... HTTP request logic ...
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `ip` | String | IP address to check (e.g., `"8.8.8.8"`) |
| `api_key` | String | AbuseIPDB API key |

**Returns:**
```python
{
    'ip': '1.2.3.4',
    'abuseConfidenceScore': 85,      # 0-100 (higher = more malicious)
    'countryCode': 'CN',
    'usageType': 'Data Center/Web Hosting',
    'domain': 'example.com',
    'totalReports': 142,
    'lastReportedAt': '2025-12-10T15:30:00Z'
}
```

**Error Response:**
```python
{'ip': '1.2.3.4', 'error': 'HTTP 401: Unauthorized'}
```

#### Abuse Confidence Score:

| Score | Interpretation |
|-------|----------------|
| 0-25 | Low risk - likely legitimate |
| 26-50 | Medium risk - monitor closely |
| 51-75 | High risk - suspicious activity |
| 76-100 | Critical risk - known malicious |

> 🔑 **API Key:** Get a free key at [abuseipdb.com](https://www.abuseipdb.com/). The free tier allows 1,000 checks per day.

---

### 5.5 `realtime_detect.py`

**Purpose:** The main detection engine that continuously monitors captured packets, classifies them using the ML model, and takes action on threats.

**Location:** `src/realtime_detect.py`

#### Key Components:

**File Paths:**
```python
DATA_PATH = '../data/captured_packets.csv'           # Input: captured packets
MODEL_PATH = '../models/rf_model.joblib'             # ML model
PROTO_ENCODER_PATH = '../models/proto_encoder.joblib' # Protocol encoder
LOG_PATH = '../data/alerts.log'                      # Output: alerts
```

**Model Loading:**
```python
clf = joblib.load(MODEL_PATH)           # Load trained Random Forest
le_proto = joblib.load(PROTO_ENCODER_PATH)  # Load protocol encoder
```

**Protocol Mapping:**
```python
PROTOCOL_MAP = {'TCP': 'tcp', 'UDP': 'udp', 'ICMP': 'icmp'}
```

#### Functions:

**`preprocess_row(row)`**

Transforms a captured packet row into the format expected by the ML model.

```python
def preprocess_row(row):
    # Convert protocol string to encoded integer
    proto_type = PROTOCOL_MAP.get(str(row['protocol']).upper(), 'other')
    row['protocol_type'] = le_proto.transform([proto_type])[0]
    
    # Map packet_length to src_bytes (approximation)
    row['src_bytes'] = int(row['packet_length'])
    row['dst_bytes'] = 0  # Unknown in real-time
    
    return row
```

**Input:** Pandas Series (one row from captured_packets.csv)
**Output:** Transformed row with `protocol_type`, `src_bytes`, `dst_bytes`

---

**`block_ip(ip)`**

Blocks a malicious IP using Windows Firewall (netsh).

```python
def block_ip(ip):
    if ip in blocked_ips:  # Don't block twice
        return
    
    cmd = f'netsh advfirewall firewall add rule name="IDS_Block_{ip}" dir=in action=block remoteip={ip} enable=yes'
    subprocess.run(cmd, shell=True, check=True)
    
    blocked_ips.add(ip)
    # Log the action
```

**Input:** IP address string
**Side Effects:**
- Creates Windows Firewall rule
- Adds IP to `blocked_ips` set
- Logs to `alerts.log`

> ⚠️ **Windows Only:** This uses `netsh` which is Windows-specific. On Linux, you would use `iptables` or `nftables`.

---

**`main()`**

The main detection loop.

```python
def main():
    last_seen = 0  # Track processed rows
    
    while True:
        # Read captured packets
        df = pd.read_csv(DATA_PATH)
        
        # Process only new rows
        new_rows = df.iloc[last_seen:]
        new_rows = new_rows.apply(preprocess_row, axis=1)
        
        # Predict using ML model
        X = new_rows[['protocol_type', 'src_bytes', 'dst_bytes']]
        preds = clf.predict(X)
        
        for i, pred in enumerate(preds):
            if pred != 0:  # 0 = normal, anything else = attack
                # Log alert
                # Check AbuseIPDB
                # Block IP if score >= 50
        
        last_seen = len(df)
        sleep(2)  # Check every 2 seconds
```

#### Detection Workflow:

```
┌─────────────────────────────────────────────────────────────┐
│                    DETECTION LOOP                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐                                            │
│  │ Read CSV    │◀────────────────────────────────┐          │
│  └──────┬──────┘                                 │          │
│         ▼                                        │          │
│  ┌─────────────┐                                 │          │
│  │ New packets?│──No──▶ Sleep 2s ────────────────┘          │
│  └──────┬──────┘                                            │
│         │ Yes                                               │
│         ▼                                                   │
│  ┌─────────────┐                                            │
│  │ Preprocess  │                                            │
│  │ (encode     │                                            │
│  │  protocol)  │                                            │
│  └──────┬──────┘                                            │
│         ▼                                                   │
│  ┌─────────────┐                                            │
│  │ ML Predict  │                                            │
│  └──────┬──────┘                                            │
│         ▼                                                   │
│  ┌─────────────┐                                            │
│  │ Normal?     │──Yes──▶ Skip                               │
│  └──────┬──────┘                                            │
│         │ No (Attack)                                       │
│         ▼                                                   │
│  ┌─────────────┐                                            │
│  │ Log Alert   │                                            │
│  └──────┬──────┘                                            │
│         ▼                                                   │
│  ┌─────────────┐                                            │
│  │ AbuseIPDB   │                                            │
│  │ Check       │                                            │
│  └──────┬──────┘                                            │
│         ▼                                                   │
│  ┌─────────────┐                                            │
│  │ Score ≥ 50? │──No──▶ Continue                            │
│  └──────┬──────┘                                            │
│         │ Yes                                               │
│         ▼                                                   │
│  ┌─────────────┐                                            │
│  │ BLOCK IP    │                                            │
│  └─────────────┘                                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Usage:
```bash
# Set API key (optional but recommended)
$env:ABUSEIPDB_API_KEY="your_key_here"

# Run detector
python src/realtime_detect.py
```

---

## 6. Dashboard (dashboard/)

### 6.1 `app.py`

**Purpose:** Provides a real-time web-based dashboard for monitoring network traffic, viewing alerts, and checking threat intelligence.

**Location:** `dashboard/app.py`

#### Configuration:

```python
DATA_PATH = '../data/captured_packets.csv'   # Packet data
LOG_PATH = '../data/alerts.log'              # Alert logs

st.set_page_config(page_title='AI-Powered IDS Dashboard', layout='wide')
```

#### Dashboard Sections:

**1. Header:**
```python
st.title('AI-Powered IDS for Home Networks')
```

**2. Live Traffic Column (`col1`):**
- Displays total packet count
- Shows last 20 captured packets in a data table
- Line chart of recent packet lengths

**3. Recent Alerts Column (`col2`):**
- Lists last 20 alerts (newest first)
- Each alert displayed as a red error box
- Shows "No suspicious activity detected" if no alerts

**4. Sidebar - Threat Intelligence:**
- Displays AbuseIPDB lookup results
- Shows IP details: country, abuse score, usage type, domain
- Warning indicator if IP was auto-blocked

**5. Optional GeoIP Section:**
- Geographic location lookup for suspicious IPs
- Requires `GeoLite2-City.mmdb` database file

#### Functions:

**`load_packets()`**
```python
def load_packets():
    if os.path.exists(DATA_PATH):
        return pd.read_csv(DATA_PATH)
    return pd.DataFrame()
```
Returns all captured packets as a Pandas DataFrame.

**`load_alerts()`**
```python
def load_alerts():
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH) as f:
            lines = f.readlines()
        return lines[-20:][::-1]  # Last 20, reversed
    return []
```
Returns the 20 most recent alerts (newest first).

#### Dashboard Layout:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     AI-Powered IDS for Home Networks                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────┐    ┌─────────────────────────────────────────┐ │
│  │                         │    │        SIDEBAR                          │ │
│  │     LIVE TRAFFIC        │    │                                         │ │
│  │                         │    │  Threat Intelligence (AbuseIPDB)        │ │
│  │  Total: 72,307 packets  │    │  ─────────────────────────────          │ │
│  │                         │    │  IP: 1.2.3.4                            │ │
│  │  ┌─────────────────┐    │    │  Abuse Score: 85                        │ │
│  │  │ Data Table      │    │    │  Country: CN                            │ │
│  │  │ (last 20)       │    │    │  Usage: Data Center                     │ │
│  │  └─────────────────┘    │    │  Domain: example.com                    │ │
│  │                         │    │  Reports: 142                           │ │
│  │  ┌─────────────────┐    │    │                                         │ │
│  │  │ Packet Length   │    │    │  ⚠️ This IP was auto-blocked!           │ │
│  │  │ Line Chart      │    │    │                                         │ │
│  │  └─────────────────┘    │    └─────────────────────────────────────────┘ │
│  │                         │                                                │
│  └─────────────────────────┘                                                │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                        RECENT ALERTS                                    ││
│  │  ┌─────────────────────────────────────────────────────────────────────┐││
│  │  │ ❌ ALERT: Suspicious activity detected: {...} | Predicted: neptune │││
│  │  │ ❌ AbuseIPDB: {'ip': '1.2.3.4', 'abuseConfidenceScore': 85}         │││
│  │  │ ❌ AUTO-BLOCKED IP: 1.2.3.4                                         │││
│  │  └─────────────────────────────────────────────────────────────────────┘││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│                        AI-Powered IDS | Streamlit Dashboard                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Usage:
```bash
streamlit run dashboard/app.py
# Opens at http://localhost:8501
```

> 💡 **Auto-Refresh:** Streamlit automatically refreshes the page when data changes. You can also click "Rerun" in the top-right corner.

---

## 7. Data Directory (data/)

This directory contains all data files used by the system.

### 7.1 `captured_packets.csv`

**Purpose:** Stores all packets captured by the sniffer in real-time.

**Format:**
| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | String | ISO 8601 formatted capture time |
| `src_ip` | String | Source IP address |
| `dst_ip` | String | Destination IP address |
| `src_port` | Integer | Source port number |
| `dst_port` | Integer | Destination port number |
| `protocol` | String | TCP, UDP, or ICMP |
| `packet_length` | Integer | Total packet size in bytes |

**Example Data:**
```csv
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,packet_length
2025-12-13T17:14:29.942962,10.7.116.127,239.255.255.250,1900,1900,UDP,179
2025-12-13T17:14:30.046042,10.7.116.154,224.0.0.251,5353,5353,UDP,127
```

**Created by:** `src/sniffer.py`
**Read by:** `src/realtime_detect.py`, `dashboard/app.py`

---

### 7.2 `nsl_kdd_preprocessed.csv`

**Purpose:** Preprocessed version of the NSL-KDD training dataset with proper column headers.

**Size:** ~125,975 rows (network connection records)

**Key Columns Used for Training:**
| Column | Type | Description |
|--------|------|-------------|
| `protocol_type` | String | tcp, udp, or icmp |
| `src_bytes` | Integer | Bytes sent from source |
| `dst_bytes` | Integer | Bytes sent to destination |
| `label` | String | Attack type or "normal" |

**Created by:** `src/dataset_prep.py`
**Read by:** `src/train_model.py`

---

### 7.3 `alerts.log`

**Purpose:** Log file containing all security alerts and actions.

**Format:** Plain text, one entry per line.

**Entry Types:**
```
ALERT: Suspicious activity detected: {...} | Predicted label: neptune
AbuseIPDB: {'ip': '1.2.3.4', 'abuseConfidenceScore': 85, ...}
AUTO-BLOCKED IP: 1.2.3.4
Failed to block IP 1.2.3.4: Permission denied
```

**Created by:** `src/realtime_detect.py`
**Read by:** `dashboard/app.py`

---

### 7.4 `NSL_KDD-master/` Directory

**Purpose:** Contains the raw NSL-KDD dataset files downloaded from GitHub.

#### Files:

| File | Description |
|------|-------------|
| `KDDTrain+.txt` | Main training dataset (125,973 records) |
| `KDDTrain+.csv` | Same data in CSV format |
| `KDDTest+.txt` | Test dataset (22,544 records) |
| `KDDTest+.csv` | Same data in CSV format |
| `KDDTest-21.txt` | Test set excluding 21 attack types |
| `KDDTrain+_20Percent.txt` | 20% sample of training data |
| `20 Percent Training Set.csv` | Same as above, CSV format |
| `Small Training Set.csv` | Smaller subset for testing |
| `Field Names.csv` | Feature names and types |
| `Attack Types.csv` | Attack name to category mapping |
| `ReadMe.txt` | Dataset documentation |

#### Attack Categories (from Attack Types.csv):

| Category | Attack Types | Description |
|----------|-------------|-------------|
| **DoS** | neptune, smurf, pod, teardrop, land, back | Denial of Service |
| **Probe** | ipsweep, nmap, portsweep, satan | Network scanning |
| **R2L** | ftp_write, guess_passwd, imap, phf, spy, warezclient | Remote to Local |
| **U2R** | buffer_overflow, loadmodule, perl, rootkit | User to Root |
| **Normal** | normal | Legitimate traffic |

---

## 8. Models Directory (models/)

This directory contains the trained machine learning models saved in joblib format.

### 8.1 `rf_model.joblib`

**Purpose:** The trained Random Forest classifier for network intrusion detection.

**Model Details:**
| Property | Value |
|----------|-------|
| **Algorithm** | Random Forest Classifier |
| **Number of Trees** | 100 |
| **Features** | `protocol_type`, `src_bytes`, `dst_bytes` |
| **Output** | Attack label (0=normal, others=attack) |
| **Random State** | 42 (for reproducibility) |

**Created by:** `src/train_model.py`
**Used by:** `src/realtime_detect.py`

---

### 8.2 `proto_encoder.joblib`

**Purpose:** LabelEncoder for converting protocol type strings to integers.

**Encoding:**
| Protocol | Encoded Value |
|----------|---------------|
| `tcp` | 0 |
| `udp` | 1 |
| `icmp` | 2 |

**Created by:** `src/train_model.py`
**Used by:** `src/realtime_detect.py`

---

## 9. Complete Workflow

### One-Time Setup (Before First Use):

```
Step 1: Install Dependencies
───────────────────────────
pip install -r requirements.txt

Step 2: Download & Preprocess Dataset
─────────────────────────────────────
python src/dataset_prep.py
    │
    └──▶ Downloads NSL-KDD from GitHub
    └──▶ Creates data/nsl_kdd_preprocessed.csv

Step 3: Train ML Model
──────────────────────
python src/train_model.py
    │
    └──▶ Trains Random Forest on 125,973 samples
    └──▶ Creates models/rf_model.joblib
    └──▶ Creates models/proto_encoder.joblib
```

### Runtime Workflow (Normal Operation):

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         RUNTIME WORKFLOW                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  TERMINAL 1                 TERMINAL 2                 TERMINAL 3           │
│  ──────────                 ──────────                 ──────────           │
│                                                                             │
│  python src/sniffer.py      python src/realtime_detect.py                   │
│         │                          │                   streamlit run        │
│         │                          │                   dashboard/app.py     │
│         ▼                          │                          │             │
│  ┌─────────────┐                   │                          │             │
│  │ Capture     │                   │                          │             │
│  │ Packets     │                   │                          │             │
│  └──────┬──────┘                   │                          │             │
│         │                          │                          │             │
│         ▼                          │                          │             │
│  ┌─────────────┐                   │                          │             │
│  │ Write to    │                   │                          │             │
│  │ CSV file    │───────────────────┼──────────────────────────┼─────┐       │
│  └─────────────┘                   │                          │     │       │
│                                    ▼                          │     │       │
│                           ┌─────────────┐                     │     │       │
│                           │ Read CSV    │◀────────────────────┼─────┘       │
│                           └──────┬──────┘                     │             │
│                                  │                            │             │
│                                  ▼                            │             │
│                           ┌─────────────┐                     │             │
│                           │ ML Classify │                     │             │
│                           └──────┬──────┘                     │             │
│                                  │                            │             │
│                           Attack │ Normal                     │             │
│                              ────┴────                        │             │
│                              │                                │             │
│                              ▼                                │             │
│                       ┌─────────────┐                         │             │
│                       │ AbuseIPDB   │                         │             │
│                       └──────┬──────┘                         │             │
│                              │                                │             │
│                              ▼                                │             │
│                       ┌─────────────┐                         │             │
│                       │ Log Alert   │─────────────────────────┼───────┐     │
│                       │ + Block IP  │                         │       │     │
│                       └─────────────┘                         │       │     │
│                                                               │       │     │
│                                                               ▼       │     │
│                                                        ┌─────────────┐│     │
│                                                        │ Dashboard   ││     │
│                                                        │ Reads CSV   │◀─────┘
│                                                        │ + Log File  │      │
│                                                        └──────┬──────┘      │
│                                                               │             │
│                                                               ▼             │
│                                                        ┌─────────────┐      │
│                                                        │ Display in  │      │
│                                                        │ Browser     │      │
│                                                        │ :8501       │      │
│                                                        └─────────────┘      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Data Flow Diagram

```
                              ┌──────────────────┐
                              │   NETWORK        │
                              │   INTERFACE      │
                              └────────┬─────────┘
                                       │
                                       │ Raw Packets
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                              sniffer.py                                       │
│  ┌─────────────┐    ┌─────────────────┐    ┌─────────────────────────────┐   │
│  │ scapy.sniff │───▶│ extract_features│───▶│ packet_callback             │   │
│  └─────────────┘    └─────────────────┘    │ (append to CSV)             │   │
│                                            └─────────────────────────────┘   │
└─────────────────────────────────────────────────────────┬────────────────────┘
                                                          │
                                                          │ CSV append
                                                          ▼
                                             ┌────────────────────────┐
                                             │ captured_packets.csv   │
                                             │                        │
                                             │ timestamp, src_ip,     │
                                             │ dst_ip, ports,         │
                                             │ protocol, length       │
                                             └────────────┬───────────┘
                                                          │
                              ┌────────────────────────────┴─────────────────┐
                              │                                              │
                              ▼                                              ▼
         ┌─────────────────────────────────────┐           ┌─────────────────────────┐
         │        realtime_detect.py           │           │       app.py            │
         │                                     │           │      (Dashboard)        │
         │  ┌──────────────┐                   │           │                         │
         │  │ Load Model   │                   │           │  ┌─────────────────┐    │
         │  │ rf_model.    │                   │           │  │ load_packets()  │    │
         │  │ joblib       │                   │           │  └────────┬────────┘    │
         │  └──────┬───────┘                   │           │           │             │
         │         │                           │           │           ▼             │
         │         ▼                           │           │  ┌─────────────────┐    │
         │  ┌──────────────┐                   │           │  │ Display Table   │    │
         │  │ preprocess_  │                   │           │  │ + Charts        │    │
         │  │ row()        │                   │           │  └─────────────────┘    │
         │  └──────┬───────┘                   │           │                         │
         │         │                           │           └─────────────────────────┘
         │         ▼                           │
         │  ┌──────────────┐                   │
         │  │ clf.predict()│                   │
         │  └──────┬───────┘                   │
         │         │                           │
         │   Normal│Attack                     │
         │     ────┴────                       │
         │         │                           │
         │         ▼                           │
         │  ┌──────────────┐                   │
         │  │ check_ip_    │◀──────────────────┼───────┐
         │  │ abuse()      │                   │       │
         │  └──────┬───────┘                   │       │
         │         │                           │       │
         │         ▼                           │       │
         │  ┌──────────────┐                   │       │
         │  │ block_ip()   │                   │       │
         │  └──────┬───────┘                   │       │
         │         │                           │       │
         └─────────┼───────────────────────────┘       │
                   │                                   │
                   │ Write alerts                      │
                   ▼                                   │
         ┌─────────────────────┐                       │
         │    alerts.log       │───────────────────────┘
         └─────────────────────┘         Read by Dashboard
                   │
                   │ Firewall rule
                   ▼
         ┌─────────────────────┐
         │  Windows Firewall   │
         │  (netsh)            │
         └─────────────────────┘
```

---

## 11. Tips for Developers

### 🚀 Quick Start Commands

```bash
# One-time setup
python src/dataset_prep.py
python src/train_model.py

# Run all components (3 terminals)
python src/sniffer.py              # Terminal 1
python src/realtime_detect.py      # Terminal 2
streamlit run dashboard/app.py     # Terminal 3
```

### 📝 Common Modifications

**Add More Features to the Model:**
1. Update `features` list in `train_model.py`
2. Update `preprocess_row()` in `realtime_detect.py` to extract those features
3. Retrain the model

**Change Detection Threshold:**
```python
# In realtime_detect.py, change this line:
if abuse_result.get('abuseConfidenceScore', 0) >= 50:  # Change 50 to desired threshold
```

**Add Email Alerts:**
Add to `realtime_detect.py`:
```python
import smtplib
def send_email_alert(alert_message):
    # Your email sending code here
```

### ⚠️ Common Issues

| Issue | Solution |
|-------|----------|
| Sniffer not capturing | Run as Administrator (Windows) or with sudo (Linux) |
| TensorFlow errors | Use Python 3.11, not 3.12+ |
| Model not found | Run `train_model.py` first |
| Dashboard blank | Ensure `captured_packets.csv` exists |
| AbuseIPDB errors | Check API key is set correctly |

### 🔧 Extending the Project

**Ideas for Enhancement:**

1. **Deep Learning Model:** Replace Random Forest with a neural network using TensorFlow
2. **More Protocols:** Add support for DNS, HTTP, HTTPS payload analysis
3. **Cross-Platform Blocking:** Add iptables support for Linux
4. **Database Storage:** Replace CSV with SQLite or PostgreSQL
5. **Email/SMS Alerts:** Integrate with Twilio or SendGrid
6. **Geolocation Map:** Add a map visualization of attack sources
7. **Historical Analysis:** Add graphs showing attack trends over time

### 📚 Learning Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [scikit-learn User Guide](https://scikit-learn.org/stable/user_guide.html)
- [Streamlit Documentation](https://docs.streamlit.io/)
- [NSL-KDD Dataset Paper](https://www.unb.ca/cic/datasets/nsl.html)
- [AbuseIPDB API Docs](https://docs.abuseipdb.com/)

---

## Summary

The AI-IDPS project is a complete intrusion detection system with these key components:

| Component | File | Role |
|-----------|------|------|
| **Data Preparation** | `dataset_prep.py` | Downloads and preprocesses NSL-KDD |
| **Model Training** | `train_model.py` | Trains Random Forest classifier |
| **Packet Capture** | `sniffer.py` | Captures live network packets |
| **Threat Intel** | `threat_intel.py` | Queries AbuseIPDB API |
| **Detection Engine** | `realtime_detect.py` | Classifies and blocks threats |
| **Dashboard** | `app.py` | Web visualization interface |

The system works by:
1. Capturing network packets in real-time
2. Classifying each packet using a machine learning model
3. Checking suspicious IPs against threat intelligence databases
4. Automatically blocking high-risk IPs
5. Displaying everything on a live dashboard

---

<div align="center">

**Happy Hacking! 🛡️**

*This walkthrough was created to help developers understand and extend the AI-IDPS project.*

</div>
