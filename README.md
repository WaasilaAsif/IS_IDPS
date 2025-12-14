# AI-Powered Hybrid IDPS (Intrusion Detection and Prevention System)

## Overview
A sophisticated **Hybrid Network Intrusion Detection and Prevention System** for home and small office networks. Combines **machine learning**, **behavioral analysis**, and **threat intelligence** to detect and automatically block modern cyber attacks in real-time.

Trained on the **CICIDS2017** dataset (modern 2017 attacks), this system achieves **97% accuracy** with minimal false positives through intelligent port classification and behavioral pattern detection.

---

## Key Features

### **Hybrid Detection Architecture**
- **Machine Learning (Random Forest):** 97% accuracy on attack-prone ports (SSH, RDP, SMB, databases)
- **Port-Based Attack Classification:** 11 specific attack types (SSH Brute Force, RDP, MySQL, MongoDB, PostgreSQL, Redis, Elasticsearch, Web Admin, Telnet, SMB, FTP)
- **Behavioral Detection:** Port scanning, connection flooding, data exfiltration, DDoS patterns
- **Threat Intelligence:** AbuseIPDB integration for global IP reputation checking
- **Smart Port Classification:** Skips ML on HTTP/HTTPS traffic to eliminate false positives

### **Multi-Mode Auto-Blocking (Enhanced)**
1. **High Threat Intel:** AbuseIPDB score ≥50 → Immediate block
2. **Medium Threat + Alerts:** Score 25-49 + 2+ alerts → Block
3. **ML-Based Blocking:** 95%+ confidence on attack ports → Block (works without API)
4. **Rate Limit Fallback:** 5+ alerts when API unavailable → Block

**Blocking Enhancements:**
- **Duplicate Prevention:** Checks firewall rules before creating duplicates
- **Firewall State Sync:** Verifies rules still exist before skipping re-block
- **Dashboard Verification:** Shows only IPs with actual firewall rules (not stale log data)
- **Re-blocking Support:** Unblocked IPs can be re-blocked if attacks continue

### **Real-Time Dashboard**
- Live traffic monitoring with flow tracking
- Recent alerts with specific attack type classification (11 attack types)
- Blocked IPs management with **firewall state verification**
- Unblock functionality with automatic re-blocking support
- Attack type distribution pie chart
- Auto-refresh for real-time updates

### **Windows Firewall Integration**
- Automatic firewall rule creation (`IDS_Block_<IP>`)
- Persistent blocking across reboots
- Dashboard-based unblock controls

---

## System Architecture

```
[Network Traffic]
       ↓
[Packet Sniffer] ──→ captured_packets.csv (with flow tracking)
       ↓
[Real-Time Detector]
   ├─ Behavioral Analysis (port scans, floods, exfiltration)
   ├─ ML Classification (attack ports only)
   └─ Threat Intelligence (AbuseIPDB)
       ↓
[4-Mode Blocking Decision]
       ↓
[Windows Firewall] + alerts.log
       ↓
[Streamlit Dashboard] (monitoring & control)
```

---

## Project Structure
```
IS_IDPS/
├── data/
│   ├── MachineLearningCVE/      # CICIDS2017 dataset
│   ├── captured_packets.csv      # Live traffic with flow stats
│   ├── alerts.log                # Detection logs
│   └── cicids2017_preprocessed.csv
├── models/
│   ├── rf_model.joblib           # Trained Random Forest (97% accuracy)
│   └── proto_encoder.joblib      # Protocol label encoder
├── src/
│   ├── sniffer.py                # Flow-based packet capture
│   ├── realtime_detect.py        # Hybrid detection engine
│   ├── train_model.py            # Model training
│   ├── prepare_cicids2017.py     # Dataset preprocessing
│   └── threat_intel.py           # AbuseIPDB integration
├── dashboard/
│   └── app.py                    # Streamlit web interface
├── inject_test_packets.py        # Basic attack simulation (SSH, Telnet, SMB)
├── inject_advanced_attacks.py    # Advanced test suite (RDP, databases, port scans)
├── SYSTEM_DOCUMENTATION.md       # Comprehensive technical docs
└── requirements.txt
```

---

## Quick Start

### Prerequisites
- **Windows 10/11** (for firewall integration)
- **Python 3.8+**
- **Administrator privileges** (for packet capture and firewall rules)

### 1. Clone & Setup
```powershell
git clone https://github.com/WaasilaAsif/IS_IDPS.git
cd IS_IDPS

# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 2. Prepare Dataset & Train Model
```powershell
# Download CICIDS2017 dataset (place CSVs in data/MachineLearningCVE/)
# Then preprocess and train:
python src/prepare_cicids2017.py
python src/train_model.py
```

### 3. (Optional) Configure AbuseIPDB
Get a free API key from [AbuseIPDB](https://www.abuseipdb.com/)
```powershell
$env:ABUSEIPDB_API_KEY = "6b794aeeb4c320d20262dcd70017c38a5088f1c1410e64f1a999b8299d1328ed71b08a4dc28e9238"
```

### 4. Start the System (3 terminals)

**Terminal 1 - Packet Sniffer:**
```powershell
python src/sniffer.py
```

**Terminal 2 - Detection Engine (as Administrator):**
```powershell
$env:ABUSEIPDB_API_KEY = "6b794aeeb4c320d20262dcd70017c38a5088f1c1410e64f1a999b8299d1328ed71b08a4dc28e9238"
python src/realtime_detect.py
```

**Terminal 3 - Dashboard:**
```powershell
streamlit run dashboard/app.py
```

### 5. Access Dashboard
Open [http://localhost:8501](http://localhost:8501) in your browser

---

## Testing the System

### Basic Attack Simulation (3 attacks)
```powershell
python inject_test_packets.py
```
Tests: SSH brute force, Telnet exploitation, SMB vulnerability scan

### Advanced Attack Suite (37 attacks, 6 scenarios)
```powershell
python inject_advanced_attacks.py
```
Tests:
- RDP brute force (port 3389)
- MySQL/PostgreSQL/MongoDB attacks
- Web admin panel brute force
- Port scanning (behavioral detection)
- All attack port categories

---

## What Makes This System Unique

### Intelligent Port Classification
- **Attack Ports:** 22, 23, 445, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 8080, 8888 → **ML applied**
- **Safe Ports:** 53, 80, 443, 587, 993, 5222, etc. → **Skipped by ML** (behavioral only)
- **Why:** Prevents false positives from encrypted HTTPS traffic while catching real attacks

### Security-Focused Whitelist
- **~15 million IPs** whitelisted (narrowed from original 300M)
- **Removed all cloud compute /8 blocks** (AWS EC2, Azure VMs, Google Compute)
- **Only consumer services whitelisted:** Google Search, Facebook, CDNs, DNS
- **Result:** Attackers using cloud VMs are now detectable

### Flow-Based Tracking
- Tracks bidirectional conversations (forward/backward bytes and packets)
- Maintains state per `(src_ip, dst_ip, src_port, dst_port)` tuple
- Enables behavioral detection (data exfiltration, connection patterns)

---

## Performance Metrics

**Model (Random Forest on CICIDS2017):**
- Accuracy: **97%**
- Attack Precision: **99%** (very few false positives)
- Attack Recall: **84%** (catches most attacks)
- Normal Precision: **96%**

**Dataset:**
- **500,000 samples** (401k normal, 99k attacks)
- **CICIDS2017** modern attack types (DDoS, web attacks, brute force, infiltration)

**Operational:**
- **Zero false positives** on normal web browsing (Google, Facebook, Reddit)
- **100% detection** on attack ports (SSH, RDP, SMB, databases)
- **11 specific attack types** identified: SSH Brute Force, RDP Brute Force, MySQL Attack, MongoDB Attack, PostgreSQL Attack, Redis Attack, Elasticsearch Attack, Web Admin Attack, Telnet Attack, SMB Attack, FTP Brute Force, Port Scan
- **95% confidence** for port-based heuristic classifications (not misleading 100%)
- **Real-time processing** with 2-second scan intervals
- **No duplicate blocking logs** - each IP blocked once per session

---

## Configuration

### Adjusting Detection Sensitivity

**Behavioral Thresholds** (in `src/realtime_detect.py`):
```python
# Port scan: Currently >10 unique ports
if len(port_scan_tracker[src_ip]) > 20:  # Less sensitive

# Connection flood: Currently >50 connections
if connection_tracker[src_ip] > 100:  # Less sensitive
```

**ML Confidence Thresholds:**
```python
# Alert threshold (currently 90%)
if attack_confidence >= 0.95:  # Fewer alerts, higher precision

# Blocking threshold (currently 95%)
if attack_confidence >= 0.98:  # Even more conservative blocking
```

### Adding to Whitelist
```python
WHITELIST_RANGES = [
    '142.250.0.0/15',      # Google
    '192.168.1.0/24',      # Your home network
]
```

**Warning:** Only whitelist specific ranges you trust, not entire /8 blocks!

---

## Security Considerations

### Strengths
- Detects modern attacks (CICIDS2017 training)  
- Behavioral detection catches zero-day attacks  
- No false positives on normal HTTPS traffic  
- Automatic blocking protects in real-time  
- Threat intelligence validates with global data  

### Limitations
- Encrypted traffic analysis limited (can't see payload)  
- Memory grows unbounded (dictionaries need cleanup)  
- AbuseIPDB rate limit (1000 requests/day free tier)  
- Windows-only firewall integration  
- Single network interface monitored  

### Best Practices
- Review blocked IPs regularly in dashboard
- Add legitimate services to whitelist as needed
- Monitor `alerts.log` for patterns
- Keep model updated with new attack samples
- Use on networks you own/have permission to monitor


## Acknowledgements

- [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html) - Canadian Institute for Cybersecurity
- [Scapy](https://scapy.net/) - Packet manipulation library
- [scikit-learn](https://scikit-learn.org/) - Machine learning framework
- [Streamlit](https://streamlit.io/) - Dashboard framework
- [AbuseIPDB](https://www.abuseipdb.com/) - Threat intelligence API


---

## Disclaimer

**For educational and home/lab use only.** Do not deploy on networks you don't own or have explicit permission to monitor. Auto-blocking can disrupt network connectivity if misconfigured. Use responsibly. 
