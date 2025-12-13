# IDPS System Documentation

## Table of Contents
1. [System Overview](#system-overview)
2. [Architecture & Data Flow](#architecture--data-flow)
3. [Dataset & Preprocessing](#dataset--preprocessing)
4. [Components](#components)
   - [Packet Sniffer](#1-packet-sniffer-srcsnifferpy)
   - [Real-time Detection Engine](#2-real-time-detection-engine-srcrealtime_detectpy)
   - [Machine Learning Model](#3-machine-learning-model-modelsrf_modeljoblib)
   - [Model Training](#4-model-training-srctrainmodelpy)
   - [Dashboard](#5-dashboard-dashboardapppy)
   - [Test Injection](#6-test-injection-inject_test_packetspy)
5. [Detection Mechanisms](#detection-mechanisms)
6. [Blocking Logic](#blocking-logic)
7. [Configuration & Tuning](#configuration--tuning)

---

## System Overview

This is a **Hybrid Network Intrusion Detection and Prevention System (IDPS)** that combines:
- **Flow-based traffic monitoring** - Tracks bidirectional conversations between hosts
- **Behavioral anomaly detection** - Identifies suspicious patterns (port scanning, connection flooding, data exfiltration)
- **Machine Learning classification** - Uses Random Forest trained on CICIDS2017 dataset to detect attacks
- **Automated blocking** - Integrates with Windows Firewall to block malicious IPs
- **Threat intelligence** - Queries AbuseIPDB for reputation scoring
- **Real-time dashboard** - Streamlit web interface for monitoring and manual control

**Key Design Philosophy:**
- **Hybrid Detection**: ML is NOT applied to normal HTTP/HTTPS traffic (ports 80/443) to prevent false positives on encrypted connections. Instead, behavioral detection monitors for anomalies.
- **Attack-Focused ML**: Machine learning only analyzes traffic on attack-prone ports (SSH, Telnet, SMB, RDP, databases) where signature patterns are more reliable.
- **Defense in Depth**: Multiple blocking triggers (threat intelligence, ML confidence, alert accumulation, behavioral patterns) provide layered security.

---

## Architecture & Data Flow

```
[Network Traffic]
       ↓
[Packet Sniffer (sniffer.py)]
  - Captures packets via Scapy
  - Tracks flows (src→dst, dst→src)
  - Accumulates bytes/packets per flow
  - Writes to captured_packets.csv
       ↓
[Real-time Detector (realtime_detect.py)]
  - Reads new packets from CSV
  - Behavioral Analysis:
    * Port scan detection
    * Connection flood detection
    * Data exfiltration detection
    * Tiny packet flood detection
  - ML Classification (attack ports only):
    * Loads RandomForest model
    * Predicts attack probability
    * 90% confidence threshold for alerts
  - Threat Intelligence:
    * Queries AbuseIPDB API
    * Gets abuse confidence score
  - Blocking Decision:
    * 4-mode hybrid logic
    * Creates Windows Firewall rules
  - Logs alerts to alerts.log
       ↓
[Dashboard (app.py)]
  - Displays live traffic
  - Shows recent alerts
  - Lists blocked IPs
  - Manual blocking controls
  - Auto-refreshes every few seconds
```

---

## Dataset & Preprocessing

### CICIDS2017 Dataset

**Source:** Canadian Institute for Cybersecurity (2017)

**Content:**
- **2.8 million network flows** captured over 5 days
- **Modern attack types:** DDoS, web attacks, brute force, infiltration, botnets, port scans
- **85 features** including flow duration, packet counts, byte counts, inter-arrival times, flags, etc.

**Included Attack Types:**
- DoS/DDoS (Hulk, GoldenEye, Slowloris, Slowhttptest)
- SSH Brute Force
- FTP Brute Force
- Web attacks (SQL injection, XSS)
- Infiltration attacks
- Botnet traffic
- Port scanning

### Preprocessing Pipeline (`src/prepare_cicids2017.py`)

**Purpose:** Convert raw CICIDS2017 CSV files into simplified 3-feature format compatible with the IDPS.

**Process:**
1. **File Discovery:** Recursively searches `data/MachineLearningCVE/` for all CSV files using `os.walk()`
2. **Protocol Inference:** CICIDS2017 lacks explicit protocol field, so it's inferred from destination ports:
   - Ports 22, 23, 80, 443, 445, etc. → `tcp`
   - Ports 53, 67, 123, 161 → `udp`
   - Port 0 → `icmp`
3. **Feature Extraction:**
   - `protocol_type`: Encoded protocol (tcp/udp/icmp)
   - `src_bytes`: Total bytes sent from source (Forward Packet Length)
   - `dst_bytes`: Total bytes received at destination (Backward Packet Length)
   - `label`: BENIGN (normal) or attack type
4. **Label Normalization:** All non-BENIGN labels converted to `attack`
5. **Balancing:** Samples 500k rows if dataset exceeds this size (maintains class balance)
6. **Output:** `cicids2017_preprocessed.csv` with clean, consistent format

**Why Only 3 Features?**
- **Simplicity:** Easier to capture in real-time (no complex statistical calculations needed)
- **Performance:** Fast processing for real-time detection
- **Effectiveness:** 97% accuracy with just protocol + byte counts proves sufficient
- **Real-time Compatibility:** Sniffer can track these features with minimal overhead

---

## Components

### 1. Packet Sniffer (`src/sniffer.py`)

**Purpose:** Capture all network packets and track bidirectional flow statistics.

**How It Works:**

1. **Packet Capture:**
   - Uses **Scapy** library to sniff network interfaces
   - Captures IP packets only (filters out non-IP traffic)
   - Runs continuously in background

2. **Flow Tracking:**
   - Maintains a **dictionary of active flows** keyed by `(src_ip, dst_ip, src_port, dst_port)`
   - For each flow, tracks:
     - `fwd_bytes`: Bytes sent from source to destination
     - `bwd_bytes`: Bytes sent from destination back to source
     - `fwd_packets`: Packet count source→destination
     - `bwd_packets`: Packet count destination→source
     - `total_bytes`: Sum of forward and backward bytes

3. **Direction Detection:**
   - First packet in a flow establishes direction
   - Subsequent packets check if they match original direction or reverse direction
   - Forward packets increment `fwd_bytes` and `fwd_packets`
   - Backward packets increment `bwd_bytes` and `bwd_packets`

4. **Output:**
   - Writes each packet to `captured_packets.csv` with columns:
     - `timestamp`: ISO format datetime
     - `src_ip`: Source IP address
     - `dst_ip`: Destination IP address
     - `src_port`: Source port (0 if ICMP)
     - `dst_port`: Destination port (0 if ICMP)
     - `protocol`: tcp/udp/icmp
     - `length`: Packet size in bytes
     - `fwd_bytes`: Cumulative forward bytes for this flow
     - `bwd_bytes`: Cumulative backward bytes for this flow

**Key Features:**
- **Real-time flow awareness:** Unlike simple packet capture, maintains state of conversations
- **Bidirectional tracking:** Understands request/response patterns
- **Persistent logging:** All traffic recorded for analysis and training

**Limitations:**
- **Memory growth:** Flow dictionary grows unbounded (no cleanup of old flows)
- **CSV bloat:** captured_packets.csv grows infinitely (no log rotation)
- **Single-threaded:** Processes packets sequentially (could drop packets under high load)

---

### 2. Real-time Detection Engine (`src/realtime_detect.py`)

**Purpose:** Analyze captured packets for malicious behavior and automatically block threats.

This is the **core intelligence** of the IDPS. It implements a sophisticated hybrid detection system.

#### Initialization Phase

1. **Model Loading:**
   - Loads `rf_model.joblib` (Random Forest classifier)
   - Loads `proto_encoder.joblib` (LabelEncoder for protocol strings)

2. **Whitelist Configuration (Narrowed for Security):**
   - Defines **WHITELIST_RANGES** covering ~15 million IPs (narrowed from original ~300 million):
     - **Google services only** (142.250.0.0/15, 172.217.0.0/16, 216.58.192.0/19, 108.177.0.0/16)
     - **Google DNS** (8.8.8.0/24, 8.8.4.0/24)
     - **Facebook/Meta** (157.240.0.0/16, 31.13.0.0/16, 69.63.0.0/16, 66.220.0.0/16, 173.252.0.0/16)
     - **Microsoft consumer services** (13.107.0.0/16, 40.96.0.0/13, 40.104.0.0/15, 52.96.0.0/14, 104.40.0.0/13, 137.116.0.0/16, 168.61.0.0/16, 199.30.16.0/20)
     - **GitHub** (140.82.0.0/16, 185.199.0.0/16, 192.30.252.0/22)
     - **Cloudflare CDN/DNS** (104.16.0.0/13, 172.64.0.0/13, 1.1.1.0/24, 1.0.0.0/24)
     - **Akamai CDN** (104.64.0.0/11, 23.0.0.0/12)
     - **Fastly CDN** (151.101.0.0/16, 146.75.0.0/16, 199.232.0.0/16)
     - **Public DNS** (9.9.9.9/32 Quad9, 208.67.222.222/32 OpenDNS - specific IPs only)
     - **Private networks** (192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12)
   - **Purpose:** Prevent false positives from legitimate services WITHOUT whitelisting entire cloud compute ranges
   - **Security improvement:** Removed AWS EC2, Azure VMs, Google Cloud Compute /8 blocks - attackers using cloud VMs are now detectable
   - **What was removed:** ~285 million IPs including all /8 blocks for AWS (3.0.0.0/8, 15.0.0.0/8, 18.0.0.0/8, 54.0.0.0/8), Azure (4.0.0.0/8, 20.0.0.0/8, 40.0.0.0/8, 51.0.0.0/8, 52.0.0.0/8), Google Cloud (34.0.0.0/8, 35.0.0.0/8), and overly broad ranges

3. **Port Classification:**
   - **ATTACK_PORTS:** {22, 23, 445, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 8080, 8888}
     - SSH, Telnet, SMB, RDP, database servers, web admin panels
     - **ML is applied** to traffic on these ports
   - **WEB_PORTS:** {80, 443}
     - Standard HTTP/HTTPS
     - **ML is skipped** (behavioral detection only)
   - **SAFE_PORTS:** {53, 853, 5353, 123, 443, 80, 993, 995, 587, 465, 110, 143, 5222, 8443}
     - DNS (53), DNS-over-TLS (853), mDNS (5353), NTP (123)
     - Mail servers (993 IMAPS, 995 POP3S, 587 SMTP submission, 465 SMTPS, 110 POP3, 143 IMAP)
     - XMPP chat (5222), secure web (8443)
     - **Completely skipped** by ML - checked on both source AND destination ports
     - **Prevents false positives** from DNS responses, time sync, email traffic

4. **State Tracking:**
   - `alert_counter`: Counts alerts per IP (for blocking threshold)
   - `connection_tracker`: Counts connections per IP (for flood detection)
   - `port_scan_tracker`: Tracks unique destination ports per IP (for port scan detection)
   - `last_seen`: File position for incremental CSV reading

#### Detection Loop

Runs continuously, checking for new packets in `captured_packets.csv`:

**Step 1: Read New Packets**
- Uses `last_seen` to read only new lines (incremental processing)
- Skips whitelisted IPs immediately

**Step 2: Behavioral Analysis**

Runs **before** ML, on **all traffic** (including HTTP/HTTPS):

1. **Port Scan Detection:**
   - Tracks unique destination ports per source IP
   - **Trigger:** More than 10 unique ports accessed by single IP
   - **Rationale:** Attackers probe services to find vulnerabilities

2. **Connection Flood Detection:**
   - Counts total connections per source IP
   - **Trigger:** More than 50 connections from single IP
   - **Rationale:** DDoS, brute force, or botnet behavior

3. **Data Exfiltration Detection (Web Ports Only):**
   - Sums total bytes transferred on ports 80/443
   - **Trigger:** More than 100 MB from single IP on web ports
   - **Rationale:** Large uploads could indicate data theft

4. **Tiny Packet Flood Detection (Web Ports Only):**
   - Counts packets smaller than 100 bytes on ports 80/443
   - **Trigger:** More than 20 tiny packets from single IP
   - **Rationale:** Slowloris-style attacks using many small requests

**Step 3: Machine Learning Classification**

Only runs on **suspicious traffic**:
- Traffic on ATTACK_PORTS (22, 23, 445, etc.)
- Traffic on non-standard ports (not 80, 443, or common safe ports)

**ML Process:**
1. **Preprocessing:**
   - Encodes protocol string using LabelEncoder
   - Extracts features: `protocol_type`, `src_bytes` (fwd_bytes), `dst_bytes` (bwd_bytes)
2. **Prediction:**
   - `model.predict_proba()` returns probability of [normal, attack]
   - Attack confidence = probability of attack class
3. **Alert Threshold:**
   - **90% confidence:** Log alert
   - **95% confidence + attack port:** Flag for blocking

**Step 4: Threat Intelligence**

For each alert (if AbuseIPDB API available):
1. Queries `https://api.abuseipdb.com/api/v2/check`
2. Gets abuse confidence score (0-100)
3. Checks recent reports count
4. **Rate Limit Handling:** If 429 error, silently skips API check (falls back to ML-only blocking)

**Step 5: Blocking Decision**

Four modes (evaluated in order):

1. **Mode 1: High Abuse Score**
   - AbuseIPDB score ≥ 50
   - **Action:** Immediate block (known malicious IP)

2. **Mode 2: Medium Abuse + Alert Accumulation**
   - AbuseIPDB score 25-49 AND IP has 2+ alerts
   - **Action:** Block (suspicious IP with repeated offense)

3. **Mode 3: ML-Based Blocking (No API Required)**
   - Attack confidence ≥ 95% AND traffic on attack port
   - **Action:** Block (high confidence attack on vulnerable service)
   - **This mode works even when AbuseIPDB is rate-limited**

4. **Mode 4: Rate Limit Fallback**
   - AbuseIPDB unavailable (rate limited) AND IP has 5+ alerts
   - **Action:** Block (repeated suspicious behavior)

**Step 6: Logging**
- Writes to `alerts.log` with format:
  ```
  [TIMESTAMP] ALERT: 192.168.1.100 → 10.0.0.50:22 | ML Confidence: 100.0% | Abuse Score: 75 | Reason: SSH Brute Force | AUTO-BLOCKED: High abuse score
  ```

#### Key Functions

**`preprocess_row(row)`**
- Converts DataFrame row to model input format
- Encodes protocol string to integer
- Returns: `[protocol_type, fwd_bytes, bwd_bytes]`

**`is_whitelisted(ip)`**
- Checks if IP falls in any WHITELIST_RANGES
- Uses `ipaddress` module for CIDR matching
- Returns: `True` if safe, `False` if should be analyzed

**`block_ip(ip, reason)`**
- Creates Windows Firewall rule using `netsh advfirewall`
- Rule name: `IDS_Block_{ip}`
- Direction: Inbound
- Action: Block all traffic from IP
- Checks if rule already exists (avoids duplicate blocks)

**`check_ip_abuse(ip, api_key)`**
- Queries AbuseIPDB API v2
- Returns: `(abuse_score, is_malicious, total_reports)` or `(0, False, 0)` if unavailable
- Handles rate limits gracefully (returns zeros instead of crashing)

---

### 3. Machine Learning Model (`models/rf_model.joblib`)

**Algorithm:** Random Forest Classifier (Ensemble Learning)

**Training Data:** 500,000 samples from CICIDS2017
- 401,000 normal traffic samples
- 99,000 attack samples

**Features (3):**
1. `protocol_type`: Encoded integer (0=tcp, 1=udp, 2=icmp)
2. `src_bytes`: Total bytes sent source→destination (forward bytes)
3. `dst_bytes`: Total bytes sent destination→source (backward bytes)

**Performance Metrics:**
- **Accuracy:** 97%
- **Attack Precision:** 99% (very few false positives on attacks)
- **Attack Recall:** 84% (misses some attacks, but catches most)
- **Normal Precision:** 96% (correctly identifies normal traffic)

**Why Random Forest?**
- **Ensemble method:** Combines multiple decision trees for robustness
- **Non-linear:** Captures complex patterns in traffic
- **Interpretable:** Can analyze feature importance
- **Fast prediction:** Suitable for real-time processing

**Model Behavior:**
- Traffic on port 22 (SSH) with large byte counts → High attack probability
- Port 23 (Telnet) traffic → High attack probability (Telnet is inherently insecure)
- Port 445 (SMB) traffic → High attack probability (common ransomware vector)
- HTTP/HTTPS traffic → **Not evaluated by model** (behavioral detection only)

**Companion File:** `proto_encoder.joblib`
- LabelEncoder that maps: tcp→0, udp→1, icmp→2
- Must be applied before passing data to model

---

### 4. Model Training (`src/train_model.py`)

**Purpose:** Train the Random Forest model on CICIDS2017 dataset.

**Process:**

1. **Load Preprocessed Data:**
   - Reads `cicids2017_preprocessed.csv`
   - 500k samples with 3 features + label

2. **Encode Protocol:**
   - Uses `LabelEncoder` to convert tcp/udp/icmp to integers
   - Saves encoder to `proto_encoder.joblib`

3. **Split Dataset:**
   - 80% training, 20% testing
   - `random_state=42` for reproducibility

4. **Train Random Forest:**
   - `n_estimators=100` (100 decision trees)
   - `random_state=42`
   - Fits on training data

5. **Evaluate:**
   - Predicts on test set
   - Calculates accuracy, precision, recall, F1-score
   - Prints classification report

6. **Save Model:**
   - Exports to `models/rf_model.joblib`
   - Can be loaded instantly by detector

**When to Retrain:**
- After collecting more real-world attack samples
- If false positive rate increases
- When new attack types emerge
- After significant changes to network environment

---

### 5. Dashboard (`dashboard/app.py`)

**Purpose:** Streamlit web interface for monitoring and control.

**Technology:** Streamlit (Python web framework)

**Components:**

#### A. Live Traffic Monitor (Left Column)
- **Data Source:** `captured_packets.csv`
- **Display:** Last 20 packets in table format
- **Columns:** Timestamp, Source IP, Destination IP, Dest Port, Protocol, Bytes
- **Auto-refresh:** Updates every few seconds

#### B. Recent Alerts (Right Column)
- **Data Source:** `alerts.log`
- **Display:** Last 15 alerts
- **Format:** Color-coded by severity
  - Red: High confidence attacks (>95%)
  - Orange: Medium confidence (80-95%)
  - Yellow: Low confidence (70-80%)
- **Information:** Source IP, destination, port, ML confidence, abuse score, reason, blocking status

#### C. IP Block Management Section (Full Width)
- **Data Source:** Parses `alerts.log` for "AUTO-BLOCKED" and "UNBLOCKED" entries
- **Display:** Separate sections for blocked vs unblocked IPs
- **Status Indicators:**
  - 🔴 BLOCKED (red) - Currently blocked IPs with active firewall rules
  - ⚪ UNBLOCKED (white) - Previously blocked but manually unblocked IPs
- **Content:**
  - Total count: "Currently blocked: X IPs | Previously unblocked: Y IPs"
  - Expandable cards per IP showing block reason
  - **Unblock button** for each blocked IP
- **Unblock Functionality:**
  - Removes Windows Firewall rule via `netsh advfirewall firewall delete rule`
  - Logs unblock action to `alerts.log` with timestamp
  - Auto-refreshes dashboard to show updated status
  - Handles "rule not found" gracefully (treats as success if already removed)
- **Deduplication:** Shows each IP only once, tracks latest status (blocked or unblocked)

#### D. Manual Block Interface
- **Input:** Text field for IP address
- **Action:** Button to manually block IP
- **Validation:** Checks if IP already blocked
- **Logging:** Adds manual block entry to alerts.log

**Key Functions:**

**`load_alerts()`**
- Reads last 200 lines of `alerts.log`
- Parses each line with regex to extract fields
- Returns DataFrame with alert details

**`load_blocked_ips()`**
- Searches `alerts.log` for "AUTO-BLOCKED:" and "UNBLOCKED:" strings
- Extracts IP address and block reason from AUTO-BLOCKED lines
- Tracks unblocked IPs from UNBLOCKED lines
- Uses dictionary to deduplicate (IP as key)
- Returns list of `{ip: str, reason: str, is_blocked: bool}` objects
- `is_blocked=True` if IP in blocked list and NOT in unblocked set
- `is_blocked=False` if IP has been manually unblocked

**`unblock_ip(ip)`**
- Removes Windows Firewall rule: `netsh advfirewall firewall delete rule name="IDS_Block_{ip}"`
- Logs unblock action: "UNBLOCKED: {ip} - Manually unblocked from dashboard at {timestamp}"
- Returns `(True, message)` on success (including if rule already removed)
- Returns `(False, error)` on failure
- Handles "No rules match" as success (IP effectively unblocked)

**`block_ip_dashboard(ip, reason)`**
- Wrapper for blocking from UI
- Calls `netsh advfirewall` command
- Logs manual block to alerts.log

**Access:** `http://localhost:8501`

---

### 6. Test Injection (`inject_test_packets.py`)

**Purpose:** Generate synthetic packets for testing detection system by writing directly to CSV (bypasses network layer).

**Attack Simulations:**

1. **SSH Brute Force Attack (Port 22):**
   - Source: 185.220.101.1 (Tor exit node)
   - Destination: 192.168.10.138
   - Protocol: TCP
   - Bytes: 60 fwd, 0 bwd (one-way SYN packet, no response)
   - **Attack Type:** SSH brute force / unauthorized access attempt
   - **Real-world equivalent:** Attackers scanning for weak SSH passwords
   - **Detection reason:** Port 22 in ATTACK_PORTS, small packet size typical of reconnaissance probes

2. **Telnet Exploitation Attempt (Port 23):**
   - Source: 185.220.101.1 (Tor exit node)
   - Destination: 192.168.10.138
   - Protocol: TCP
   - Bytes: 60 fwd, 0 bwd
   - **Attack Type:** Telnet vulnerability exploitation
   - **Real-world equivalent:** IoT botnet scanning (Mirai malware targets Telnet)
   - **Detection reason:** Port 23 extremely suspicious (Telnet sends passwords in plaintext, obsolete protocol)

3. **SMB/WannaCry Vulnerability Scan (Port 445):**
   - Source: 185.220.101.2 (Tor exit node)
   - Destination: 192.168.10.138
   - Protocol: TCP
   - Bytes: 60 fwd, 0 bwd
   - **Attack Type:** SMB vulnerability exploitation (EternalBlue/WannaCry vector)
   - **Real-world equivalent:** WannaCry, NotPetya, and other ransomware spread via SMB
   - **Detection reason:** Port 445 high-risk, used by ransomware for lateral movement

**Common Attack Pattern:**
- `fwd_bytes: 60, bwd_bytes: 0` - **One-way traffic with no response**
- Simulates **connection attempts to closed/filtered ports**
- Typical of **reconnaissance/scanning** behavior (not legitimate communication)

**Expected Results:**
- All three packets flagged with **100% attack confidence**
- IPs 185.220.101.1 and 185.220.101.2 blocked (Mode 3: ML-based blocking on attack ports)
- Alerts logged with "High confidence attack on sensitive port" reason

**Usage:**
```bash
python inject_test_packets.py
```

**Important Notes:**
- **Bypasses network layer:** Writes directly to `captured_packets.csv`, not real packets
- **Tests detection logic only:** Does NOT test firewall blocking effectiveness
- **Firewall blocking works differently:** Real blocked IPs are dropped at kernel level before sniffer sees them
- **Why IPs show alerts repeatedly:** Inject script bypasses firewall, detector processes CSV entries regardless of firewall rules

**Why 100% Confidence:**
- Attack-prone ports (22, 23, 445) in ATTACK_PORTS set
- Low byte counts (60) match CICIDS2017 attack patterns for port scans
- No bidirectional communication (scanning behavior, not normal traffic)
- Model trained on 500k samples recognizes this as reconnaissance activity

---

### 7. Advanced Attack Simulations (`inject_advanced_attacks.py`)

**Purpose:** Comprehensive attack testing suite covering 6 different modern attack scenarios. Tests detection across multiple attack vectors and behavioral patterns.

**Attack Scenarios (37 total packets):**

#### 1. RDP Brute Force Attack (Port 3389) - 5 packets
```python
Source: 45.142.214.123
Pattern: Multiple connection attempts with small packets (54 bytes)
```
- **Attack Type:** Remote Desktop Protocol credential stuffing
- **Real-world:** Ransomware groups (Conti, REvil) exploit RDP vulnerabilities
- **Detection:** ML recognizes repeated connection attempts on port 3389
- **Why detected:** RDP is critical infrastructure service, small packets indicate authentication attempts

#### 2. MySQL Database Attack (Port 3306) - 3 packets
```python
Source: 103.85.24.155
Pattern: Varying packet sizes (78-120 bytes) simulating SQL queries
```
- **Attack Type:** SQL injection / unauthorized database access
- **Real-world:** Data breach attempts, credential harvesting from databases
- **Detection:** Port 3306 in ATTACK_PORTS, multiple queries from single IP
- **Why detected:** Direct database access from external IP, query-like patterns

#### 3. MongoDB NoSQL Injection (Port 27017) - 2 packets
```python
Source: 217.12.204.100
Pattern: Large payload packets (250-310 bytes) with code injection attempts
```
- **Attack Type:** NoSQL database exploitation
- **Real-world:** Modern database attacks targeting MongoDB instances (ransomware, data theft)
- **Detection:** Port 27017 in ATTACK_PORTS, large payloads indicate injection attempts
- **Why detected:** MongoDB exposed to internet is high-risk, large packets suggest malicious payloads

#### 4. Web Admin Panel Brute Force (Port 8080) - 8 packets
```python
Source: 91.201.67.89
Pattern: 8 consecutive POST requests with incrementing sizes (85-120 bytes)
```
- **Attack Type:** Admin panel credential brute force
- **Real-world:** Compromising web application admin panels (WordPress, phpMyAdmin, custom panels)
- **Detection:** Port 8080 in ATTACK_PORTS, repeated authentication attempts
- **Why detected:** Multiple login attempts in rapid succession, classic brute force pattern

#### 5. Port Scanning Reconnaissance (Multiple Ports) - 16 packets
```python
Source: 159.89.133.22
Pattern: Single IP probing 16 different ports (21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8888, 9200)
```
- **Attack Type:** Network reconnaissance / service discovery
- **Real-world:** Nmap scan, Masscan, automated vulnerability scanning (Shodan, Censys)
- **Detection:** **BEHAVIORAL ALERT** - >10 unique ports from single IP triggers port scan detection
- **Why detected:** Legitimate users don't probe multiple services; this is reconnaissance phase before exploitation
- **Special note:** This is the **only attack that triggers behavioral detection** in addition to ML

#### 6. PostgreSQL Database Breach (Port 5432) - 3 packets
```python
Source: 188.166.123.45
Pattern: Multiple authentication attempts with varying packet sizes (88-95 bytes)
```
- **Attack Type:** Database credential stuffing
- **Real-world:** Targeting exposed PostgreSQL instances for data theft
- **Detection:** Port 5432 in ATTACK_PORTS, repeated connection attempts
- **Why detected:** PostgreSQL should not be exposed to internet, multiple auth attempts indicate brute force

**Attack Breakdown:**
```
Total Packets: 37
Total IPs: 6 (all should be blocked)

Distribution:
  • RDP Brute Force (3389):     5 packets
  • MySQL Attacks (3306):       3 packets
  • MongoDB Injection (27017):  2 packets
  • Web Admin Brute (8080):     8 packets
  • Port Scanning (multi):      16 packets (BEHAVIORAL + ML)
  • PostgreSQL Breach (5432):   3 packets
```

**Expected Detection Results:**
- **ML Detection:** All packets trigger 90-100% confidence on attack ports
- **Behavioral Detection:** Port scanning IP (159.89.133.22) triggers "Port scan detected from X - 16 unique ports"
- **Auto-Blocking:** All 6 IPs blocked via Mode 3 (ML high confidence ≥95% on dangerous ports)
- **No False Positives:** Zero legitimate traffic flagged

**Usage:**
```bash
python inject_advanced_attacks.py
```

**Testing Coverage:**
This script comprehensively tests:
1. **Database security** (MySQL, MongoDB, PostgreSQL)
2. **Remote access security** (RDP)
3. **Web application security** (admin panels)
4. **Reconnaissance detection** (port scanning)
5. **ML classification** across all attack port categories
6. **Behavioral pattern detection** (scanning behavior)

**Difference from inject_test_packets.py:**
- `inject_test_packets.py`: Basic attacks (SSH, Telnet, SMB) - 3 packets, 2 IPs
- `inject_advanced_attacks.py`: Comprehensive suite - 37 packets, 6 IPs, multiple attack types
- Use basic for quick testing, advanced for thorough validation

**Why These Attacks Matter:**
- **RDP/SSH/Telnet:** Most common entry points for ransomware
- **Databases (MySQL/PostgreSQL/MongoDB):** High-value targets for data breaches
- **Web admin panels:** Gateway to full application compromise
- **Port scanning:** Reconnaissance phase that precedes all targeted attacks

**Validation Checklist:**
After running, verify in dashboard:
- ✅ 6 IPs in "Blocked IPs" section
- ✅ 37+ alerts in "Recent Alerts" (may be more due to repeated blocking logs)
- ✅ Port scan behavioral alert for 159.89.133.22
- ✅ 100% ML confidence on all attacks
- ✅ All blocks via "ML high confidence on dangerous port" reason

---

## Detection Mechanisms

### 1. Behavioral Detection (Pattern-Based)

**Philosophy:** Detect anomalies in connection patterns regardless of packet content.

**Advantages:**
- Works on encrypted traffic (HTTPS, SSH)
- No false positives from legitimate services
- Catches zero-day attacks (no signature needed)
- Fast (no ML computation)

**Techniques:**

#### Port Scanning Detection
- **Pattern:** Single IP probing many different ports
- **Threshold:** >10 unique destination ports
- **Attackers:** Reconnaissance phase of attack (looking for open services)
- **Example:** Nmap scan, Masscan

#### Connection Flooding Detection
- **Pattern:** Excessive connections from single IP
- **Threshold:** >50 connections
- **Attackers:** DDoS, brute force (trying many passwords), botnet C2 check-ins
- **Example:** SYN flood, HTTP flood

#### Data Exfiltration Detection
- **Pattern:** Large outbound data transfer on web ports
- **Threshold:** >100 MB total bytes on ports 80/443
- **Attackers:** Malware uploading stolen data, compromised server
- **Example:** Database dump uploaded to attacker server via POST request

#### Tiny Packet Flood Detection
- **Pattern:** Many small packets on web ports
- **Threshold:** >20 packets <100 bytes on ports 80/443
- **Attackers:** Slowloris, Slow HTTP attacks
- **Example:** Opening many connections with minimal data to exhaust server resources

### 2. Machine Learning Detection (Signature-Based)

**Philosophy:** Learn attack signatures from training data, apply to similar traffic.

**Advantages:**
- High precision on known attack types
- Can distinguish attack variants
- Quantifiable confidence score

**Limitations:**
- Only works on traffic patterns similar to training data
- Struggles with encrypted traffic (can't see payload)
- False positives on unusual but legitimate traffic

**Application Strategy:**
- **Applied to:** Attack-prone ports (SSH, Telnet, SMB, RDP, databases)
- **Skipped on:** Normal web traffic (HTTP/HTTPS)
- **Reason:** Modern web traffic is encrypted and highly variable (TLS handshakes, keepalives, HTTP/2 multiplexing) - doesn't match clean lab attack signatures

**Confidence Thresholds:**
- **90%:** Log alert, track for blocking threshold
- **95%:** Eligible for immediate ML-based blocking (Mode 3)

### 3. Threat Intelligence (Reputation-Based)

**Philosophy:** Leverage global data about known malicious IPs.

**Source:** AbuseIPDB (community-driven IP reputation database)

**Advantages:**
- Instant blocking of known attackers
- Crowd-sourced intelligence from thousands of networks
- Updated continuously

**Limitations:**
- API rate limits (1000 requests/day on free tier)
- Zero-day attacks not in database
- False positives from shared IPs (VPNs, Tor exits)

**Integration:**
- Query after ML generates alert
- Abuse score 0-100 (percentage of malicious reports)
- Scores ≥50 trigger immediate block
- Scores 25-49 contribute to multi-alert blocking

---

## Blocking Logic

### Four-Mode Hybrid System

**Design Rationale:** Defense in depth - multiple paths to blocking ensures threats don't slip through.

#### Mode 1: High Abuse Score (Threat Intel Priority)
```
IF abuse_score >= 50:
    BLOCK("High abuse score")
```
- **Purpose:** Immediately block IPs with strong malicious reputation
- **Confidence:** Very high (crowd-sourced global data)
- **Typical IPs:** Known botnets, scanning hosts, compromised servers

#### Mode 2: Medium Abuse + Alert Accumulation (Threat Intel + Local Evidence)
```
IF 25 <= abuse_score < 50 AND alert_counter[ip] >= 2:
    BLOCK("Suspicious IP with repeated offense")
```
- **Purpose:** Block moderately suspicious IPs after local confirmation
- **Confidence:** High (external + internal evidence)
- **Typical IPs:** VPNs used by attackers, newly compromised hosts

#### Mode 3: ML-Based Blocking (Independent ML Decision)
```
IF attack_confidence >= 95% AND dst_port IN ATTACK_PORTS:
    BLOCK("High confidence attack on sensitive port")
```
- **Purpose:** Block obvious attacks even without threat intel
- **Confidence:** Very high (95%+ from model trained on 500k samples)
- **Typical IPs:** Zero-day attacks, private botnets not yet reported
- **Critical Feature:** **Works without AbuseIPDB** (not rate-limited)

#### Mode 4: Rate Limit Fallback (Local Evidence Only)
```
IF abuseipdb_unavailable AND alert_counter[ip] >= 5:
    BLOCK("Repeated alerts during API unavailability")
```
- **Purpose:** Maintain blocking capability when threat intel fails
- **Confidence:** Medium (local evidence only, no external validation)
- **Typical Scenario:** After 1000 daily API calls exhausted
- **Threshold:** Higher (5 alerts) to reduce false positives

### Windows Firewall Integration

**Command:**
```bash
netsh advfirewall firewall add rule name="IDS_Block_192.168.1.100" dir=in action=block remoteip=192.168.1.100
```

**Effect:**
- Drops all inbound packets from blocked IP
- Rule persists across reboots
- Can be viewed: `netsh advfirewall firewall show rule name=all | Select-String "IDS_Block"`
- Can be deleted: `netsh advfirewall firewall delete rule name="IDS_Block_192.168.1.100"`

**Administrator Privileges:** Required (detector must run as admin)

---

## Configuration & Tuning

### Adjusting Detection Sensitivity

**Behavioral Thresholds (in `realtime_detect.py`):**

```python
# Port Scan Detection
if len(port_scan_tracker[src_ip]) > 10:  # Increase to 20 for less sensitivity

# Connection Flood Detection
if connection_tracker[src_ip] > 50:  # Increase to 100 for less sensitivity

# Data Exfiltration Detection
if total_bytes > 100 * 1024 * 1024:  # Increase to 500 MB for less sensitivity

# Tiny Packet Flood Detection
if tiny_packet_count > 20:  # Increase to 50 for less sensitivity
```

**ML Confidence Thresholds:**

```python
# Alert threshold
if attack_confidence >= 0.90:  # Increase to 0.95 for fewer alerts

# Blocking threshold (Mode 3)
if attack_confidence >= 0.95 and dst_port in ATTACK_PORTS:  # Increase to 0.98
```

**Alert Accumulation:**

```python
# Mode 2 threshold
if 25 <= abuse_score < 50 and alert_counter[src_ip] >= 2:  # Increase to 3+

# Mode 4 threshold
if alert_counter[src_ip] >= 5:  # Increase to 10+
```

### Whitelist Management

**Current Configuration (Narrowed for Security):**
- Whitelist reduced from ~300 million IPs to ~15 million IPs
- Removed all /8 blocks for cloud compute (AWS EC2, Azure VMs, Google Compute)
- Kept only specific ranges for consumer services and CDNs

**Adding New Ranges:**

```python
WHITELIST_RANGES = [
    '142.250.0.0/15',      # Google services (Search, YouTube, Gmail)
    '172.217.0.0/16',      # Google services
    # Add your trusted network:
    '192.168.1.0/24',      # Home network
    '10.0.0.0/8',          # Private network
]
```

**When to Add:**
- Legitimate service generating repeated alerts
- **Specific IP ranges** for services you actively use (NOT entire /8 blocks)
- Corporate VPN exit points
- Internal network ranges

**What NOT to Add:**
- Entire cloud provider /8 blocks (AWS, Azure, GCP) - attackers use these for compute
- Broad ranges covering millions of IPs unless absolutely necessary
- Unknown or untrusted IP ranges

**Security Consideration:**
- Every whitelisted IP is invisible to detection - use sparingly
- Prefer adding specific /16 or /24 ranges over /8 blocks
- Regularly review whitelist for services no longer used

### Port Classification

**Current Safe Ports (Skip ML Entirely):**

```python
SAFE_PORTS = {53, 853, 5353, 123, 443, 80, 993, 995, 587, 465, 110, 143, 5222, 8443}
# DNS: 53 (standard), 853 (DoT), 5353 (mDNS)
# Time: 123 (NTP)
# Web: 80 (HTTP), 443 (HTTPS), 8443 (alt HTTPS)
# Mail: 993 (IMAPS), 995 (POP3S), 587 (submission), 465 (SMTPS), 110 (POP3), 143 (IMAP)
# Chat: 5222 (XMPP)
```

**Adding New Safe Ports:**

```python
SAFE_PORTS = {53, 853, 5353, 123, 443, 80, 993, 995, 587, 465, 110, 143, 5222, 8443}
# Add: 25 (SMTP), 21 (FTP if trusted), 194 (IRC if used)
```

**Important:** Safe ports are checked on **both source AND destination ports** to handle server responses (e.g., DNS responses from port 53)

**Adding Attack Ports (apply ML):**

```python
ATTACK_PORTS = {22, 23, 445, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 8080, 8888}
# Add: 5900 (VNC), 135 (RPC), 139 (NetBIOS)
```

### Performance Optimization

**Memory Management:**
- Add cleanup for old flow entries in `sniffer.py`
- Implement LRU cache for flow dictionary
- Rotate `captured_packets.csv` (e.g., daily)

**Processing Speed:**
- Reduce CSV read frequency (currently reads on every loop)
- Batch process multiple packets at once
- Use multiprocessing for ML prediction

**Dashboard Responsiveness:**
- Limit packet display (currently shows all)
- Add pagination for large alert lists
- Cache blocked IP list (don't parse log every refresh)

### AbuseIPDB Configuration

**API Key:** Set environment variable:
```bash
$env:ABUSEIPDB_API_KEY = "your_api_key_here"
```

**Rate Limit Considerations:**
- Free tier: 1000 requests/day
- Consider paid tier for production
- Current design handles rate limits gracefully
- ML-based blocking (Mode 3) ensures protection continues

---

## System Requirements

**Software:**
- Python 3.8+
- Administrator privileges (for firewall rules)
- Windows 10/11 (netsh commands)

**Python Packages:**
- scapy (packet capture)
- pandas (data processing)
- scikit-learn (machine learning)
- joblib (model serialization)
- streamlit (dashboard)
- requests (API calls)

**Hardware:**
- 4GB RAM minimum (flows and model in memory)
- 10GB disk space (captured packets and logs grow)
- Stable network interface

---

## Operational Notes

**Startup Sequence:**
1. Activate virtual environment: `.\venv\Scripts\Activate.ps1`
2. Start sniffer: `python src/sniffer.py` (normal terminal)
3. Start detector: `python src/realtime_detect.py` (admin terminal)
4. Start dashboard: `streamlit run dashboard/app.py`

**Monitoring:**
- Check dashboard at `http://localhost:8501`
- Monitor `alerts.log` for detailed information
- View blocked IPs: `netsh advfirewall firewall show rule name=all | Select-String "IDS_Block"`

**Maintenance:**
- Clear old captures: `captured_packets.csv` grows indefinitely
- Monitor memory usage: Dictionaries grow unbounded
- Check AbuseIPDB quota: Resets at midnight UTC
- Review false positives: Add to whitelist if legitimate

**Troubleshooting:**
- No alerts: Check if traffic captured in `captured_packets.csv`
- False positives: Add IP ranges to whitelist
- Model errors: Retrain if feature format changed
- API errors: Check API key and rate limit status

---

## Future Enhancements

**Potential Improvements:**
1. **IPv6 Support:** Currently IPv4 only
2. **Deep Packet Inspection:** Analyze payloads for specific attack signatures
3. **Automatic Whitelist Learning:** Use ML to identify legitimate services
4. **Distributed Deployment:** Monitor multiple network segments
5. **Integration with SIEM:** Export alerts to enterprise security platforms
6. **Active Response:** Beyond blocking (rate limiting, challenge-response)
7. **Encrypted Traffic Analysis:** TLS fingerprinting, JA3 hashing
8. **Geolocation Blocking:** Block entire countries if not needed
9. **Time-based Rules:** More aggressive blocking during off-hours
10. **Automatic Model Retraining:** Incorporate real-world captures into training set

---

## Conclusion

This IDPS represents a **pragmatic hybrid approach** to network security:
- **Behavioral detection** handles encrypted modern traffic
- **Machine learning** catches signature-based attacks on vulnerable ports
- **Threat intelligence** blocks known malicious actors
- **Automated blocking** provides active defense
- **Real-time monitoring** gives visibility and control

The system is designed for **home/small office networks** where:
- Most traffic is legitimate HTTPS (should not trigger alerts)
- Attack-prone services (SSH, databases) are rare but critical
- Cloud service dependencies are common (need robust whitelisting)
- Manual configuration is acceptable (no large IT team)

**Key Success Factor:** The decision to **skip ML on HTTP/HTTPS** eliminates false positives while behavioral detection catches actual threats (data exfiltration, DDoS). This hybrid approach achieves both high detection rate and low false positive rate.
