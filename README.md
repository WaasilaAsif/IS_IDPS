# AI-Powered Intrusion Detection System (IDS) for Home Networks

## 🚀 Overview
This project is a lightweight, AI-enhanced Intrusion Detection System (IDS) designed to monitor network traffic on your home Wi-Fi network. It uses machine learning to flag unusual or potentially malicious activity in real time, with a modern dashboard and optional threat intelligence and auto-blocking features.

<img width="2527" height="1280" alt="Screenshot 2025-07-16 211455" src="https://github.com/user-attachments/assets/91966419-ac9c-494f-a5a5-2852607e292c" />

---

## 🧰 Features
- **Real-time Packet Sniffing:** Captures live network traffic using Scapy.
- **Feature Extraction:** Extracts protocol, source/destination, and packet size features.
- **Machine Learning Detection:** Classifies traffic as normal or suspicious using a Random Forest model.
- **Threat Intelligence:** Integrates with AbuseIPDB to check IP reputation.
- **Auto-Blocking:** Automatically blocks high-risk IPs using firewall rules (Windows only).
- **Interactive Dashboard:** Streamlit dashboard for live traffic, alerts, and threat intelligence.

---

## 🏗️ Architecture
```
+-------------------+      +-------------------+      +-------------------+
|  Packet Sniffer   | ---> |  ML Classifier    | ---> |  Alert/Block/Log  |
+-------------------+      +-------------------+      +-------------------+
        |                        |                           |
        v                        v                           v
   [captured_packets.csv]   [rf_model.joblib]         [alerts.log]
        |                        |                           |
        +------------------------+---------------------------+
                                 |
                                 v
                        [Streamlit Dashboard]
```

---

## 📦 Project Structure
```
.
├── data/                # Datasets, logs, and captured packets
├── models/              # Trained ML models and encoders
├── src/                 # Source code (sniffer, ML, detection, threat intel)
├── dashboard/           # Streamlit dashboard app
├── requirements.txt     # Python dependencies
└── README.md            # This file
```

---

## ⚡ Quickstart (Local)

### 1. Clone the Repository
```sh
git clone https://github.com/WaasilaAsif/IS_IDPS.git
cd ai-powered-ids-for-home-networks
```

### 2. Set Up Python Environment
```sh
python -m venv venv
venv\Scripts\activate  # On Windows
# or
source venv/bin/activate  # On Linux/Mac
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Prepare Dataset & Train Model
```sh
python src/dataset_prep.py      # Download and preprocess NSL-KDD
python src/train_model.py       # Train and save the ML model
```

### 4. Start Packet Capture
```sh
python src/sniffer.py           # Run in a separate terminal
```

### 5. (Optional) Set AbuseIPDB API Key
Get a free API key from [AbuseIPDB](https://www.abuseipdb.com/).
```sh
$env:ABUSEIPDB_API_KEY="31126b5cebf692c76a6b86b4470229555ccd7f35a30b8f163e83b5d8cb98936aced92735ad186c5d" # Windows
export ABUSEIPDB_API_KEY="31126b5cebf692c76a6b86b4470229555ccd7f35a30b8f163e83b5d8cb98936aced92735ad186c5d"  # Linux/Mac
```

### 6. Run Real-Time Detection
```sh
python src/realtime_detect.py   # Run in a separate terminal
```

### 7. Launch the Dashboard
```sh
streamlit run dashboard/app.py
```
Visit [http://localhost:8501](http://localhost:8501) in your browser.

---

##  ️ Troubleshooting
- **TensorFlow install fails:** Ensure you're using Python 3.11.
- **Dashboard not loading:** Check firewall settings and ensure port 8501 is open.
- **Packet capture permissions:** On Linux, you may need to run as root. On Windows, run as Administrator.
- **Model not found:** Make sure to run `train_model.py` before starting detection.

---

## 🔒 Security & Ethics
- **For home/lab use only.**
- **Auto-blocking** can disrupt your network if misused—use with caution.
- **Do not use on networks you do not own or have permission to monitor.**

---

## 🤝 Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Open a pull request

---

## 📄 License
MIT License. See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgements
- [Scapy](https://scapy.net/)
- [scikit-learn](https://scikit-learn.org/)
- [Streamlit](https://streamlit.io/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [NSL-KDD Dataset](https://www.unb.ca/cic/datasets/nsl.html) 
