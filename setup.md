setup md
# 🛡️ AI-IDPS Setup Guide

> **AI-Powered Intrusion Detection & Prevention System**

This comprehensive guide explains step-by-step how to set up the AI-IDPS project on **Windows, Linux, or macOS**.

---

## 📋 Table of Contents

1. [Prerequisites](#1️⃣-prerequisites)
2. [Install Python](#2️⃣-install-python)
3. [Clone the Repository](#3️⃣-clone-the-repository)
4. [Set Up Virtual Environment](#4️⃣-set-up-virtual-environment)
5. [Set AbuseIPDB API Key (Optional)](#5️⃣-set-abuseipdb-api-key-optional)
6. [Running the Project](#6️⃣-running-the-project)
7. [Test Installation](#7️⃣-test-installation)
8. [Troubleshooting](#8️⃣-troubleshooting)
9. [Recommended Practices](#9️⃣-recommended-practices)

---

## 1️⃣ Prerequisites

Before you begin, ensure you have the following:

| Requirement | Description |
|-------------|-------------|
| **Operating System** | Windows 10/11, Linux, or macOS |
| **Privileges** | Administrator/root access (for some setups) |
| **Internet** | Active internet connection |
| **Git** | Version control system installed |


---

## 2️⃣ Install Python

### Step 2.1: Check Existing Python Installation

Open **PowerShell** (Windows) or **Terminal** (Linux/Mac):

**Windows:**
```powershell
py --list
```

**Linux/Mac:**
```bash
python3 --version
```

> ✅ If Python 3.11 is already installed, skip to [Step 2.3](#step-23-verify-python-installation).

---

### Step 2.2: Install Python 3.11 (Recommended for ML Compatibility)

1. Download **Python 3.11** from [python.org](https://www.python.org/downloads/release/python-3110/)

2. During installation, ensure you:
   - ☑️ Check **"Add Python to PATH"**
   - ☑️ Enable **"Long Path Support"**
   - ☑️ Ensure **pip** is installed

3. **Restart your terminal** after installation

---

### Step 2.3: Verify Python Installation

```powershell
py -3.11 --version
```

**Expected output:**
```
Python 3.11.x
```

> ⚠️ **Important:** TensorFlow and other ML libraries do **not** support Python 3.14 yet. Always use **Python 3.11** for this project.

---

### Step 2.4: Fix Legacy `py` Launcher (Windows Only)

If `py --list` fails or shows a legacy warning:

1. Open **Settings** → **Apps** → **Installed apps**
2. Search for **"Python Launcher"**
3. **Uninstall** it
4. **Restart PowerShell**

Verify the fix:
```powershell
py --list
```
> Should show managed Python versions without warnings.

---

## 3️⃣ Clone the Repository

```bash
git clone https://github.com/WaasilaAsif/IS_IDPS.git
cd IS_IDPS
```

---

## 4️⃣ Set Up Virtual Environment

### Step 4.1: Create and Activate Virtual Environment

**Windows PowerShell:**
```powershell
python -m venv venv
venv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

> 💡 You should see `(venv)` prefix in your terminal prompt when activated.

---

### Step 4.2: Upgrade pip

```powershell
python -m pip install --upgrade pip
```

---

### Step 4.3: Install Dependencies

```powershell
pip install -r requirements.txt
```

> ✅ This will install **TensorFlow**, **Scapy**, **Pandas**, **Streamlit**, and other required dependencies.

---

## 5️⃣ Set AbuseIPDB API Key (Optional)

To enable threat intelligence lookups:

1. Create an account at [AbuseIPDB](https://www.abuseipdb.com/)
2. Navigate to your account and copy your **Personal API Key**
3. Set the environment variable:

**Windows PowerShell:**
```powershell
$env:ABUSEIPDB_API_KEY="your_api_key_here"
```

**Linux/Mac:**
```bash
export ABUSEIPDB_API_KEY="your_api_key_here"
```

> 💡 **Tip:** To make this permanent, add it to your system's environment variables or shell profile (`.bashrc`, `.zshrc`).

---

## 6️⃣ Running the Project

The project consists of three components that run in separate terminals. **Ensure `venv` is activated in each terminal.**

### Step 6.1: Start Packet Capture

Open a **new terminal** (with venv activated):

```powershell
python src/sniffer.py
```

> 📡 This starts capturing network packets.

---

### Step 6.2: Run Real-Time Detection

Open **another terminal** (with venv activated):

```powershell
python src/realtime_detect.py
```

> 🔍 This analyzes packets in real-time using the ML model.

---

### Step 6.3: Launch Dashboard

```powershell
streamlit run dashboard/app.py
```

> 🌐 Visit **http://localhost:8501** in your browser to access the dashboard.

---

### 📊 Summary

| Component | Command | Purpose |
|-----------|---------|---------|
| **Sniffer** | `python src/sniffer.py` | Captures network packets |
| **Detector** | `python src/realtime_detect.py` | Real-time threat analysis |
| **Dashboard** | `streamlit run dashboard/app.py` | Web-based visualization |

> 💡 All scripts can run simultaneously in separate terminals using the same `venv`.

---

## 7️⃣ Test Installation

Verify TensorFlow installation:

```powershell
python -c "import tensorflow as tf; print(tf.__version__)"
```

**Expected output:**
```
2.20.0
```

> ℹ️ **Note:** oneDNN optimization warnings are normal and can be safely ignored.

---

## 8️⃣ Troubleshooting

| Issue | Solution |
|-------|----------|
| **TensorFlow install fails** | Ensure you're using **Python 3.11** |
| **Multiple Python versions** | Use `py -3.11 -m venv venv` explicitly |
| **Dashboard not loading** | Check firewall settings and ensure **port 8501** is open |
| **Packet capture permission errors (Linux)** | Use `sudo` to run with elevated privileges |
| **Packet capture permission errors (Windows)** | Run terminal as **Administrator** |

---

## 9️⃣ Recommended Practices

### ✅ Best Practices Checklist

- [ ] Always use **one virtual environment** for the entire project
- [ ] **Activate `venv`** in every terminal you open before running commands
- [ ] **Pin dependencies** after setup to ensure reproducibility:
  ```powershell
  pip freeze > requirements.txt
  ```
- [ ] **Document Python version** in README: `Python 3.11.x`

---

## 📞 Need Help?

If you encounter any issues not covered in this guide, please:
1. Check the [Troubleshooting](#8️⃣-troubleshooting) section
2. Open an issue on the [GitHub repository](https://github.com/WaasilaAsif/IS_IDPS/issues)

---

<div align="center">

**Happy Detecting! 🛡️**

*Built with ❤️ for network security*

</div>