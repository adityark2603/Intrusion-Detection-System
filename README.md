# NeuralShield — ML-Based Intrusion Detection System

A real-time network intrusion detection system that uses a **Random Forest** classifier to detect malicious traffic from live Zeek logs. Includes a live web dashboard for monitoring.

---

## How It Works

1. **Zeek** sniffs your network interface and writes connection logs (`conn.log`) in real time
2. `live_detect.py` reads new flows from `conn.log` every 5 seconds, extracts 4 features, and runs them through the model
3. The model outputs a probability score — anything above **0.70** is flagged as an **ATTACK**
4. `app.py` wraps the detector in a **Flask web dashboard** at `http://localhost:5000`

The model was trained on the **CIC-IDS2017** dataset (DDoS, PortScan, Botnet, BruteForce traffic).

---

## Folder Structure

```
Intrusion-Detection-System/
└── live_detection/ (live detection + dashboard)
    ├── app.py                  ← Flask web dashboard (start here)
    ├── live_detect.py          ← Core detection loop (reads Zeek conn.log)
    ├── train_model.py          ← Model training script
    ├── conn.log                ← Live Zeek connection log (generated at runtime)
    ├── flows_live.tsv          ← Sample flows for offline testing
    ├── label_map.json          ← { 0: BENIGN, 1: ATTACK }
    ├── features/
    │   └── features.json       ← Feature list: duration, orig_bytes, resp_bytes, proto
    ├── model/
    │   └── ids_model.joblib    ← Trained Random Forest model
    ├── logs/
    │   ├── alerts.log          ← Alerts only (generated at runtime)
    │   └── full.log            ← All flow decisions (generated at runtime)
    └── static/
        ├── index.html          ← Dashboard frontend
        └── style.css           ← Dashboard styles

```

---

## Requirements

### System
- Linux (tested on Ubuntu 22.04)
- [Zeek](https://zeek.org/get-zeek/) installed and on your PATH
- Python 3.8+
- `sudo` access (needed for Zeek to sniff a network interface)

### Python packages

```bash
pip install flask flask-cors pandas scikit-learn joblib numpy
```

---

## Setup

### 1. Clone the repo

```bash
 git clone https://github.com/adityark2603/Intrusion-Detection-System.git
cd Intrusion-Detection-System
```

### 2. Install dependencies

```bash
pip install flask flask-cors pandas scikit-learn joblib numpy
```

### 3. Train the model (skip if `model/ids_model.joblib` exists and no changes have been made to model)

```bash
cd week3
python3 train_model.py
```

This downloads the CIC-IDS2017 dataset and trains a Random Forest. Takes about 5–10 minutes. If the download fails (no internet), it automatically falls back to synthetic training data.

---

## Running the IDS

### Step 1 — Start Zeek on your network interface

Open **Terminal 1**. Replace `ens33` with your actual interface (find it with `ip a`):

```bash
cd ~/Intrusion-Detection-System/live_detection
sudo zeek -C -i ens33
```

This creates and continuously updates `conn.log` in the current directory.

### Step 2 — Start the web dashboard

Open **Terminal 2**:

```bash
cd ~/Intrusion-Detection-System/live_detection
python3 app.py
```

Open your browser and go to: **http://127.0.0.1:5000**

Click **"Initialize IDS"** in the dashboard to start the detection loop.

### Step 3 (optional) — Watch alerts in the terminal

Open **Terminal 3**:

```bash
tail -f ~/NeuralShield-IDS/week3/logs/alerts.log
```

## Simulating Attacks (for testing)

With Zeek running, open a second terminal and try any of the following. Watch the dashboard for alerts.

### Port Scan (Nmap)
```bash
sudo nmap -sS -p 1-1000 192.168.244.128
sudo nmap -A -T4 192.168.244.128
```

### DoS / Flood (hping3)
```bash
sudo apt install hping3

# TCP SYN flood
sudo hping3 -S --flood -p 80 192.168.244.128

# ICMP flood
sudo hping3 --icmp --flood 192.168.244.128
```
Stop with `Ctrl+C` after 10–15 seconds.

---

## Model Details

| Property | Value |
|---|---|
| Algorithm | Random Forest (200 trees) |
| Training data | CIC-IDS2017 (Friday DDoS subset) |
| Features | `duration`, `orig_bytes`, `resp_bytes`, `proto` |
| Output | Binary — `BENIGN` (0) or `ATTACK` (1) |
| Alert threshold | 0.70 probability |
| Detection interval | Every 5 seconds |

---

## Configuration

Key settings are at the top of `live_detect.py`:

```python
THRESHOLD       = 0.7     # Alert if P(attack) > this
POLL_INTERVAL   = 5       # Seconds between scans
WHITELIST_PORTS = {5353, 5355, 67, 68, 123}   # Always treated as benign
```

---

## Tech Stack

- **Zeek** — network traffic capture and log generation
- **scikit-learn** — Random Forest classifier
- **pandas** — flow feature extraction and preprocessing
- **Flask** — web dashboard backend
- **CIC-IDS2017** — training dataset
