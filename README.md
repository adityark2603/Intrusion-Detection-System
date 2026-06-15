# NeuralShield — ML-Based Intrusion Detection System

A real-time network intrusion detection system that uses a **Random Forest** classifier to detect malicious traffic from live Zeek logs. Includes a live web dashboard for monitoring.

![Dashboard](week3/ss/w3-terminal.png)

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
IDS/
├── week3/                      ← Main project (live detection + dashboard)
│   ├── app.py                  ← Flask web dashboard (start here)
│   ├── live_detect.py          ← Core detection loop (reads Zeek conn.log)
│   ├── train_model.py          ← Model training script
│   ├── conn.log                ← Live Zeek connection log (generated at runtime)
│   ├── flows_live.tsv          ← Sample flows for offline testing
│   ├── label_map.json          ← { 0: BENIGN, 1: ATTACK }
│   ├── features/
│   │   └── features.json       ← Feature list: duration, orig_bytes, resp_bytes, proto
│   ├── model/
│   │   └── ids_model.joblib    ← Trained Random Forest model
│   ├── logs/
│   │   ├── alerts.log          ← Alerts only (generated at runtime)
│   │   └── full.log            ← All flow decisions (generated at runtime)
│   ├── static/
│   │   ├── index.html          ← Dashboard frontend
│   │   └── style.css           ← Dashboard styles
│   └── ss/
│       └── w3-terminal.png     ← Screenshot
│
├── week2/                      ← Earlier iteration (offline flow analysis)
│   ├── data/
│   │   ├── conn.log
│   │   ├── flows_raw.tsv
│   │   ├── flows_ready.csv
│   │   └── preprocess.py
│   ├── features/
│   │   └── features.json
│   ├── model/
│   │   └── ids_model.joblib
│   └── test_model.py
│
└── week1/                      ← Initial Zeek log exploration
    ├── conn.log
    ├── conn_selected.csv
    ├── dns.log
    ├── http.log
    └── ssl.log
```

> **Note:** `test_capture.pcap` files are excluded from this repo (too large). See [Running Without a Live Interface](#running-without-a-live-interface) to use them.

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
git clone https://github.com/YOUR_USERNAME/NeuralShield-IDS.git
cd NeuralShield-IDS
```

### 2. Install dependencies

```bash
pip install flask flask-cors pandas scikit-learn joblib numpy
```

### 3. Train the model (skip if `model/ids_model.joblib` already exists)

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
cd ~/NeuralShield-IDS/week3
sudo zeek -C -i ens33
```

This creates and continuously updates `conn.log` in the current directory.

### Step 2 — Start the web dashboard

Open **Terminal 2**:

```bash
cd ~/NeuralShield-IDS/week3
python3 app.py
```

Open your browser and go to: **http://127.0.0.1:5000**

Click **"Initialize IDS"** in the dashboard to start the detection loop.

### Step 3 (optional) — Watch alerts in the terminal

Open **Terminal 3**:

```bash
tail -f ~/NeuralShield-IDS/week3/logs/alerts.log
```

---

## Running Without a Live Interface

If you don't have Zeek running, you can test the model directly by injecting flows into `flows_live.tsv`:

```bash
cd week3

# Simulate a DDoS flow
echo -e "101.5\t43804\t9784\ttcp" >> flows_live.tsv

# Simulate a port scan (20 tiny flows)
for i in $(seq 1 20); do
  echo -e "0.001\t44\t0\ttcp" >> flows_live.tsv
done
```

Or score flows instantly with no Zeek needed:

```bash
python3 - <<'EOF'
import pandas as pd, joblib

model = joblib.load("model/ids_model.joblib")

tests = [
    ("Port scan",    0.001,  44,     0,    "tcp"),
    ("DDoS flood",   101.5,  43804,  9784, "tcp"),
    ("Exfiltration", 95.3,   500000, 200,  "tcp"),
    ("Normal web",   0.577,  87,     189,  "tcp"),
    ("Normal DNS",   0.034,  94,     622,  "udp"),
]

rows = [{"duration": d, "orig_bytes": o, "resp_bytes": r, "proto": p}
        for _, d, o, r, p in tests]
df = pd.DataFrame(rows)
df["proto"] = df["proto"].astype("category").cat.codes
for c in ["duration", "orig_bytes", "resp_bytes"]:
    df[c] = pd.to_numeric(df[c])

probs = model.predict_proba(df[model.feature_names_in_])

print(f"\n{'Label':<20} {'P(attack)':<12} {'Result'}")
print("-" * 45)
for i, (name, *_) in enumerate(tests):
    p = probs[i][1]
    print(f"{name:<20} {p:<12.3f} {'ATTACK' if p > 0.7 else 'BENIGN'}")
EOF
```

---

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
