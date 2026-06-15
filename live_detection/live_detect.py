import time
import pandas as pd
import joblib
import subprocess
import os
import json
import logging
from datetime import datetime

# ─────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────
MODEL_PATH      = "model/ids_model.joblib"
CONN_LOG        = "conn.log"
FLOWS_FILE      = "flows_live.tsv"
ALERT_LOG       = "logs/alerts.log"
FULL_LOG        = "logs/full.log"
THRESHOLD       = 0.7
WHITELIST_PORTS = {5353, 5355, 67, 68, 123}	# Whitelisted ports — always benign
WHITELIST_PROTOS = {"unknown_transport"}
WHITELIST_DSTS = {"224.0.0.22", "224.0.0.251", "ff02::2", "ff02::16", "ff02::fb"}
POLL_INTERVAL   = 5	# seconds (was 30)
MAX_LOG_LINES   = 10000	    # rotate logs after this many lines

# ─────────────────────────────────────────
#  LOGGING SETUP
# ─────────────────────────────────────────
os.makedirs("logs", exist_ok=True)

# Full log — every flow
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(FULL_LOG),
        logging.StreamHandler()   # still prints to terminal
    ]
)
logger = logging.getLogger("IDS")

# Alerts-only log
alert_handler = logging.FileHandler(ALERT_LOG)
alert_handler.setLevel(logging.WARNING)
alert_handler.setFormatter(logging.Formatter("%(asctime)s [ALERT] %(message)s"))
logger.addHandler(alert_handler)

# ─────────────────────────────────────────
#  LOAD MODEL
# ─────────────────────────────────────────
try:
    model = joblib.load(MODEL_PATH)
    logger.info(f"Model loaded: {MODEL_PATH}")
    logger.info(f"Features expected: {list(model.feature_names_in_)}")
except Exception as e:
    logger.error(f"Failed to load model: {e}")
    raise SystemExit(1)

# ─────────────────────────────────────────
#  TRACKING — avoid re-alerting same flows
# ─────────────────────────────────────────
seen_flows = set()      # set of (ts, id_orig_h, id_resp_h) tuples
session_stats = {
    "total": 0,
    "alerts": 0,
    "benign": 0,
    "start_time": datetime.now().isoformat()
}

# ─────────────────────────────────────────
#  EXTRACT FLOWS FROM ZEEK conn.log
#  Pulls: ts, src_ip, src_port, dst_ip, dst_port, proto, duration, orig_bytes, resp_bytes
# ─────────────────────────────────────────
def extract_flows():
    try:
        result = subprocess.run(
            "zeek-cut ts id.orig_h id.orig_p id.resp_h id.resp_p proto duration orig_bytes resp_bytes < conn.log",
            shell=True,
            capture_output=True,
            text=True
        )
        if not result.stdout.strip():
            return None

        from io import StringIO
        df = pd.read_csv(
            StringIO(result.stdout),
            sep="\t",
            header=None,
            names=["ts", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "duration", "orig_bytes", "resp_bytes"]
        )
        return df
    except Exception as e:
        logger.warning(f"Flow extraction error: {e}")
        return None

# ─────────────────────────────────────────
#  PREPROCESS FOR MODEL
# ─────────────────────────────────────────
def preprocess(df):
    features = df.copy()
    for col in ["duration", "orig_bytes", "resp_bytes"]:
        features[col] = pd.to_numeric(features[col], errors="coerce")
    features["proto"] = features["proto"].astype("category").cat.codes
    features = features.fillna(0)
    return features[model.feature_names_in_]

# ─────────────────────────────────────────
#  SUMMARISE SESSION STATS
# ─────────────────────────────────────────
def print_summary():
    elapsed = (datetime.now() - datetime.fromisoformat(session_stats["start_time"]))
    mins = int(elapsed.total_seconds() // 60)
    secs = int(elapsed.total_seconds() % 60)
    total = session_stats["total"] or 1
    threat_pct = (session_stats["alerts"] / total) * 100
    logger.info(
        f"─── SESSION SUMMARY ── {mins}m {secs}s ── "
        f"Total: {session_stats['total']} | "
        f"Alerts: {session_stats['alerts']} | "
        f"Benign: {session_stats['benign']} | "
        f"Threat rate: {threat_pct:.1f}%"
    )

# ─────────────────────────────────────────
#  MAIN DETECTION LOOP
# ─────────────────────────────────────────
logger.info("=" * 60)
logger.info("  NeuralShield IDS — Starting Live Detection")
logger.info(f"  Threshold : {THRESHOLD}")
logger.info(f"  Interval  : {POLL_INTERVAL}s")
logger.info(f"  Alert log : {ALERT_LOG}")
logger.info("=" * 60)

cycle = 0

try:
    while True:
        cycle += 1
        df = extract_flows()

        if df is None or df.empty:
            logger.warning("Waiting for Zeek data...")
            time.sleep(POLL_INTERVAL)
            continue

        # Build flow fingerprints to skip already-seen flows
        df["_fp"] = df["ts"].astype(str) + "|" + df["src_ip"].astype(str) + "|" + df["dst_ip"].astype(str)
        new_flows = df[~df["_fp"].isin(seen_flows)].copy()

        if new_flows.empty:
            logger.info(f"[Cycle {cycle}] No new flows.")
            time.sleep(POLL_INTERVAL)
            continue

        # Add all new fingerprints to seen set
        seen_flows.update(new_flows["_fp"].tolist())

        # Trim seen_flows to avoid unbounded memory
        if len(seen_flows) > 50000:
            seen_flows.clear()
            logger.info("Seen-flows cache cleared (50k limit reached)")

        # Preprocess & predict — ALL new flows, not just last 5
        try:
            X = preprocess(new_flows)
            probs = model.predict_proba(X)
        except Exception as e:
            logger.warning(f"Prediction error: {e}")
            time.sleep(POLL_INTERVAL)
            continue

        new_alerts = 0
        for i, (_, row) in enumerate(new_flows.iterrows()):
            prob_attack = probs[i][1]
            session_stats["total"] += 1

            src = f"{row.get('src_ip','?')}:{row.get('src_port','?')}"
            dst = f"{row.get('dst_ip','?')}:{row.get('dst_port','?')}"
            proto = row.get("proto", "?")
            dur = row.get("duration", 0)
            
            # Skip whitelisted ports
            dst_ip = str(row.get("dst_ip", ""))
            proto_raw = str(row.get("proto", ""))
            if int(row.get("dst_port", 0)) in WHITELIST_PORTS \
               or proto_raw in WHITELIST_PROTOS \
               or any(dst_ip.startswith(w) for w in WHITELIST_DSTS):
                session_stats["benign"] += 1
                continue

            if prob_attack > THRESHOLD:
                session_stats["alerts"] += 1
                new_alerts += 1
                logger.warning(
                    f"[ALERT] prob={prob_attack:.3f} | "
                    f"{src} → {dst} | "
                    f"proto={proto} | dur={dur}s"
                )
            else:
                session_stats["benign"] += 1
                logger.info(
                    f"[OK]    prob={prob_attack:.3f} | "
                    f"{src} → {dst} | "
                    f"proto={proto} | dur={dur}s"
                )

        logger.info(
            f"[Cycle {cycle}] Processed {len(new_flows)} new flows | "
            f"+{new_alerts} alerts | "
            f"Session total: {session_stats['total']} flows, {session_stats['alerts']} alerts"
        )

        # Print summary every 10 cycles
        if cycle % 10 == 0:
            print_summary()

        time.sleep(POLL_INTERVAL)

except KeyboardInterrupt:
    logger.info("IDS stopped by user.")
    print_summary()
