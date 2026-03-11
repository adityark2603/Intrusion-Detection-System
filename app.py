from flask import Flask, jsonify, Response, send_from_directory
from flask_cors import CORS
import subprocess
import threading
import time
import json
import re
import os
import queue
from datetime import datetime

app = Flask(__name__, static_folder='static')
CORS(app)

# Global state
ids_process = None
ids_running = False
log_queue = queue.Queue(maxsize=500)
stats = {
    "total_flows": 0,
    "alerts": 0,
    "benign": 0,
    "start_time": None,
    "last_prob": 0.0,
    "history": []  # list of {time, alerts, benign}
}
stats_lock = threading.Lock()
all_logs = []
alerts_list = []

def parse_line(line):
    """Parse a line from live_detect.py output"""
    line = line.strip()
    if not line:
        return None

    prob_match = re.search(r'prob=([\d.]+)', line)
    prob = float(prob_match.group(1)) if prob_match else None

    if '[ALERT]' in line:
        return {"type": "alert", "msg": line, "prob": prob, "time": datetime.now().strftime("%H:%M:%S")}
    elif '[OK]' in line:
        return {"type": "ok", "msg": line, "prob": prob, "time": datetime.now().strftime("%H:%M:%S")}
    elif '[INFO]' in line:
        return {"type": "info", "msg": line, "prob": None, "time": datetime.now().strftime("%H:%M:%S")}
    elif '[WARN]' in line:
        return {"type": "warn", "msg": line, "prob": None, "time": datetime.now().strftime("%H:%M:%S")}
    else:
        return {"type": "log", "msg": line, "prob": prob, "time": datetime.now().strftime("%H:%M:%S")}

def run_ids():
    global ids_process, ids_running
    ids_running = True
    with stats_lock:
        stats["start_time"] = datetime.now().isoformat()
        stats["total_flows"] = 0
        stats["alerts"] = 0
        stats["benign"] = 0
        stats["history"] = []

    try:
        ids_process = subprocess.Popen(
            ["python3", "-u", "live_detect.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=os.path.expanduser("~/IDS/week3")
        )

        for line in iter(ids_process.stdout.readline, ''):
            parsed = parse_line(line)
            if parsed:
                all_logs.append(parsed)
                if len(all_logs) > 1000:
                    all_logs.pop(0)

                with stats_lock:
                    if parsed["type"] == "alert":
                        stats["alerts"] += 1
                        stats["total_flows"] += 1
                        alerts_list.append(parsed)
                        if len(alerts_list) > 200:
                            alerts_list.pop(0)
                    elif parsed["type"] == "ok":
                        stats["benign"] += 1
                        stats["total_flows"] += 1

                    if parsed["prob"] is not None:
                        stats["last_prob"] = parsed["prob"]

                    # history point every 5 flows
                    if stats["total_flows"] % 5 == 0 and stats["total_flows"] > 0:
                        stats["history"].append({
                            "time": datetime.now().strftime("%H:%M:%S"),
                            "alerts": stats["alerts"],
                            "benign": stats["benign"]
                        })
                        if len(stats["history"]) > 60:
                            stats["history"].pop(0)

                try:
                    log_queue.put_nowait(json.dumps(parsed))
                except queue.Full:
                    pass

    except Exception as e:
        err = {"type": "error", "msg": f"[ERROR] {str(e)}", "prob": None, "time": datetime.now().strftime("%H:%M:%S")}
        all_logs.append(err)
        try:
            log_queue.put_nowait(json.dumps(err))
        except:
            pass
    finally:
        ids_running = False
        ids_process = None
        stop_msg = {"type": "info", "msg": "[INFO] IDS stopped.", "prob": None, "time": datetime.now().strftime("%H:%M:%S")}
        all_logs.append(stop_msg)
        try:
            log_queue.put_nowait(json.dumps(stop_msg))
        except:
            pass

@app.route('/api/start', methods=['POST'])
def start_ids():
    global ids_running
    if ids_running:
        return jsonify({"status": "already_running"})
    t = threading.Thread(target=run_ids, daemon=True)
    t.start()
    return jsonify({"status": "started"})

@app.route('/api/stop', methods=['POST'])
def stop_ids():
    global ids_process, ids_running
    if ids_process:
        ids_process.terminate()
        ids_running = False
        return jsonify({"status": "stopped"})
    return jsonify({"status": "not_running"})

@app.route('/api/status')
def get_status():
    with stats_lock:
        s = dict(stats)
    return jsonify({
        "running": ids_running,
        "stats": s
    })

@app.route('/api/logs')
def get_logs():
    return jsonify(all_logs[-100:])

@app.route('/api/alerts')
def get_alerts():
    return jsonify(alerts_list[-50:])

@app.route('/api/stream')
def stream():
    def event_stream():
        while True:
            try:
                msg = log_queue.get(timeout=30)
                yield f"data: {msg}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type':'ping','msg':'','prob':None,'time':''})}\n\n"
    return Response(event_stream(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
