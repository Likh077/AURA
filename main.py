# main.py
import os
import threading
import signal
import sys
from queue import Queue
from flask import Flask, jsonify, render_template
from scapy.all import sniff, IP

# import your existing modules (make sure names match your files)
from anomaly_detection_service import BehavioralAnomalyDetector
from threat_intel_service import ThreatIntel
from firewall_manager import FirewallManager
from geolocation_service import GeoLocator
from integrity_monitor import FileIntegrityMonitor

# Queues for UI
traffic_data_queue = Queue()
integrity_queue = Queue()

app = Flask(__name__, template_folder='templates', static_folder='static')

# Initialize modules
detector = BehavioralAnomalyDetector()
intel = ThreatIntel()
firewall = FirewallManager()
geo = GeoLocator()

# Initialize File Integrity Monitor (use a safe test folder first)
WATCH_DIRS = [r"C:\Users\LIKHITH\OneDrive\Desktop\AURA-COPY"]  # ensure test_dir exists and contains testfile.txt
integrity_monitor = FileIntegrityMonitor(
    baseline_path=os.path.join(os.getcwd(), "integrity_baseline.json"),
    watch_dirs=WATCH_DIRS,
    interval=30,
    alert_queue=integrity_queue,
    max_files=20000  # optional cap for speed; None for unlimited
)

# start integrity monitor background thread
integrity_monitor.start_monitoring(initial_delay=1)

# ---- Radar/sniffer logic (unchanged) ----
stop_sniffer = threading.Event()

def process_packet(packet):
    if not packet.haslayer(IP):
        return
    src = packet[IP].src
    dst = packet[IP].dst
    if geo._is_private_ip(src) and geo._is_private_ip(dst):
        return
    external_ip = dst if geo._is_private_ip(src) else src

    intel_score = intel.check_ip_reputation(external_ip)
    behavior_score = detector.calculate_threat_score(external_ip)
    final_score = min(1.0, round(intel_score + behavior_score, 2))

    location = geo.get_location(external_ip)
    country = location.get("country", "Unknown") if location else "Unknown"
    lat = location.get("latitude", 0.0) if location else 0.0
    lon = location.get("longitude", 0.0) if location else 0.0

    if final_score >= 0.6:
        firewall.block_ip(external_ip)

    traffic_data_queue.put({
        "src_ip": src,
        "dst_ip": dst,
        "external_ip": external_ip,
        "score": final_score,
        "country": country,
        "lat": lat,
        "lon": lon,
        "blocked": final_score >= 0.6
    })

    print(f"[AURA] {src} → {dst} | Score={final_score} | {'BLOCKED' if final_score>=0.6 else 'OK'}")

def start_sniffer():
    print("🔍 Starting live packet capture...")
    sniff(prn=process_packet, store=False, stop_filter=lambda pkt: stop_sniffer.is_set())

sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
sniffer_thread.start()

# ---- Flask routes ----
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/traffic')
def traffic():
    data = []
    while not traffic_data_queue.empty():
        data.append(traffic_data_queue.get())
    return jsonify(data)

@app.route('/status')
def status():
    return jsonify(detector.get_status())

@app.route('/blocked')
def blocked():
    return jsonify(firewall.list_blocked_ips())

@app.route('/integrity')
def integrity():
    # return all queued integrity events (consumes queue)
    events = []
    while not integrity_queue.empty():
        events.append(integrity_queue.get())
    return jsonify(events)

@app.route('/force_integrity')
def force_integrity():
    # synchronous force scan and return result
    event = integrity_monitor.force_scan()
    if event:
        return jsonify({"status": "changed", "event": event})
    else:
        return jsonify({"status": "ok", "event": None})

# graceful shutdown
def shutdown_handler(sig, frame):
    print("\n[ AURA ] Shutting down...")
    stop_sniffer.set()
    integrity_monitor.stop_monitoring()
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

if __name__ == "__main__":
    print("✅ System initialized successfully.")
    print("🌍 Web UI: http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
