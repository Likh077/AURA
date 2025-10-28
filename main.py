import sys
import threading
import time
import logging
from logging.handlers import QueueHandler
from queue import Queue
from flask import Flask, jsonify, render_template
from scapy.all import sniff, IP
from anomaly_detection_service import BehavioralAnomalyDetector
from threat_intel_service import ThreatIntel
from firewall_manager import FirewallManager
from geolocation_service import GeoLocator

# --- Queues for real-time updates to UI ---
traffic_data_queue = Queue()
log_queue = Queue()

# --- Flask app setup ---
app = Flask(__name__, template_folder='templates', static_folder='static')

# --- Initialize global modules ---
detector = BehavioralAnomalyDetector()
intel = ThreatIntel()
firewall = FirewallManager()
geo = GeoLocator()

# --- Logging setup ---
log = logging.getLogger('werkzeug')
log.handlers = []
log.addHandler(QueueHandler(log_queue))

print("🚀 Starting AURA Cyber Threat Radar...")
print("🌐 Running live monitoring and auto-blocking system...\n")

# --- Background thread: Packet sniffing ---
def process_packet(packet):
    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst

    # Ignore private-to-private
    if geo._is_private_ip(src) and geo._is_private_ip(dst):
        return

    # Choose the external IP (for analysis)
    external_ip = dst if geo._is_private_ip(src) else src

    # --- Threat analysis pipeline ---
    intel_score = intel.check_ip_reputation(external_ip)
    behavior_score = detector.calculate_threat_score(external_ip)
    final_score = min(1.0, round(intel_score + behavior_score, 2))

    # --- Get location info ---
    location = geo.get_location(external_ip)
    country = "Unknown"
    lat, lon = 0.0, 0.0
    if location:
        country = location.get("country", "Unknown")
        lat = location.get("latitude", 0.0)
        lon = location.get("longitude", 0.0)

    # --- Auto-block logic ---
    if final_score >= 0.6:
        firewall.block_ip(external_ip)

    # --- Send to UI ---
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

    # Console log
    print(f"[AURA] {src} → {dst} | Score={final_score} | {'BLOCKED' if final_score>=0.6 else 'OK'}")

def start_sniffer():
    print("🔍 Starting live packet capture...")
    sniff(prn=process_packet, store=False)

sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
sniffer_thread.start()

# --- API endpoints ---
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

# --- Run the Flask server ---
if __name__ == "__main__":
    print("✅ System initialized successfully.")
    print("🌍 Web UI: http://127.0.0.1:5000")
    print("📊 Logs UI: http://127.0.0.1:5000\n")
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
