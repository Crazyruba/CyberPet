#!/usr/bin/env python3
# cyberpet.py
# Ultieme CyberPet zonder audio, met "CyberPet Awake!" bij opstarten

import os
import subprocess
import time
import json
import logging
import random
import numpy as np
from datetime import datetime
try:
    from inky.inky_uc8159 import Inky
except ImportError:
    print("Inky niet gevonden. Geen e-Ink display ondersteuning.")
    Inky = None
from flask import Flask, render_template, send_file, request
import threading
from PIL import Image, ImageDraw, ImageFont
import matplotlib.pyplot as plt
import io
import base64
import importlib.util
import bluetooth

# Configuratie
LOG_DIR = "/home/pi/cyberpet/data/logs"
REPORT_DIR = "/home/pi/cyberpet/data/reports"
Q_TABLE_FILE = "/home/pi/cyberpet/data/q_table.json"
CVE_FILE = "/home/pi/cyberpet/data/cve_database.json"
PLUGIN_DIR = "/home/pi/cyberpet/plugins"
SCAN_INTERVAL = 300  # 5 minuten
WIFI_INTERFACES = []  # Dynamisch gevuld
WEB_PORT = 5000
PORTS = [22, 80, 443, 445, 3389]  # SSH, HTTP, HTTPS, SMB, RDP
ACTIONS = PORTS + ["deauth", "brute_force", "exploit", "sniff", "bt_scan"]

# Logging instellen
logging.basicConfig(
    filename=f"{LOG_DIR}/cyberpet_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Flask app
app = Flask(__name__)
latest_scan_results = {
    "devices": [], "handshakes": [], "exploits": [], "packets": [], "bt_devices": [],
    "viking_level": 1, "graph": "", "report": ""
}

# e-Ink display initialiseren
try:
    display = Inky() if Inky else None
except Exception:
    display = None
    logging.warning("Geen e-Ink display gedetecteerd.")

# Q-learning parameters
Q_TABLE = {}
ALPHA = 0.1
GAMMA = 0.9
EPSILON = 0.2

# Viking-levels
VIKING_LEVELS = {
    1: "CyberViking: Krijger",
    2: "CyberViking: Berserker",
    3: "CyberViking: Jarl",
    4: "CyberViking: God"
}

def load_q_table():
    """Laad Q-tabel."""
    global Q_TABLE
    try:
        with open(Q_TABLE_FILE, "r") as f:
            Q_TABLE = json.load(f)
    except FileNotFoundError:
        Q_TABLE = {}

def save_q_table():
    """Sla Q-tabel op."""
    with open(Q_TABLE_FILE, "w") as f:
        json.dump(Q_TABLE, f, indent=4)

def update_display(message, level=1):
    """Update e-Ink display."""
    if display:
        try:
            img = Image.new("RGB", display.resolution)
            draw = ImageDraw.Draw(img)
            font = ImageFont.load_default()
            try:
                viking_img = Image.open(f"/home/pi/cyberpet/viking_assets/viking_level{level}.png").resize(display.resolution)
                img.paste(viking_img, (0, 0))
            except FileNotFoundError:
                ascii_art = [
                    "  ____  ",
                    " /    \\ ",
                    f"| {level}V{level} |",
                    " \\    / "
                ] if level < 4 else [
                    "  _^_  ",
                    " / 0 \\ ",
                    f"|{level}V{level}|",
                    " \\ 0 / "
                ]
                for i, line in enumerate(ascii_art):
                    draw.text((10, 50 + i*10), line, fill=(0, 0, 0))
            draw.text((10, 10), VIKING_LEVELS.get(level, "CyberViking"), fill=(0, 0, 0))
            draw.text((10, 30), message, fill=(0, 0, 0))
            display.set_image(img)
            display.show()
        except Exception as e:
            logging.error(f"Display update mislukt: {e}")

def get_viking_level(devices, handshakes, exploits, packets, bt_devices):
    """Bepaal Viking-level."""
    total = len(devices) + len(handshakes) * 3 + len(exploits) * 5 + len(packets) * 2 + len(bt_devices)
    if total >= 20:
        return 4
    elif total >= 15:
        return 3
    elif total >= 8:
        return 2
    return 1

def generate_graph(devices, handshakes, exploits, packets, bt_devices):
    """Genereer grafiek."""
    plt.figure(figsize=(4, 3))
    labels = ["Devices", "Handshakes", "Exploits", "Packets", "BT Devices"]
    values = [len(devices), len(handshakes), len(exploits), len(packets), len(bt_devices)]
    plt.bar(labels, values, color=["blue", "red", "green", "purple", "orange"])
    plt.title("CyberPet Results")
    buf = io.BytesIO()
    plt.savefig(buf, format="png")
    buf.seek(0)
    graph = base64.b64encode(buf.getvalue()).decode("utf-8")
    plt.close()
    return graph

def generate_pdf_report(devices, handshakes, exploits, packets, bt_devices):
    """Genereer PDF-rapport."""
    report_file = f"{REPORT_DIR}/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    c = canvas.Canvas(report_file, pagesize=letter)
    c.drawString(100, 750, "CyberPet Scan Report")
    c.drawString(100, 730, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.drawString(100, 710, f"Devices Found: {len(devices)}")
    c.drawString(100, 690, f"Handshakes Captured: {len(handshakes)}")
    c.drawString(100, 670, f"Exploits Executed: {len(exploits)}")
    c.drawString(100, 650, f"Packets Captured: {len(packets)}")
    c.drawString(100, 630, f"Bluetooth Devices: {len(bt_devices)}")
    c.save()
    return report_file

def detect_wifi_interfaces():
    """Detecteer beschikbare WiFi-interfaces."""
    result = subprocess.run(["iw", "dev"], capture_output=True, text=True).stdout
    return [line.split()[1] for line in result.stdout.splitlines() if "Interface" in line]

def scan_network(subnet, interface):
    """Scan netwerk met Nmap en Q-learning."""
    logging.info(f"Start netwerkscan op {subnet} met {interface}...")
    update_display("Scanning network...")
    
    devices = []
    state = f"{subnet}:{interface}"
    if state not in Q_TABLE:
        Q_TABLE[state] = {str(action): 0 for action in ACTIONS}

    for _ in range(5):
        action = random.choice(ACTIONS) if random.random() < EPSILON else max(Q_TABLE[state], key=lambda a: Q_TABLE[state][a])
        
        if action in PORTS:
            cmd = f"nmap -p {action} --open {subnet}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if "Nmap scan report" in line:
                    ip = line.split()[-1]
                    devices.append({"ip": ip, "port": action, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
                if f"{action}/tcp open" in line:
                    Q_TABLE[state][str(action)] += ALPHA * (1 + GAMMA * max(Q_TABLE[state].values()) - Q_TABLE[state][str(action)])
                else:
                    Q_TABLE[state][str(action)] += ALPHA * (-0.1 + GAMMA * max(Q_TABLE[state].values()) - Q_TABLE[state][str(action)])
    
    save_q_table()
    logging.info(f"Gevonden apparaten: {devices}")
    update_display(f"Found {len(devices)} devices")
    return devices

def capture_handshakes(interface):
    """Verzamel WiFi-handshakes."""
    logging.info(f"Start handshake-verzameling op {interface}...")
    update_display("Capturing handshakes...")
    
    try:
        cmd = f"sudo bettercap -iface {interface} -eval 'wifi.recon on; wifi.deauth all; sleep 60; quit'"
        subprocess.run(cmd, shell=True, capture_output=True, text=True)
        pcap_files = [f for f in os.listdir("/root") if f.endswith(".pcap")]
        logging.info(f"Verzamelde handshakes: {pcap_files}")
        update_display(f"Captured {len(pcap_files)} handshakes")
        return pcap_files
    except Exception as e:
        logging.error(f"Handshake-verzameling mislukt: {e}")
        return []

def load_plugins():
    """Laad plug-ins."""
    plugins = []
    for filename in os.listdir(PLUGIN_DIR):
        if filename.endswith(".py"):
            module_name = filename[:-3]
            spec = importlib.util.spec_from_file_location(module_name, f"{PLUGIN_DIR}/{filename}")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            if hasattr(module, "run"):
                plugins.append(module)
    return plugins

def check_cve(ip, port):
    """Controleer CVE's."""
    try:
        with open(CVE_FILE, "r") as f:
            cve_data = json.load(f)
        return cve_data.get(f"{ip}:{port}", [])
    except Exception:
        return []

def save_results(devices, handshakes, exploits, packets, bt_devices):
    """Sla resultaten op."""
    global latest_scan_results
    level = get_viking_level(devices, handshakes, exploits, packets, bt_devices)
    graph = generate_graph(devices, handshakes, exploits, packets, bt_devices)
    report = generate_pdf_report(devices, handshakes, exploits, packets, bt_devices)
    latest_scan_results = {
        "devices": devices,
        "handshakes": handshakes,
        "exploits": exploits,
        "packets": packets,
        "bt_devices": bt_devices,
        "viking_level": level,
        "graph": graph,
        "report": report
    }
    with open(f"{LOG_DIR}/results.json", "w") as f:
        json.dump(latest_scan_results, f, indent=4)
    update_display(f"Level {level}: {VIKING_LEVELS[level]}", level)

@app.route("/")
def index():
    """Flask-webinterface."""
    return render_template("index.html", results=latest_scan_results)

@app.route("/report")
def download_report():
    """Download PDF-rapport."""
    return send_file(latest_scan_results["report"], as_attachment=True)

@app.route("/control", methods=["POST"])
def control():
    """Beheer CyberPet via webinterface."""
    action = request.form.get("action")
    if action == "start_scan":
        threading.Thread(target=main, daemon=True).start()
        return "Scan gestart!"
    return "Ongeldige actie."

def run_flask():
    """Start Flask-webserver."""
    app.run(host="0.0.0.0", port=WEB_PORT, debug=False)

def main():
    """Hoofdloop."""
    logging.info("CyberPet gestart.")
    update_display("CyberPet Awake!", 1)  # Toon "CyberPet Awake!" bij opstarten
    load_q_table()
    
    # Start Flask
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()

    # Detecteer WiFi-interfaces
    global WIFI_INTERFACES
    WIFI_INTERFACES = detect_wifi_interfaces()

    while True:
        for interface in WIFI_INTERFACES:
            result = subprocess.run(["ip", "-4", "addr", "show", interface], capture_output=True, text=True)
            subnet = next((line.split()[1] for line in result.stdout.splitlines() if "inet" in line), None)
            if not subnet:
                logging.error(f"Geen subnet gevonden voor {interface}.")
                update_display(f"No subnet on {interface}!")
                continue

            devices = scan_network(subnet, interface)
            handshakes = capture_handshakes(interface)
            exploits = []
            packets = []
            bt_devices = []
            for plugin in load_plugins():
                try:
                    result = plugin.run(subnet, interface)
                    if plugin.__name__ == "metasploit_exploit":
                        exploits.extend(result)
                    elif plugin.__name__ == "packet_sniffer":
                        packets.extend(result)
                    elif plugin.__name__ == "bluetooth_scan":
                        bt_devices.extend(result)
                    else:
                        exploits.extend(result)
                except Exception as e:
                    logging.error(f"Plug-in mislukt: {e}")
            for device in devices:
                device["cves"] = check_cve(device["ip"], device["port"])
            save_results(devices, handshakes, exploits, packets, bt_devices)
        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("CyberPet gestopt door gebruiker.")
        update_display("CyberViking sleeps...", latest_scan_results["viking_level"])