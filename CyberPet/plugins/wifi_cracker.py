# wifi_cracker.py
def run(subnet, interface):
    """Probeer WiFi-handshakes te kraken met Hashcat."""
    try:
        cmd = "hashcat -m 22000 /root/*.pcap -o /home/pi/cyberpet/data/cracked.txt"
        subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return [{"target": subnet, "result": "Cracking attempted"}]
    except Exception as e:
        return [{"target": subnet, "result": f"Error: {e}"}]