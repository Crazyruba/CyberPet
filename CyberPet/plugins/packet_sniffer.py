# packet_sniffer.py
def run(subnet, interface):
    """Sniff netwerkpackets met tcpdump."""
    try:
        cmd = f"tcpdump -i {interface} -c 100 -w /home/pi/cyberpet/data/packets.pcap"
        subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return [{"interface": interface, "packets": "100 packets captured"}]
    except Exception as e:
        return [{"interface": interface, "result": f"Error: {e}"}]