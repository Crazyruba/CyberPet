# network_mapper.py
def run(subnet, interface):
    """Voer een gedetailleerde netwerksan uit."""
    try:
        cmd = f"nmap -A {subnet}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return [{"target": subnet, "details": result.stdout}]
    except Exception as e:
        return [{"target": subnet, "result": f"Error: {e}"}]