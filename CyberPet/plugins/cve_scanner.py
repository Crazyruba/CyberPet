# cve_scanner.py
def run(subnet, interface):
    """Scan op CVE's met Nmap scripts."""
    try:
        cmd = f"nmap --script vuln {subnet}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        cves = []
        for line in result.stdout.splitlines():
            if "CVE" in line:
                cves.append({"target": subnet, "cve": line})
        return cves
    except Exception as e:
        return [{"target": subnet, "result": f"Error: {e}"}]