# bluetooth_scan.py
def run(subnet, interface):
    """Scan Bluetooth-apparaten."""
    try:
        devices = bluetooth.discover_devices(lookup_names=True)
        return [{"device": f"{addr} ({name})"} for addr, name in devices]
    except Exception as e:
        return [{"result": f"Error: {e}"}]