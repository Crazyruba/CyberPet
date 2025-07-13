# brute_force.py
def run(subnet, interface):
    """Simuleer een brute-force-aanval."""
    import random
    return [{"target": subnet, "result": random.choice(["Success", "Failed"])}]