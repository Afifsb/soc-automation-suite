import requests

def block_ip(base_url: str, ip: str, reason: str) -> dict:
    url = f"{base_url.rstrip('/')}/block"
    r = requests.post(url, json={"ip": ip, "reason": reason}, timeout=10)
    return r.json()

def list_blocked(base_url: str) -> dict:
    url = f"{base_url.rstrip('/')}/blocked"
    r = requests.get(url, timeout=10)
    return r.json()
