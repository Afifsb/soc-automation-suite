from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List

from src.common.schema import Event



# BRUTE FORCE DETECTION
def detect_bruteforce(events: List[Event], threshold: int, window_minutes: int) -> List[Dict]:
    """
    Looks for >= threshold auth_fail events from same src_ip within window.
    """
    window = timedelta(minutes=window_minutes)
    buckets = defaultdict(deque)
    alerts: List[Dict] = []

    for e in events:
        if e.event_type != "auth_fail" or not e.src_ip:
            continue

        t = datetime.strptime(e.timestamp, "%Y-%m-%d %H:%M:%S")
        q = buckets[e.src_ip]
        q.append(t)

        while q and (t - q[0]) > window:
            q.popleft()

        if len(q) >= threshold:
            alerts.append({
                "rule_id": "BRUTE_FORCE",
                "severity": "high",
                "src_ip": e.src_ip,
                "count": len(q),
                "window_minutes": window_minutes
            })
            q.clear()

    return alerts


# WEB RECON DETECTION

def detect_web_recon(events: List[Event], threshold: int = 5) -> List[Dict]:
    """
    Detects reconnaissance via 404 hits on sensitive paths.
    """
    sensitive_keywords = [
        "/admin", "/wp-admin", "/login", "/.env", "/phpmyadmin",
        "/administrator", "/config", "/.git", "/backup"
    ]

    hits = defaultdict(int)
    alerts: List[Dict] = []

    for e in events:
        if e.source != "nginx":
            continue
        if e.event_type != "web_404":
            continue
        if not e.src_ip:
            continue

        path = ""
        if isinstance(e.enrichment, dict):
            path = str(e.enrichment.get("path", ""))

        if any(k in path for k in sensitive_keywords):
            hits[e.src_ip] += 1

    for ip, count in hits.items():
        if count >= threshold:
            alerts.append({
                "rule_id": "WEB_RECON",
                "severity": "medium",
                "src_ip": ip,
                "count": count,
                "window_minutes": None
            })

    return alerts



# PORT SCAN DETECTION 

def detect_port_scan(events: List[Event], threshold_ports: int = 5) -> List[Dict]:
    """
    Detects port scanning:
    Same IP connecting to many different destination ports.
    Works on firewall log events.
    """
    ports_by_ip = defaultdict(set)
    alerts: List[Dict] = []

    for e in events:
        if e.source != "firewall":
            continue
        if not e.src_ip:
            continue
        if not isinstance(e.enrichment, dict):
            continue

        dpt = e.enrichment.get("dst_port")
        if isinstance(dpt, int):
            ports_by_ip[e.src_ip].add(dpt)

    for ip, ports in ports_by_ip.items():
        if len(ports) >= threshold_ports:
            alerts.append({
                "rule_id": "PORT_SCAN",
                "severity": "high",
                "src_ip": ip,
                "count": len(ports),
                "window_minutes": None
            })

    return alerts