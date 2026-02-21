import re
from typing import List, Optional
from src.common.schema import Event


NGINX_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)

def parse_nginx_access(lines: List[str]) -> List[Event]:
    events: List[Event] = []
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue

        m = NGINX_RE.match(raw)
        if not m:
            continue

        status = m.group("status")
        path = m.group("path")

        # simple event_type mapping
        event_type = "web_request"
        if status.startswith("4"):
            event_type = "web_4xx"
        if status == "404":
            event_type = "web_404"

        events.append(Event(
            timestamp=m.group("ts"),
            source="nginx",
            event_type=event_type,
            src_ip=m.group("ip"),
            action=status,
            raw=raw,
            enrichment={
                "method": m.group("method"),
                "path": path,
                "status": int(status),
            }
        ))
    return events
