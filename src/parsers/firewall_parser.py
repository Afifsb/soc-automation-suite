import re
from typing import List
from src.common.schema import Event


FW_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+)\s+DPT=(?P<dpt>\d+)\s+ACTION=(?P<action>\S+)"
)

def parse_firewall_log(lines: List[str]) -> List[Event]:
    events: List[Event] = []
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        m = FW_RE.match(raw)
        if not m:
            continue

        events.append(Event(
            timestamp=m.group("ts"),
            source="firewall",
            event_type="fw_conn",
            src_ip=m.group("src"),
            raw=raw,
            enrichment={
                "dst_ip": m.group("dst"),
                "dst_port": int(m.group("dpt")),
                "action": m.group("action"),
            }
        ))
    return events