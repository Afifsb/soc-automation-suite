import re
from typing import List
from src.common.schema import Event

LINE = re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<status>FAIL|SUCCESS) user=(?P<user>\S+) src_ip=(?P<ip>\S+)")

def parse_auth_log(lines: List[str]) -> List[Event]:
    events: List[Event] = []
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        m = LINE.search(raw)
        if not m:
            continue
        status = m.group("status")
        events.append(Event(
            timestamp=m.group("ts"),
            source="authlog",
            event_type="auth_fail" if status == "FAIL" else "auth_success",
            src_ip=m.group("ip"),
            user=m.group("user"),
            action=status.lower(),
            raw=raw
        ))
    return events
