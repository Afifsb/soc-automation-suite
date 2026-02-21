from dataclasses import dataclass, field
from typing import Any, Dict, Optional

@dataclass
class Event:
    timestamp: str
    source: str
    event_type: str
    src_ip: Optional[str] = None
    user: Optional[str] = None
    action: Optional[str] = None
    raw: str = ""
    enrichment: Dict[str, Any] = field(default_factory=dict)
