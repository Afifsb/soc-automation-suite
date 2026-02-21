import json
import time
from pathlib import Path
from typing import Any, Dict, Optional

def load_cache(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}

def save_cache(path: str, cache: Dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cache, indent=2), encoding="utf-8")

def get_cached(cache: Dict[str, Any], key: str, ttl_seconds: int) -> Optional[dict]:
    item = cache.get(key)
    if not item:
        return None
    ts = item.get("_cached_at")
    if not isinstance(ts, (int, float)):
        return None
    if time.time() - ts > ttl_seconds:
        return None
    return item.get("data")

def set_cached(cache: Dict[str, Any], key: str, data: dict) -> None:
    cache[key] = {"_cached_at": time.time(), "data": data}