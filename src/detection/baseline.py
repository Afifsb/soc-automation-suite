import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

from src.common.schema import Event


@dataclass
class BaselineMetric:
    ema: float = 0.0        
    last_updated: str = ""  


def _load_state(path: str) -> Dict[str, BaselineMetric]:
    p = Path(path)
    if not p.exists():
        return {}

    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        out: Dict[str, BaselineMetric] = {}
        for k, v in raw.items():
            out[k] = BaselineMetric(
                ema=float(v.get("ema", 0.0)),
                last_updated=str(v.get("last_updated", "")),
            )
        return out
    except Exception:
        return {}


def _save_state(path: str, state: Dict[str, BaselineMetric]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    raw = {k: {"ema": v.ema, "last_updated": v.last_updated} for k, v in state.items()}
    p.write_text(json.dumps(raw, indent=2), encoding="utf-8")


def _update_ema(old: float, new: float, alpha: float) -> float:
    if old <= 0:
        return float(new)
    return (alpha * float(new)) + ((1 - alpha) * float(old))


def _count_current(events: List[Event], metric: str) -> int:
    """
    Count "current run" totals for a metric.
    For a simple baseline, we count all events in the log file for this run.
    """
    if metric == "auth_fail_total":
        return sum(1 for e in events if e.event_type == "auth_fail")
    if metric == "nginx_404_total":
        return sum(1 for e in events if e.source == "nginx" and e.event_type == "web_404")
    return 0


def detect_baseline_spikes(cfg: dict, events: List[Event]) -> List[dict]:
    """
    Creates anomaly alerts if current count is much higher than baseline EMA.
    Writes/updates baseline state in a JSON file.
    """
    baseline_cfg = cfg.get("baseline", {})
    if not baseline_cfg.get("enable", False):
        return []

    state_file = baseline_cfg.get("file", "data/enriched_events/baseline_state.json")
    alpha = float(baseline_cfg.get("alpha", 0.2))
    spike_multiplier = float(baseline_cfg.get("spike_multiplier", 3))
    min_baseline = float(baseline_cfg.get("min_baseline", 3))

    state = _load_state(state_file)
    now_iso = datetime.now().isoformat(timespec="seconds")

    alerts: List[dict] = []

    for metric in ["auth_fail_total", "nginx_404_total"]:
        current = _count_current(events, metric)

        old = state.get(metric, BaselineMetric()).ema
        baseline = max(old, min_baseline)

        # Detect spike BEFORE updating baseline (important)
        if current > spike_multiplier * baseline:
            rule_id = "BASELINE_AUTH_FAIL_SPIKE" if metric == "auth_fail_total" else "BASELINE_NGINX_404_SPIKE"
            sev = "high" if metric == "auth_fail_total" else "medium"
            alerts.append({
                "rule_id": rule_id,
                "severity": sev,
                "src_ip": "multiple",
                "count": current,
                "window_minutes": None,
                "baseline_ema": round(old, 2),
                "multiplier": spike_multiplier
            })

        # Update baseline EMA
        new_ema = _update_ema(old, current, alpha)
        state[metric] = BaselineMetric(ema=new_ema, last_updated=now_iso)

    _save_state(state_file, state)
    return alerts
