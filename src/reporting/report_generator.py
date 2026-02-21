import csv
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml



# Helpers / parsing

ALERT_LINE = re.compile(r"^\[(?P<ts>[^]]+)\]\s+ALERT\s+(?P<msg>.*)$")
ACTION_LINE = re.compile(r"^\[(?P<ts>[^]]+)\]\s+ACTION\s+(?P<msg>.*)$")


@dataclass
class AlertRecord:
    ts: str
    rule_id: str = ""
    severity: str = ""
    src_ip: str = ""
    count: Optional[int] = None
    window_minutes: Optional[int] = None
    ti: Optional[Dict[str, Any]] = None
    raw_msg: str = ""


@dataclass
class ActionRecord:
    ts: str
    action_type: str = ""   
    ip: str = ""
    abuse_score: Optional[int] = None
    raw_msg: str = ""


def load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def parse_kv_tokens(base_msg: str) -> Dict[str, str]:
    """
    Parses tokens like: key=value key=value ...
    Safe for your current log format.
    """
    out: Dict[str, str] = {}
    for token in base_msg.split():
        if "=" in token:
            k, v = token.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def split_msg_and_ti(msg: str) -> Tuple[str, Optional[dict]]:
    """
    Your alert message looks like:
      BRUTE_FORCE severity=high src_ip=... count=5 window=5m TI={...json...}
    This splits it into base part + TI JSON object.
    """
    if " TI=" not in msg:
        return msg, None

    base, ti_part = msg.split(" TI=", 1)
    ti_part = ti_part.strip()
    try:
        ti_obj = json.loads(ti_part)
        return base.strip(), ti_obj
    except Exception:
        
        return base.strip(), None


def parse_alerts(alerts_log_path: str) -> List[AlertRecord]:
    records: List[AlertRecord] = []
    p = Path(alerts_log_path)
    if not p.exists():
        return records

    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = ALERT_LINE.match(line.strip())
        if not m:
            continue

        ts = m.group("ts")
        msg = m.group("msg")
        base_msg, ti_obj = split_msg_and_ti(msg)

        
        rule_id = base_msg.split()[0] if base_msg else ""

        kv = parse_kv_tokens(base_msg)

        
        window_minutes = None
        w = kv.get("window")
        if w and w.endswith("m"):
            try:
                window_minutes = int(w[:-1])
            except Exception:
                window_minutes = None

        count_val = None
        if "count" in kv:
            try:
                count_val = int(kv["count"])
            except Exception:
                count_val = None

        rec = AlertRecord(
            ts=ts,
            rule_id=rule_id,
            severity=kv.get("severity", ""),
            src_ip=kv.get("src_ip", ""),
            count=count_val,
            window_minutes=window_minutes,
            ti=ti_obj,
            raw_msg=msg,
        )
        records.append(rec)

    return records


def parse_actions(actions_log_path: str) -> List[ActionRecord]:
    records: List[ActionRecord] = []
    p = Path(actions_log_path)
    if not p.exists():
        return records

    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = ACTION_LINE.match(line.strip())
        if not m:
            continue

        ts = m.group("ts")
        msg = m.group("msg")

        
        action_type = msg.split()[0] if msg else ""

        kv = parse_kv_tokens(msg)

        ip = kv.get("ip", "")

        abuse_score = None
        if "abuse_score" in kv:
            try:
                abuse_score = int(kv["abuse_score"])
            except Exception:
                abuse_score = None

        records.append(ActionRecord(
            ts=ts,
            action_type=action_type,
            ip=ip,
            abuse_score=abuse_score,
            raw_msg=msg
        ))

    return records



def ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def write_csv(path: str, rows: List[dict], fieldnames: List[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def make_markdown_report(
    alerts: List[AlertRecord],
    actions: List[ActionRecord],
    generated_at: str
) -> str:
    
    by_rule = Counter([a.rule_id for a in alerts if a.rule_id])
    by_sev = Counter([a.severity for a in alerts if a.severity])
    top_ips = Counter([a.src_ip for a in alerts if a.src_ip]).most_common(10)

    action_counts = Counter([a.action_type for a in actions if a.action_type])
    blocked_ips = sorted({a.ip for a in actions if a.action_type == "BLOCKED" and a.ip})

    
    recent_alerts = alerts[-15:]

    lines: List[str] = []
    lines.append(f"# SOC Automation Report\n")
    lines.append(f"**Generated at:** {generated_at}\n")
    lines.append("## Summary\n")
    lines.append(f"- Total alerts: **{len(alerts)}**")
    lines.append(f"- Total actions: **{len(actions)}**")
    lines.append(f"- Blocked IPs (unique): **{len(blocked_ips)}**\n")

    lines.append("## Alerts by Rule\n")
    if by_rule:
        for k, v in by_rule.most_common():
            lines.append(f"- {k}: {v}")
    else:
        lines.append("- (No alerts found)")
    lines.append("")

    lines.append("## Alerts by Severity\n")
    if by_sev:
        for k, v in by_sev.most_common():
            lines.append(f"- {k}: {v}")
    else:
        lines.append("- (No severity data)")
    lines.append("")

    lines.append("## Top Source IPs (from alerts)\n")
    if top_ips:
        for ip, c in top_ips:
            lines.append(f"- {ip}: {c}")
    else:
        lines.append("- (No IPs found)")
    lines.append("")

    lines.append("## Actions Summary\n")
    if action_counts:
        for k, v in action_counts.most_common():
            lines.append(f"- {k}: {v}")
    else:
        lines.append("- (No actions found)")
    lines.append("")

    lines.append("## Blocked IPs\n")
    if blocked_ips:
        for ip in blocked_ips:
            lines.append(f"- {ip}")
    else:
        lines.append("- (No IPs blocked)")
    lines.append("")

    lines.append("## Recent Alerts (last 15)\n")
    lines.append("| Time | Rule | Severity | Src IP | Count | TI abuse_score |")
    lines.append("|---|---|---|---|---:|---:|")
    for a in recent_alerts:
        abuse = ""
        if a.ti and "abuse_score" in a.ti:
            abuse = str(a.ti.get("abuse_score"))
        lines.append(
            f"| {a.ts} | {a.rule_id} | {a.severity} | {a.src_ip} | {a.count or ''} | {abuse} |"
        )

    lines.append("\n## Notes\n")
    lines.append("- This report is generated from `outputs/alerts.log` and `outputs/actions.log`.")
    lines.append("- TI enrichment currently supports AbuseIPDB (extendable).")
    lines.append("- Automated response is a safe prototype using a mock firewall API.\n")

    return "\n".join(lines)


def main():
    cfg = load_yaml("config/config.yaml")

    alerts_path = cfg["paths"]["alerts_log"]
    actions_path = cfg["paths"]["actions_log"]
    reports_dir = cfg["paths"]["reports_dir"]

    ensure_dir(reports_dir)

    alerts = parse_alerts(alerts_path)
    actions = parse_actions(actions_path)

    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    generated_at = datetime.now().isoformat(timespec="seconds")

    
    alerts_csv = str(Path(reports_dir) / f"alerts_{ts}.csv")
    actions_csv = str(Path(reports_dir) / f"actions_{ts}.csv")

    alerts_rows = []
    for a in alerts:
        row = asdict(a)
        
        row["ti"] = json.dumps(a.ti, ensure_ascii=False) if a.ti else ""
        alerts_rows.append(row)

    actions_rows = [asdict(x) for x in actions]

    write_csv(
        alerts_csv,
        alerts_rows,
        fieldnames=["ts", "rule_id", "severity", "src_ip", "count", "window_minutes", "ti", "raw_msg"]
    )
    write_csv(
        actions_csv,
        actions_rows,
        fieldnames=["ts", "action_type", "ip", "abuse_score", "raw_msg"]
    )

    
    report_md = str(Path(reports_dir) / f"soc_report_{ts}.md")
    md = make_markdown_report(alerts, actions, generated_at)
    Path(report_md).write_text(md, encoding="utf-8")

    print(f"Report generated:\n- {report_md}\n- {alerts_csv}\n- {actions_csv}")


if __name__ == "__main__":
    main()
