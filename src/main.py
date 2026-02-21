import json
import yaml
from pathlib import Path

from src.parsers.syslog_parser import parse_auth_log
from src.parsers.nginx_parser import parse_nginx_access
from src.parsers.firewall_parser import parse_firewall_log

from src.detection.detectors import (
    detect_bruteforce,
    detect_web_recon,
    detect_port_scan
)
from src.detection.baseline import detect_baseline_spikes

from src.enrichment.ti_client import enrich_ip
from src.common.logger import log_alert, log_action
from src.response.responder import should_block, perform_response


def load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_lines_if_exists(file_path: Path) -> list[str]:
    if not file_path.exists():
        return []
    return file_path.read_text(encoding="utf-8", errors="ignore").splitlines()


def main():
    cfg = load_yaml("config/config.yaml")
    rules = load_yaml("config/rules.yaml")["rules"]

    sample_dir = Path(cfg["paths"]["sample_logs_dir"])
    alerts_path = cfg["paths"]["alerts_log"]
    actions_path = cfg["paths"]["actions_log"]

    enrichment_cfg = cfg.get("enrichment", {})
    enrichment_enabled = bool(enrichment_cfg.get("enable", False))

    response_cfg = cfg.get("response", {})
    response_enabled = bool(response_cfg.get("enable", False))


    # Parse logs (auth + nginx + firewall)

    auth_file = sample_dir / "auth.log"
    nginx_file = sample_dir / "nginx_access.log"
    fw_file = sample_dir / "firewall.log"

    auth_lines = load_lines_if_exists(auth_file)
    nginx_lines = load_lines_if_exists(nginx_file)
    fw_lines = load_lines_if_exists(fw_file)

    if not auth_lines and not nginx_lines and not fw_lines:
        print(f"No sample logs found in: {sample_dir}")
        return

    events = []

    if auth_lines:
        events.extend(parse_auth_log(auth_lines))

    if nginx_lines:
        events.extend(parse_nginx_access(nginx_lines))

    if fw_lines:
        events.extend(parse_firewall_log(fw_lines))

    total_alerts = 0
    total_actions = 0


    # Baseline anomaly detection

    baseline_alerts = detect_baseline_spikes(cfg, events)
    for a in baseline_alerts:
        total_alerts += 1
        base_msg = (
            f"{a['rule_id']} severity={a['severity']} src_ip={a['src_ip']} "
            f"count={a['count']} baseline_ema={a.get('baseline_ema')} mult={a.get('multiplier')}"
        )
        print(base_msg)
        log_alert(alerts_path, base_msg)


    # Apply rules

    for r in rules:
        rule_type = r.get("type")

        if rule_type == "brute_force":
            alerts = detect_bruteforce(
                events,
                threshold=int(r["threshold"]),
                window_minutes=int(r["window_minutes"])
            )

        elif rule_type == "web_recon":
            alerts = detect_web_recon(
                events,
                threshold=int(r.get("threshold", 5))
            )

        elif rule_type == "port_scan":
            alerts = detect_port_scan(
                events,
                threshold_ports=int(r.get("threshold_ports", 5))
            )

        else:
            continue

        
        # Handle alerts
        
        for a in alerts:
            total_alerts += 1

            window_part = f" window={a['window_minutes']}m" if a.get("window_minutes") else ""
            base_msg = (
                f"{a['rule_id']} severity={a['severity']} "
                f"src_ip={a['src_ip']} count={a['count']}{window_part}"
            )

            ti_data = {}
            msg = base_msg

            # ---------- TI ENRICHMENT (with cache) ----------
            if enrichment_enabled and a.get("src_ip"):
                try:
                    ti_data = enrich_ip(a["src_ip"], cfg)  # ← pass cfg for cache
                    msg = f"{base_msg} TI={json.dumps(ti_data, ensure_ascii=False)}"
                except Exception as e:
                    msg = f"{base_msg} TI_ERROR={str(e)}"

            print(msg)
            log_alert(alerts_path, msg)

            # ---------- AUTOMATED RESPONSE ----------
            # Auto respond for BRUTE_FORCE + PORT_SCAN
            if response_enabled and a.get("src_ip") and a.get("rule_id") in ("BRUTE_FORCE", "PORT_SCAN"):
                try:
                    if should_block(a, ti_data):
                        resp = perform_response(cfg, a, ti_data)
                        action_msg = f"BLOCKED ip={a['src_ip']} resp={json.dumps(resp, ensure_ascii=False)}"
                        total_actions += 1
                    else:
                        score = ti_data.get("abuse_score")
                        action_msg = f"NO_ACTION ip={a['src_ip']} abuse_score={score} (policy not met)"

                    print(action_msg)
                    log_action(actions_path, action_msg)

                except Exception as e:
                    err_msg = f"RESPONSE_ERROR ip={a.get('src_ip')} err={str(e)}"
                    print(err_msg)
                    log_action(actions_path, err_msg)

    print(
        f"Done. Alerts generated: {total_alerts}. Actions taken: {total_actions}. "
        f"Check {alerts_path} and {actions_path}"
    )


if __name__ == "__main__":
    main()