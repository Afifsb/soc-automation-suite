from src.response.mock_firewall_client import block_ip

def should_block(alert: dict, ti_data: dict) -> bool:
    """
    Demo SOC policy (behavior + TI):

    Block when:
    - severity is high AND (
        TI abuse_score >= 25
        OR brute-force count >= 5
      )

    Why: TI can be 0 for new/clean IPs, but behavior can still be malicious.
    """
    if alert.get("severity") != "high":
        return False

    score = int(ti_data.get("abuse_score") or 0)
    count = int(alert.get("count") or 0)

    # Reputation-based block
    if score >= 25:
        return True

    # Behavior-based block for brute-force
    if alert.get("rule_id") == "BRUTE_FORCE" and count >= 5:
        return True

    return False


def perform_response(cfg: dict, alert: dict, ti_data: dict) -> dict:
    base_url = cfg["response"]["mock_firewall_url"]

    score = ti_data.get("abuse_score")
    count = alert.get("count")
    reason = f"{alert.get('rule_id')} count={count} abuse_score={score}"

    return block_ip(base_url, alert["src_ip"], reason)
