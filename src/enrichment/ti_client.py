from src.enrichment.abuseipdb import check_ip
from src.enrichment.cache import load_cache, save_cache, get_cached, set_cached

def enrich_ip(ip: str, cfg: dict | None = None) -> dict:
    """
    Enrich IP using TI sources with caching.
    """
    cache_file = "data/enriched_events/ti_cache.json"
    ttl_hours = 24

    if cfg:
        enr = cfg.get("enrichment", {})
        cache_file = enr.get("cache_file", cache_file)
        ttl_hours = int(enr.get("cache_ttl_hours", ttl_hours))

    ttl_seconds = ttl_hours * 3600
    cache = load_cache(cache_file)
    key = f"ip:{ip}"

    cached = get_cached(cache, key, ttl_seconds)
    if cached is not None:
        cached["_cache"] = "hit"
        return cached

    result = check_ip(ip)

    if "error" in result:
        result["_cache"] = "miss_error"
        return result

    # Add severity (your logic)
    score = int(result.get("abuse_score", 0))
    if score >= 75:
        result["severity"] = "high"
    elif score >= 30:
        result["severity"] = "medium"
    else:
        result["severity"] = "low"

    result["_cache"] = "miss"
    set_cached(cache, key, result)
    save_cache(cache_file, cache)
    return result