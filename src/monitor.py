import time
from pathlib import Path
import yaml

from src.main import main as run_once

def load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def snapshot_mtimes(folder: Path) -> dict[str, float]:
    mt = {}
    for p in folder.glob("*.log"):
        try:
            mt[str(p)] = p.stat().st_mtime
        except Exception:
            pass
    return mt

def main():
    cfg = load_yaml("config/config.yaml")
    sample_dir = Path(cfg["paths"]["sample_logs_dir"])
    interval = int(cfg.get("monitor", {}).get("interval_seconds", 10))

    print(f"[monitor] Watching: {sample_dir} (every {interval}s)")
    last = snapshot_mtimes(sample_dir)

    # initial run
    run_once()

    while True:
        time.sleep(interval)
        now = snapshot_mtimes(sample_dir)
        if now != last:
            print("[monitor] Change detected. Running pipeline...")
            run_once()
            last = now

if __name__ == "__main__":
    main()