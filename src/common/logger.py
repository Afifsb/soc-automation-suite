from pathlib import Path
from datetime import datetime

def append_line(path: str, line: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def log_alert(alerts_path: str, msg: str) -> None:
    ts = datetime.now().isoformat(timespec="seconds")
    append_line(alerts_path, f"[{ts}] ALERT {msg}")

def log_action(actions_path: str, msg: str) -> None:
    ts = datetime.now().isoformat(timespec="seconds")
    append_line(actions_path, f"[{ts}] ACTION {msg}")
