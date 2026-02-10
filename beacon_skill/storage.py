import json
import time
from pathlib import Path
from typing import Any, Dict, Optional


def _dir() -> Path:
    d = Path.home() / ".beacon"
    d.mkdir(parents=True, exist_ok=True)
    return d


def append_jsonl(name: str, item: Dict[str, Any]) -> None:
    path = _dir() / name
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(item, sort_keys=True) + "\n")


def read_state() -> Dict[str, Any]:
    path = _dir() / "state.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_state(state: Dict[str, Any]) -> None:
    path = _dir() / "state.json"
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def get_last_ts(key: str) -> Optional[float]:
    state = read_state()
    v = state.get("last_ts", {}).get(key)
    try:
        return float(v)
    except Exception:
        return None


def set_last_ts(key: str, ts: Optional[float] = None) -> None:
    state = read_state()
    state.setdefault("last_ts", {})
    state["last_ts"][key] = float(ts if ts is not None else time.time())
    write_state(state)

