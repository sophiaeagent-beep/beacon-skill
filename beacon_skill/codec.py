import json
from typing import Any, Dict, List, Optional, Tuple


BEACON_VERSION = 1
BEACON_HEADER_PREFIX = "[BEACON v"


def encode_envelope(payload: Dict[str, Any], version: int = BEACON_VERSION) -> str:
    """Encode a machine-readable Beacon envelope.

    Format:
      [BEACON v1]
      {"k":"v",...}
    """
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return f"[BEACON v{version}]\n{body}"


def _find_balanced_json(s: str, start: int) -> Optional[Tuple[int, int]]:
    """Return (start,end) indices of a balanced JSON object starting at/after start."""
    i = s.find("{", start)
    if i < 0:
        return None
    depth = 0
    in_str = False
    esc = False
    for j in range(i, len(s)):
        ch = s[j]
        if in_str:
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return (i, j + 1)
    return None


def decode_envelopes(text: str) -> List[Dict[str, Any]]:
    """Extract all Beacon envelopes found in a text blob."""
    out: List[Dict[str, Any]] = []
    idx = 0
    while True:
        h = text.find(BEACON_HEADER_PREFIX, idx)
        if h < 0:
            break
        # Find end of header line.
        nl = text.find("\n", h)
        if nl < 0:
            break
        # Look for a JSON object after the header.
        span = _find_balanced_json(text, nl + 1)
        if not span:
            idx = nl + 1
            continue
        j0, j1 = span
        blob = text[j0:j1]
        try:
            obj = json.loads(blob)
            out.append(obj)
        except Exception:
            pass
        idx = j1
    return out

