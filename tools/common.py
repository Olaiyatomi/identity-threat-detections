import json
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DETECTIONS = ROOT / "detections"
TABLES = ROOT / "tables"


def _dates_to_str(obj):
    if isinstance(obj, dict):
        return {k: _dates_to_str(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_dates_to_str(v) for v in obj]
    if isinstance(obj, (date, datetime)):
        return obj.isoformat()
    return obj


def load_rules():
    """Yield (rule_dir, metadata) for every detection folder."""
    for path in sorted(DETECTIONS.glob("*/rule.yml")):
        yield path.parent, _dates_to_str(yaml.safe_load(path.read_text()))


def load_table_schema(name):
    path = TABLES / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"no table schema for {name} (expected {path})")
    return json.loads(path.read_text())["columns"]


_REL = re.compile(r"^-(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$")


def resolve_time(value, now):
    """Fixtures store times relative to 'now' (e.g. '-12m', '-1h30m') so tests
    keep working with ago() lookbacks. Absolute ISO strings pass through."""
    if isinstance(value, str):
        m = _REL.match(value)
        if m and any(m.groups()):
            d, h, mi, s = (int(x or 0) for x in m.groups())
            return (now - timedelta(days=d, hours=h, minutes=mi, seconds=s)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return value


def load_fixture(path, now=None):
    now = now or datetime.now(timezone.utc)
    rows = json.loads(Path(path).read_text())
    for row in rows:
        for col in ("TimeGenerated", "Timestamp"):
            if col in row:
                row[col] = resolve_time(row[col], now)
    return rows
