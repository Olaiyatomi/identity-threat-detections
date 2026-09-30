"""Build a small MITRE ATLAS technique index (attacks on AI systems).

Usage: python tools/update_atlas.py [path-or-url]
Writes data/atlas_index.json. Sub-techniques inherit their parent's tactics.
"""
import json
import sys
import urllib.request
from pathlib import Path

import yaml

SRC = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
OUT = Path(__file__).resolve().parent.parent / "data" / "atlas_index.json"


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else SRC
    text = urllib.request.urlopen(src).read() if src.startswith("http") else Path(src).read_bytes()
    data = yaml.safe_load(text)
    matrix = data["matrices"][0]
    tactic_names = {t["id"]: t["name"] for t in matrix["tactics"]}
    techniques = {}
    for t in matrix["techniques"]:
        techniques[t["id"]] = {"name": t["name"], "tactics": [tactic_names.get(x, x) for x in t.get("tactics", [])],
                               "parent": t.get("specializes") or t.get("subtechnique-of")}
    for tid, t in techniques.items():
        if not t["tactics"] and t["parent"] in techniques:
            t["tactics"] = techniques[t["parent"]]["tactics"]
            t["name"] = f"{techniques[t['parent']]['name']}: {t['name']}"
    OUT.write_text(json.dumps({"atlas_version": data.get("version"),
                               "techniques": {k: {"name": v["name"], "tactics": v["tactics"]} for k, v in sorted(techniques.items())}}, indent=1))
    print(f"wrote {len(techniques)} ATLAS techniques (v{data.get('version')}) to {OUT}")


if __name__ == "__main__":
    main()
