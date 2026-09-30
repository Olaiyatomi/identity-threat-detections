"""Build a small ATT&CK technique index from MITRE's enterprise-attack bundle.

Usage: python tools/update_attack.py [path-or-url]
Writes data/attack_index.json so validation runs offline and fast.
"""
import json
import sys
import urllib.request
from pathlib import Path

SRC = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUT = Path(__file__).resolve().parent.parent / "data" / "attack_index.json"


def load(src):
    if src.startswith("http"):
        with urllib.request.urlopen(src) as r:
            return json.load(r)
    return json.loads(Path(src).read_text())


def main():
    bundle = load(sys.argv[1] if len(sys.argv) > 1 else SRC)
    version = None
    techniques = {}
    for obj in bundle["objects"]:
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version")
        if obj.get("type") != "attack-pattern":
            continue
        ext = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        techniques[ext["external_id"]] = {
            "name": obj["name"],
            "tactics": sorted(p["phase_name"] for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"),
            "deprecated": bool(obj.get("x_mitre_deprecated") or obj.get("revoked")),
            "platforms": obj.get("x_mitre_platforms", []),
        }
    if version is None:
        version = bundle.get("spec_version", "unknown")
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps({"attack_version": version, "techniques": dict(sorted(techniques.items()))}, indent=1))
    print(f"wrote {len(techniques)} techniques (ATT&CK {version}) to {OUT}")


if __name__ == "__main__":
    main()
