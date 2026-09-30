"""Quality gate for every detection. Runs in CI on each push.

Checks: metadata schema, ATT&CK technique and tactic are real and current,
query file exists and uses its declared tables, fixtures only use known
columns, and each rule has at least one firing test and one benign test.
"""
import json
import sys

from jsonschema import Draft202012Validator

from common import ROOT, load_rules, load_table_schema

schema = json.loads((ROOT / "schema" / "detection.schema.json").read_text())
validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
attack = json.loads((ROOT / "data" / "attack_index.json").read_text())["techniques"]


def check(rule_dir, meta):
    errs = []
    for e in validator.iter_errors(meta):
        errs.append(f"schema: {'/'.join(map(str, e.path)) or '(root)'}: {e.message}")
    if errs:
        return errs

    for m in meta["attack"]:
        t = attack.get(m["technique"])
        if not t:
            errs.append(f"attack: {m['technique']} is not an ATT&CK technique")
        elif t["deprecated"]:
            errs.append(f"attack: {m['technique']} ({t['name']}) is deprecated or revoked")
        elif m["tactic"] not in t["tactics"]:
            errs.append(f"attack: tactic '{m['tactic']}' is not valid for {m['technique']}; use one of {t['tactics']}")

    qpath = rule_dir / meta["query"]
    if not qpath.exists():
        errs.append(f"query: {meta['query']} not found")
        return errs
    query = qpath.read_text()
    for table in meta["data_sources"]:
        try:
            load_table_schema(table)
        except FileNotFoundError as e:
            errs.append(f"data_sources: {e}")
        if table not in query:
            errs.append(f"data_sources: query never references {table}")

    firing = benign = 0
    for test in meta["tests"]:
        firing += test["expect"]["rows"] > 0
        benign += test["expect"]["rows"] == 0
        for table, fixture in test["fixtures"].items():
            fpath = rule_dir / fixture
            if not fpath.exists():
                errs.append(f"test '{test['name']}': fixture {fixture} not found")
                continue
            try:
                cols = load_table_schema(table)
            except FileNotFoundError as e:
                errs.append(f"test '{test['name']}': {e}")
                continue
            for i, row in enumerate(json.loads(fpath.read_text())):
                unknown = set(row) - set(cols)
                if unknown:
                    errs.append(f"{fixture} row {i}: columns not in {table} schema: {sorted(unknown)}")
    if not firing:
        errs.append("tests: need at least one test where the rule fires (rows > 0)")
    if not benign:
        errs.append("tests: need at least one benign test where the rule stays quiet (rows == 0)")
    return errs


def main():
    failed, seen = 0, {}
    for rule_dir, meta in load_rules():
        errs = check(rule_dir, meta)
        rid = meta.get("id")
        if rid in seen:
            errs.append(f"id {rid} already used by {seen[rid]}")
        seen[rid] = rule_dir.name
        status = "FAIL" if errs else "ok"
        print(f"[{status}] {rule_dir.name}")
        for e in errs:
            print(f"    - {e}")
        failed += bool(errs)
    print(f"\n{len(seen)} rules checked, {failed} failed")
    sys.exit(1 if failed or not seen else 0)


if __name__ == "__main__":
    main()
