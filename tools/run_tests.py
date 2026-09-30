"""Run every detection's KQL against its test fixtures in a real Kusto engine.

CI starts the Azure Data Explorer emulator (Kustainer) as a service container.
For each test we recreate the rule's tables from tables/*.json, load the
fixture rows (times relative to now), run the unmodified production query,
and check the result.

  python tools/run_tests.py                  # against http://localhost:8080
  python tools/run_tests.py --dry-run        # print the generated KQL only
  python tools/run_tests.py --only ITD-001   # one rule
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request

from common import load_fixture, load_rules, load_table_schema

CAST = {"datetime": "todatetime", "string": "tostring", "int": "toint", "long": "tolong",
        "real": "toreal", "bool": "tobool", "dynamic": ""}


class Kusto:
    def __init__(self, url, db, dry=False):
        self.url, self.db, self.dry = url.rstrip("/"), db, dry

    def _call(self, kind, csl):
        if self.dry:
            print(f"--- {kind} ---\n{csl}\n")
            return []
        body = json.dumps({"db": self.db, "csl": csl}).encode()
        req = urllib.request.Request(f"{self.url}/v1/rest/{kind}", body, {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.load(r)
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"Kusto {kind} failed ({e.code}): {e.read().decode()[:800]}") from None
        table = data["Tables"][0]
        cols = [c["ColumnName"] for c in table["Columns"]]
        return [dict(zip(cols, row)) for row in table["Rows"]]

    def mgmt(self, csl):
        return self._call("mgmt", csl)

    def query(self, csl):
        return self._call("query", csl)

    def wait_ready(self, timeout=180):
        if self.dry:
            return
        start = time.time()
        while time.time() - start < timeout:
            try:
                self.mgmt(".show version")
                return
            except Exception:
                time.sleep(3)
        raise RuntimeError("Kusto emulator did not become ready")


def load_table(k, table, rows):
    cols = load_table_schema(table)
    k.mgmt(f".drop table {table} ifexists")
    k.mgmt(f".create table {table} (" + ", ".join(f"{c}:{t}" for c, t in cols.items()) + ")")
    if not rows:
        return
    proj = ", ".join(f"{c}={CAST[t]}(r['{c}'])" if CAST[t] else f"{c}=r['{c}']" for c, t in cols.items())
    k.mgmt(f".set-or-append {table} <| print r = dynamic({json.dumps(rows)}) | mv-expand r | project {proj}")


def norm(v):
    if isinstance(v, str) and v[:1] in "[{":
        try:
            v = json.loads(v)
        except ValueError:
            pass
    if isinstance(v, list):
        return sorted(json.dumps(x, sort_keys=True) if not isinstance(x, str) else x for x in v)
    return v


def matches(row, want):
    return all(norm(row.get(k)) == norm(v) for k, v in want.items())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8080")
    ap.add_argument("--db", default="NetDefaultDB")
    ap.add_argument("--only")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    k = Kusto(args.url, args.db, args.dry_run)
    k.wait_ready()
    total = failed = 0
    for rule_dir, meta in load_rules():
        if args.only and meta["id"] != args.only:
            continue
        query = (rule_dir / meta["query"]).read_text()
        for test in meta["tests"]:
            total += 1
            for table in meta["data_sources"]:
                fixture = test["fixtures"].get(table)
                load_table(k, table, load_fixture(rule_dir / fixture) if fixture else [])
            rows = k.query(query)
            if args.dry_run:
                continue
            problems = []
            if len(rows) != test["expect"]["rows"]:
                problems.append(f"expected {test['expect']['rows']} rows, got {len(rows)}")
            for want in test["expect"].get("match", []):
                if not any(matches(r, want) for r in rows):
                    problems.append(f"no row matched {want}")
            label = f"{meta['id']} {test['name']}"
            if problems:
                failed += 1
                print(f"[FAIL] {label}")
                for p in problems:
                    print(f"    - {p}")
                for r in rows[:5]:
                    print(f"    row: {json.dumps(r, default=str)[:300]}")
            else:
                print(f"[pass] {label}")
    if not args.dry_run:
        print(f"\n{total} tests, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
