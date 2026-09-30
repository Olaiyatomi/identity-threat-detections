# Identity Threat Detections

Detection-as-code for identity attacks in Microsoft Entra ID and Microsoft 365.
Every rule is KQL that runs as-is in Microsoft Sentinel, and every rule ships
with attack and benign test data that CI replays through a real Kusto engine
before anything merges.

Identity is where most modern intrusions start: stolen sessions, MFA push
bombing, consent phishing, quiet role changes. This repo is where I build and
test detections for that layer.

**Coverage:** see [coverage/COVERAGE.md](coverage/COVERAGE.md), or load
[`coverage/attack-layer.json`](coverage/attack-layer.json) in the
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

## Detections

| ID | Detection | ATT&CK | Status |
|---|---|---|---|
| ITD-001 | [MFA fatigue burst with optional approval](detections/mfa-fatigue/) | T1621 | experimental |
| ITD-002 | [OAuth consent grants high-risk delegated permissions](detections/illicit-oauth-consent/) | T1528 | experimental |
| ITD-003 | [Password spray from a single IP against many accounts](detections/password-spray/) | T1110.003 | experimental |
| ITD-004 | [Privileged role assigned directly outside PIM](detections/priv-role-outside-pim/) | T1098.003 | experimental |
| ITD-005 | [New secret or certificate added to an application](detections/app-credential-added/) | T1098.001 | experimental |
| ITD-006 | [Conditional Access policy deleted, disabled or set to report-only](detections/ca-policy-weakened/) | T1556.009 | experimental |
| ITD-007 | [Inbox rule forwards mail out or hides it from the user](detections/inbox-rule-forward-hide/) | T1114.003 | experimental |

Planned work is in [roadmap.yml](roadmap.yml) and shows as pale cells on the coverage map.

## How it works

```
detections/<name>/
  rule.yml        metadata: ATT&CK mapping, severity, schedule, tuning,
                  false positives, triage steps, and test cases
  query.kql       the production query, unchanged between test and Sentinel
  tests/
    attack.json   log rows that must make the rule fire
    benign.json   look-alike normal activity that must stay quiet
```

On every push, GitHub Actions runs two jobs:

1. **validate** (`tools/validate.py`)
   - metadata matches [the schema](schema/detection.schema.json)
   - each ATT&CK technique exists, is not deprecated, and the tactic is valid for it
     (checked against MITRE's own data in `data/attack_index.json`)
   - the query references every table it claims to use
   - fixtures only use real columns from `tables/*.json`
   - every rule has at least one firing test and one benign test
   - the coverage map is regenerated and must match what is committed
2. **test** (`tools/run_tests.py`)
   - starts the Azure Data Explorer emulator (Kustainer) as a service container
   - for each test, rebuilds the tables, loads the fixture rows with timestamps
     shifted relative to now (so `ago()` lookbacks behave like production),
     runs the rule's query and checks the row count and key fields

## Running it locally

```bash
pip install -r requirements.txt
python tools/validate.py
python tools/coverage.py

# KQL tests need the emulator (Docker)
docker run -d -e ACCEPT_EULA=Y -p 8080:8080 mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
python tools/run_tests.py
```

`python tools/run_tests.py --dry-run` prints the exact KQL the harness sends,
which helps when a fixture does not load the way you expect.

## Adding a detection

1. Copy an existing folder in `detections/` and give it the next `ITD-` id.
2. Write the query. Put thresholds in `let` statements at the top and explain
   them under `tuning` in `rule.yml`.
3. Build `tests/attack.json` from what the attack really produces, and
   `tests/benign.json` from the normal activity most likely to look like it.
4. Run the validator and tests, then `python tools/coverage.py`.
5. Write it up in `writeups/` using the template.

## Data

All test data is synthetic and uses the documentation domain `contoso.ca`.
Nothing here comes from any employer's environment.
