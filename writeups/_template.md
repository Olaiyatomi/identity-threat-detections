# <Attack name>: how it works and how I detect it

**Detection:** `ITD-00X` in `detections/<folder>/`
**ATT&CK:** Txxxx <name>

## The attack in one paragraph
What the attacker wants, what they already have, and the steps they take.
Keep it concrete: which tool, which log line appears when.

## What it looks like in the logs
Show 3 to 5 fixture rows and point at the fields that give it away.

## The detection logic
Walk through the query in plain words. Why these thresholds? What did you
try first that did not work?

## False positives I planned for
Which benign cases are in `tests/benign.json`, and why each one matters.

## How I'd triage an alert
The first five things you would check, in order.

## What it misses
Be honest about the gaps. Interviewers trust this section most.
