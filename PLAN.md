# Build plan (3 to 5 hours a week)

Delete this file before making the repo public, or keep it private in a fork.

## Week 1: get it live
- Create the public repo `identity-threat-detections` on GitHub and push this code.
- Watch the first Actions run. If the `test` job fails, send the log to Claude.
  The KQL has not been run against the emulator yet, so the first run is the real test.
- Read both detections line by line until you can explain every line out loud.
  Change anything you would do differently. They are yours now.

## Week 2: first detection written by you
- Pick password spray (T1110.003) from roadmap.yml. It is well documented and
  uses SigninLogs, which you already know from work.
- Write the query, attack fixture and benign fixture yourself. Ask Claude to
  review, not to write.
- Start writeups/mfa-fatigue.md from the template.

## Week 3: harder one
- AiTM session token replay (T1539). This is the one interviewers will ask
  about. Research how Evilginx-style proxies show up in SigninLogs and
  AADNonInteractiveUserSignInLogs, add that table schema, and build fixtures.
- Publish the MFA fatigue write-up on LinkedIn and link the repo.

## Week 4: the part that makes it stand out
- Add `triage/`: a small Python tool that takes a detection's output rows,
  enriches them (IP reputation, the user's normal sign-in countries) and
  drafts an analyst summary with an LLM, with a human approval step.
  This speaks directly to roles like BeyondTrust Cyber Defense.
- Update your resume: link the repo, and add MITRE ATT&CK and detection
  engineering now that you can back them up.

## Later
- Free Azure account: deploy the rules to a real Sentinel workspace from CI
  (analytics rule ARM/Bicep export).
- Generate real attack logs in a test tenant if you can get one, and replace
  some synthetic fixtures with real ones.
- Sigma versions of each rule so non-Microsoft shops can read them.

## Interview use
For each detection be ready to answer: what does the attack look like, why
these thresholds, what are the false positives, how would you triage it, and
what does it miss. The write-ups are your practice for that.
