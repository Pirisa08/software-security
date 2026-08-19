---
marp: true
theme: default
paginate: true
header: "Software Security · Week 15"
---

# Week 15
## DevSecOps: Putting It Together
Software Security · Nutthakorn Chalaemwongwan

<!-- Final teaching week. Hook: everything we've learned — SAST, SCA, secrets, image scans — only works if it runs automatically on every commit. Today we wire it into one pipeline that blocks bad code. ~2 min. -->

---

## Today

- Security in the CI/CD pipeline
- Logging, monitoring & alerting
- Failing safely
- Vulnerability mgmt & disclosure
- 🎮 Game: **Break the Build** (Red vs Blue)

<!-- Roadmap, 1 min. This week ties the whole course together. Lab is the capstone of the technical units: build the gate (Blue) vs sneak past it (Red). -->

---

## The whole course in one pipeline

- SAST (Wk2) · SCA + image scan (Wk12–13) · secret scanning (Wk2)
- Automated gates instead of one-off scans
- **Secure by Design** as the default

<!-- The synthesis slide — walk back through the term: every tool we used by hand now runs automatically on every PR. Manual scanning doesn't scale and humans forget; pipelines don't. ~4 min. -->

---

## A security gate

```yaml
# .github/workflows/security-ci.yml
- semgrep   # SAST
- trivy     # SCA (fs) + IaC (config) — image scan is optional, off by default
- gitleaks  # secrets + git history
# each tool runs TWICE: once to report (SARIF, always), once to gate (fails the build)
```

- Least-privilege token: `contents: read`, `security-events: write` — don't hand the pipeline more than it needs
- Upload SARIF → GitHub Security tab

```sim
gate-check
```

<!-- The worked example — this is the lab's actual pipeline. Be precise: Trivy's active jobs are fs (SCA) and config (IaC) — the image-scan step exists in the YAML but is commented out/optional, don't claim it's active. The "runs twice" pattern (report step + separate gate step) is what Part 2 Q1 is built around — say it explicitly. The sim's 2 decoys are the actual worksheet nuance: chmod 777 has no Trivy rule at any severity, while FROM:latest IS detected (DS-0001) but rated MEDIUM and filtered by severity:HIGH,CRITICAL — same green build, different reason. The KEY line is "fail build on HIGH/CRITICAL": a gate that only warns gets ignored. ~6 min. -->

---

## Platform option — GitHub Advanced Security

- **CodeQL** code scanning (SAST) on every PR
- **Secret scanning** + push protection
- **Dependabot** for vulnerable deps
- **SonarQube** as a quality/SAST gate alongside

> Same idea as the YAML gate — managed, in the repo.

<!-- The managed equivalent they'll meet in industry. Same concept, less YAML to maintain. Mention SonarQube as the common quality-gate they'll see in internships. ~3 min. -->

---

## Logging, monitoring, alerting

- **A09:2025** — without logs you can't detect or respond
- Log security events (authn, authz failures, anomalies)
- **Never log the secret/token value itself** (CWE-532) — log `reason=bad_token`, not the token
- Alert on suspicious patterns

<!-- Shift from prevention to detection. A09 (logging/monitoring failures) is a Top 10 risk because you can't respond to what you can't see. The CWE-532 point is graded (Part 2 Q4) and easy to skip if you only say "log security events" — a log line that captures the bad token has just created a new secrets-in-logs problem. Recall W6: we read attacker actions FROM logs — but only if they were logged. ~4 min. -->

---

## Detection tooling

- **NIDS** — Snort / Suricata (network signatures)
- **HIDS** — OSSEC (host-based)
- **SIEM / stack** — Security Onion bundles them + analysis
- Network visibility: **TAP** (lossless) vs **SPAN** (cheap, can drop)

<!-- Awareness of the defender's toolkit. NIDS watches the wire, HIDS watches the host, SIEM correlates everything. TAP vs SPAN is a practical gotcha: SPAN ports drop packets under load — you miss attacks. Keep brisk. ~3 min. -->

---

## Alerts — the confusion matrix

| | Incident real | No incident |
|---|---|---|
| **Alert fired** | True positive ✅ | False positive |
| **No alert** | **False negative** 💀 | True negative |

- False negative = worst case (missed attack)
- Some false positives are inevitable — tune, don't silence

<!-- Ties back to W2 triage. The danger asymmetry: a false negative = an attack you never saw. But too many false positives → alert fatigue → analysts mute everything → effective false negatives. The skill is TUNING. ~4 min. -->

---

## When something happens (NIST SP 800-86)

**Collection → Examination → Analysis → Reporting**

- Preserve **order of volatility**: memory → temp files → disk → logs
- Failed/success logins: Windows Event **4625 / 4624**

<!-- A taste of incident response / forensics. Order of volatility: capture RAM before you pull the plug — it's gone on shutdown. 4625 (failed) / 4624 (success) are the login events they'd grep in a real investigation. ~4 min. -->

---

## Fail safely

- **A10:2025** — mishandled errors leak info / fail open
- **Fail closed:** deny on error, don't bypass checks
- Don't expose stack traces / secrets in errors

<!-- A design principle that recurs: when something breaks, DENY (fail closed), don't accidentally grant access (fail open). Verbose errors leak schema/secrets (recall W4 error-based enumeration). ~3 min. -->

---

## Vulnerability management & disclosure

- Triage by severity; track to remediation (SLAs)
- **Coordinated disclosure** & bug bounties
- security.txt; a path for researchers to report

<!-- The professional/ethical close: finding a bug is step one; managing it to a fix (with SLAs) is the job. Coordinated disclosure + security.txt = how to receive reports responsibly. Connects to the course ethics theme. ~3 min. -->

---

## One decision, made twice

![Two panels showing the same yes-or-no decision at two different times. Build time: the CI gate's HIGH/CRITICAL severity filter, not the scanner itself, decides what a build refuses — root user (DS-0002, HIGH) is caught, :latest (DS-0001, MEDIUM) slips past the filter. Run time: the /admin handler makes the identical decision on an exception — fail-open returns 200 and logs nothing (silent bypass, A09); fail-closed returns 403 and logs event=authz_failure without ever logging the token itself (CWE-532). Both defaults, unexamined, are yes: the gate exits 0 on anything it wasn't told to fail on, the handler returns 200 on anything that threw. Nobody chose — that silence is A10, CWE-636.](img/fail-closed.svg)

<!-- The synthesis slide, and arguably the whole course's closing argument: "secure by default" means someone has to have DECIDED the default, twice here — once in YAML severity filters, once in an except block. An unexamined default is always permissive. Walk both panels, land on the bottom line before the game. ~5 min. -->

---

## 🔴🔵 Game — Break the Build

- **Blue:** build the gate (Semgrep + Trivy + Gitleaks), fail on HIGH/CRITICAL, add security logging that fails closed
- **Red:** three gate-mapped attacks only — outdated dependency (Trivy SCA), a Dockerfile running as root (Trivy config), a hardcoded token (Gitleaks). `chmod 777` and `FROM:latest` are decoys that stay green — not gate bypasses
- **Score:** Blue per catch, Red per successful bypass; then capture your personal flag from the fail-open `/admin` bypass in `insecure_service.py`

<!-- The capstone game. Both roles teach: Blue learns to configure gates, Red learns where gates have blind spots — but Red's menu is fixed to 3 attacks that actually map to a gate, not open-ended. Run it as live PRs against the pipeline. The weekly quiz no longer asks for the gate/what-it-blocks/flag (dropped — quiz runs before the lab) — that's required in the worksheet instead, don't drop the flag half there, it's still graded. ~3 min. -->

---

## Deliverable

> 📋 **Worksheet 15** — `labs/week15-devsecops-pipeline/worksheet.md` (Part 3) · **kickoff:** push `security-ci.yml` → GitHub Actions; separately, `docker compose up` → :8090 (insecure) / :8091 (secure) for the flag task

- A passing PR that adds the pipeline
- Screenshot: build **failing** on each of the 3 Red-team categories (dependency, root Dockerfile, hardcoded token) — not just one
- Your personal `FLAG{...}` from the fail-open `/admin` bypass, submitted with this week's quiz Q6
- **+ Audit the AI / EiPE / Prompt Problem** (see worksheet)

<!-- Two separate targets this week, both graded: security-ci.yml is the CI gate; insecure_service.py/secure_service.py (compose, :8090/:8091) is where the personal flag lives. The "build failing" screenshots are the proof the gate actually blocks — a green pipeline that never fails is useless, and one category alone undersells the deliverable. AI-resilient tasks count. This is also the last weekly quiz. -->

---

## Key takeaways

- Automate security gates — humans forget, pipelines don't
- You can't defend what you don't log
- Fail closed; disclose responsibly

<!-- Recap + course wrap of the technical units. Cold-call: "why must the gate FAIL the build, not just warn?" (warnings get ignored). ~2 min. -->

---

# Questions?
Next week: Capstone studio & CTF warm-up

<!-- Wrap: "Teaching is done — next is your capstone: ship something secure, then defend it in the final CTF. Bring your project to the studio." -->
