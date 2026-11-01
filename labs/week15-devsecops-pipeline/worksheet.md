# Worksheet 15 — DevSecOps: Putting It Together (4 hrs)

> **Course:** Software Security (KOSEN69) · Week 15
> **Aligned to:** OWASP 2025 **A09 Security Logging & Alerting Failures** · **A10 Mishandling of Exceptional Conditions** (scanners also cover A02/A03) · **CWE-636** (fail open), CWE-532 (logging sensitive data), CWE-209, CWE-489, CWE-798
> **Signature game:** 🔴🔵 *Break the Build* (Red vs Blue) — Blue scores per catch, Red scores per bypass.

> ⚠️ **Ethics note:** The pipeline and `sample-service.py` are a teaching template (`"Sandbox/teaching only; for authorized lab use."`). Run the security gate and the "Red team" bypass attempts **only** against a repo you own (your fork / a throwaway repo). Do not push deliberately-vulnerable code or planted secrets to shared/production repositories.

---

## Part 1 — Student Information

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|---|---|---|---|
| Pirisa Kitichai | 6631503031 | 24/10/2026 | 11 |

**AI Use Disclosure:**

I used ChatGPT to understand lab instructions, troubleshoot GitHub Actions, review Semgrep and Trivy findings, and improve security explanations. I ran the tests, verified the results, and captured the evidence myself.

---

## Part 2 — Lecture Questions

Answer in your own words (2–4 sentences each).

### 1. Why do security scanners run twice in the CI pipeline?

A single failing scan may stop the workflow before the SARIF report is uploaded, making it harder to review the findings. The report step uses `exit-code: 0` to generate the results without stopping the workflow, while `if: always()` allows the SARIF upload to run. The gate step then uses `exit-code: 1` or `--error` to fail the build when security violations are detected.

### 2. What is the difference between fail-closed and fail-open?

Fail-closed denies access when an unexpected error occurs, while fail-open may accidentally grant access. In `sample-service.py`, the `/admin` handler uses `except Exception as exc` and returns HTTP 403 to prevent unauthorized access. The commented insecure version demonstrates fail-open behavior because it could return the admin panel and secret after an error, which relates to OWASP A10 and CWE-636.

### 3. Why are limited GitHub Actions permissions important?

The permissions `contents: read` and `security-events: write` follow the principle of least privilege because the workflow only needs to read repository files and upload security scan results. During my Week 15 lab, I also investigated an SARIF upload issue and learned that repository features and permissions must both be configured correctly. Using `write-all` would give the workflow unnecessary privileges and increase the damage if a third-party action or CI token were compromised.

### 4. Why should security logs not contain secret tokens?

Logging authentication tokens can expose sensitive credentials to anyone who can access the logs, which is classified as CWE-532. Instead, the application should log event types, timestamps, authentication results, and safe reasons such as `reason=bad_token`. In my Flask test, the service recorded `authn_failure`, `authz_failure`, and `authz_success` without printing token values, supporting OWASP A09 security monitoring.

### 5. What are the three security scanners, and what do they detect?

Semgrep performs Static Application Security Testing (SAST) to identify insecure code patterns and supports detection of OWASP Top 10 issues. Trivy scans vulnerable dependencies (SCA), infrastructure misconfigurations (IaC), and secrets, covering risks such as OWASP A02 and A03. Gitleaks detects hard-coded secrets in source code and Git history, including weaknesses related to CWE-798. In my Red Team test, Trivy detected `USER root` as `DS-0002 (HIGH)` and failed the security gate.

---

## Part 3 — Hands-on Lab (180 min in class)

> The task budgets below add up to 205 min. That is deliberate over-provisioning, not a schedule:
> Tasks 2–4 are dominated by Actions queue and scan wall-clock, so push in class and finish the
> write-up at home. Your instructor will say which task runs as homework.

![Two panels: the CI gate in security-ci.yml, where a MEDIUM DS-0001 finding slips past the HIGH,CRITICAL threshold and the build goes green, and the /admin handler, where one except branch returns 200 with the flag while the other returns 403 and logs it.](img/fail-closed.svg)

**Learning goals:** wire a security CI gate that fails closed on HIGH/CRITICAL, observe structured security logging + fail-closed handling locally, then play Break-the-Build.

**Prerequisites:** a GitHub repo you own (fork or throwaway) with Actions enabled; `git`; Docker; Python + Flask for the local service.

### Environment setup (real commands)

```bash
# --- A) Wire the gate into a repo you own (README-pipeline.md §1) ---
mkdir -p .github/workflows
cp labs/week15-devsecops-pipeline/security-ci.yml .github/workflows/security-ci.yml
git add .github/workflows/security-ci.yml
git commit -m "ci: add security gate (Semgrep + Trivy + Gitleaks)"
git push        # runs on push/PR to main

# --- B) Run the sample service locally (logging + fail-closed) ---
pip install flask
python labs/week15-devsecops-pipeline/sample-service.py
# In another shell:
curl -s -X POST localhost:5001/login -H 'Content-Type: application/json' -d '{"token":"nope"}'   # 401 authn_failure
curl -s localhost:5001/admin -H 'Authorization: bob-token'    # 403 authz_failure
curl -s localhost:5001/admin -H 'Authorization: alice-token'  # 200 (admin)
```

**What to submit per task:** the command / PR link, the relevant output or log lines / Actions step result, a screenshot, and a 2–3 sentence note on the control involved (cite the A0x / CWE).

### Tasks

- **Task 0 — Onboarding (15 min).** Run the sample service; trigger the three curls above. **Deliverable:** screenshot of the structured `event=...` security log lines for authn_failure, authz_failure, and authz_success.

### Task 0 — Onboarding

**Results:**

| Test | HTTP Status | Security Event |
|---|---|---|
| Invalid Login | 401 | `authn_failure` |
| Unauthorized Admin | 403 | `authz_failure` |
| Authorized Admin | 200 | `authz_success` |

**Explanation:**

The Flask service successfully logged authentication and authorization events. Invalid login attempts returned 401, unauthorized admin requests returned 403, and authorized admin requests returned 200. The logs record security events without exposing token values (OWASP A09).

**Evidence:**

![Task 0 - Security Logs](img/week15_task0_security_logs.png) 

- **Task 1 — Logging & fail-closed (35 min, A09/A10).** *Goal:* prove fail-closed behavior. *Steps:* read `/admin` in `sample-service.py`; explain why the broad `except Exception` returns **403, not the secret**, and why `type(exc).__name__` (not the message) is logged (CWE-209). Identify the line that would make it fail *open* (the commented INSECURE variant). *Deliverable:* the log lines + a 2–3 sentence explanation of fail-closed vs fail-open.

### Task 1 — Logging & Fail-Closed

**Code Review:**

- Line 96: `except Exception as exc`
- Line 101: `type(exc).__name__`
- Line 103: `return jsonify(error="forbidden"), 403`
- Lines 106–109: Commented insecure fail-open example

**Explanation:**

Fail-closed denies access when an unexpected error occurs, while fail-open may allow unauthorized access (OWASP A10 / CWE-636). The secure `/admin` handler returns HTTP 403 and logs only the exception type instead of exposing sensitive error details (CWE-209).

**Security Logs:**

- `authn_failure` — 401
- `authz_failure` — 403
- `authz_success` — 200

**Evidence:**

![Task 1 - Fail-Closed Security Logs](img/week15_task1_fail_closed_logs.png)

- **Task 1b — Break the Build, live (25 min, A10 / CWE-636).** *Goal:* exploit a real fail-open, then prove the fix. *Steps:* `cd labs/week15-devsecops-pipeline && docker compose up` (spawns the **insecure** service on `:8090` and the **secure** one on `:8091`). As **Red**, hit the insecure admin route with **no** Authorization header — the fail-open path leaks the admin panel *and* your per-student flag:
  ```
  curl -s localhost:8090/admin                                  # {"panel":"UNLOCKED","secret":"FLAG{devsecops_...}"}  <- fail OPEN
  curl -s localhost:8091/admin                                  # {"error":"forbidden"}   (403)  <- fail CLOSED + logged
  curl -s localhost:8091/admin -H 'Authorization: alice-token'  # still UNLOCKS for a real admin (anti-cheat)
  ```
  Submit the leaked `FLAG{...}`. *Deliverable:* the flag, the two contrasting `/admin` responses (`:8090` leak vs `:8091` deny), and the exact line in `insecure_service.py` that fails open. *(The instructor auto-grader re-runs these exploits against your hardened box — you pass only if every bypass is blocked **and** a valid admin token still works.)*
  ### Task 1b — Break the Build: Fail-Open vs. Fail-Closed

**Commands Executed:**

```powershell
curl.exe -i http://localhost:8090/admin
curl.exe -i http://localhost:8091/admin
curl.exe -i http://localhost:8091/admin -H "Authorization: alice-token"
```

**Test Results:**

| Test | HTTP Status | Result |
|---|---|---|
| Insecure service without token | 200 | Admin panel and secret exposed |
| Secure service without token | 403 | Access denied |
| Secure service with admin token | 200 | Access granted |

**Leaked Flag:**

`FLAG{devsecops_fail_open_leaks_admin}`

**Vulnerable Code:** `insecure_service.py`, lines 46–49

```python
except Exception:
    return jsonify(panel="UNLOCKED", secret=SECRET)
```

**Explanation:**

The insecure service catches an authorization error and grants admin access instead of denying it, causing a fail-open vulnerability (OWASP A10 / CWE-636). The secure service prevents unauthorized access by returning HTTP 403 while still allowing valid admin credentials.

**Evidence:**

![Task 1b - Fail Open vs Fail Closed](img/week15_task1b_fail_open_vs_closed.png)

- **Task 2 — Stand up the gate (35 min).** *Goal:* get the workflow running. *Steps:* push `security-ci.yml`, open the Actions run, confirm the three jobs (`semgrep`, `trivy`, `gitleaks`) execute and SARIF appears in the Security tab. *Deliverable:* screenshot of the Actions run + the Code scanning alerts page.

### Task 2 — Stand Up the Security Gate

**Objective:** Set up a GitHub Actions security pipeline and verify that the scan results are available in GitHub Code Scanning.

**Workflow:** `security-ci.yml`

**GitHub Actions Run:**

https://github.com/Pirisa08/software-security/actions/runs/39913250787

**Test Repository:**

https://github.com/Pirisa08/week15-security-test

**Code Scanning Verification (PR #1):**

https://github.com/Pirisa08/week15-security-test/pull/1

**Results:**

| Security Scanner | Baseline Result | PR #1 Result |
|---|---|---|
| Semgrep (SAST) | Success | Failed |
| Trivy (SCA + IaC) | Success | Failed |
| Gitleaks (Secret Scanning) | Success | Success |

**Code Scanning Findings:**

- **Scanner:** Trivy
- **Rule ID:** `DS-0002`
- **Severity:** HIGH
- **Location:** `Dockerfile:6`
- **Finding:** `Image user should not be 'root'`
- **Additional finding:** One LOW-severity alert was also reported.
- **Status:** Successfully displayed in GitHub Code Scanning results for PR #1.

**Explanation:**

I configured a GitHub Actions security pipeline using Semgrep, Trivy, and Gitleaks. The baseline workflow completed successfully, confirming that all three scanners could run.

I also verified that the SARIF security findings were displayed in GitHub Code Scanning for Pull Request #1. Trivy reported `DS-0002 (HIGH)` because the Dockerfile was configured to run as root. This demonstrates that the pipeline can report security findings and identify insecure code changes before merging.

**Evidence:**

![Task 2 - GitHub Actions](img/week15_task2_github_actions.png)

![Task 2 - Code Scanning Alerts](img/week15_task2_code_scanning_alerts.png)

- **Task 3 — Blue team: pass the gate (30 min).** *Goal:* a green build. *Steps:* ensure the protected repo has no HIGH/CRITICAL findings and no secrets; fix or justify-and-document any (no blanket-ignore, per README §4). *Deliverable:* link to the passing run.

### Task 3 — Blue Team: Pass the Security Gate

**Repository:** https://github.com/Pirisa08/week15-security-test

**Passing Workflow:** https://github.com/Pirisa08/week15-security-test/actions/runs/40733055033

**Results:**

| Security Scanner | Status |
|---|---|
| Semgrep (SAST) | Success |
| Trivy (SCA + IaC) | Success |
| Gitleaks (Secret Scanning) | Success |
| Overall Pipeline | Success |

**Explanation:**

I tested the security pipeline in a separate repository to avoid modifying intentionally vulnerable files from previous labs. All three security jobs completed successfully, demonstrating a passing baseline for the Blue Team (OWASP A02/A03).

**Evidence:**

![Task 3 - Blue Team Green Build](img/week15_task3_blue_team_green_build.png)

- **Task 4 — Red team: Break the Build (40 min).** *Goal:* make the gate say **no**. *Steps:* on a branch/PR, inject *one* planted defect (per README §5), each of which is caught by a *different* job: an outdated vulnerable dependency (e.g. an old `urllib3`) → Trivy SCA; a Dockerfile that runs as **root** — drop the `USER` line, or write `USER root` → Trivy config (`DS-0002`, HIGH); or a hard-coded token → Gitleaks. Open the PR and watch the matching gate step fail. *Deliverable:* screenshot of the **failing** gate step + which job caught it (Trivy SCA / Trivy config / Gitleaks) and which `exit-code: "1"` / `--error` step enforced it.
  > **Why root and not `chmod 777`.** Both gate steps filter to `--severity HIGH,CRITICAL`, and Trivy's Dockerfile scanner has no rule for `chmod` at all — it checks instruction-level `RUN`/`COPY` semantics, exactly as Week 13 Task 1 says. `chmod 777` therefore returns **nothing**, at any severity, and the build goes green: a defect that slips the gate is a Task 5 *Red point*, not a Task 4 screenshot. `:latest` is no good either — that is `DS-0001` and Trivy rates it MEDIUM, which this gate filters out. Running as root is `DS-0002` HIGH, so it fails the build for real.

### Task 4 — Red Team: Break the Build

**Objective:** Test whether the security pipeline can detect and block an intentionally insecure Dockerfile.

**Repository:** https://github.com/Pirisa08/week15-security-test

**Pull Request:** https://github.com/Pirisa08/week15-security-test/pull/1

**Branch:** `wk15-red-test`

**Injected Defect:** Running the Docker container as the root user.

**Vulnerable Dockerfile:**

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY app.py .

USER root

CMD ["python", "app.py"]
```

**Security Scan Results:**

| Scanner | Result |
|---|---|
| Semgrep (SAST) | Failed |
| Trivy (SCA + IaC) | Failed |
| Gitleaks (Secret Scanning) | Passed |
| Overall Pipeline | Failed |

**Detected Vulnerability:**

- Scanner: Trivy
- Rule ID: `DS-0002`
- Severity: HIGH
- Location: `Dockerfile:6`
- Finding: `Last USER command in Dockerfile should not be 'root'`
- Failed Step: `Gate - fail on HIGH/CRITICAL IaC findings`
- Exit Code: `1`

**Explanation:**

I intentionally configured the Dockerfile to use `USER root` in a separate test branch and opened a Pull Request. Trivy detected the insecure configuration as `DS-0002 (HIGH)` at Dockerfile line 6. The IaC security gate failed with exit code 1, demonstrating that the pipeline rejected the intentionally insecure change.

**Security Impact:**

Running a container as root gives the application unnecessary privileges. If the application is compromised, an attacker may have greater control within the container.

**Mitigation:**

Configure the Dockerfile to run as a non-root user and apply the principle of least privilege. Re-run Trivy to verify that `DS-0002` is no longer detected.

**Evidence:**

![Task 4 - Trivy Root Detection](img/week15_task4_trivy_root_detection.png)


- **Task 5 — Score Break-the-Build (25 min).** *Goal:* tally Red vs Blue. *Steps:* one Blue point per finding the gate caught, one Red point per finding that slipped through; for any bypass, propose the rule that would have caught it. *Deliverable:* scoreboard + one proposed gate improvement.

### Task 5 — Score Break-the-Build

**Objective:** Evaluate how effectively the security pipeline detects vulnerabilities.

**Scoreboard:**

| Test | Result | Score |
|---|---|---|
| Blue Team — Clean Build | All 3 security jobs passed | Baseline passed |
| Red Team — Root Container (DS-0002) | Trivy detected HIGH misconfiguration | Blue +1 |
| Red Team — Undetected Defects | None observed | Red +0 |

**Final Score:**
- Blue Team: **1 point**
- Red Team: **0 points**

**Proposed Gate Improvement:**

Pin scanner versions to verified commit SHAs and regularly update security rules to improve detection reliability.

**Explanation:**

The Trivy security gate successfully detected `USER root` in the Dockerfile (DS-0002, HIGH) and failed the build with exit code 1. No successful bypass was observed in this test, demonstrating that the pipeline can reject the planted misconfiguration (OWASP A02).

**Evidence:**
- Blue Team Green Build: https://github.com/Pirisa08/week15-security-test/actions/runs/40733055033
- Red Team PR: https://github.com/Pirisa08/week15-security-test/pull/1
- Trivy Detection: ![Task 4 - Trivy Root Detection](img/week15_task4_trivy_root_detection.png)

---

## Part 4 — Reflection

### 1. Security Logging and Fail-Closed

Security logging helps detect suspicious activities and unauthorized access attempts (OWASP A09). During my Flask testing, the application recorded `authn_failure`, `authz_failure`, and `authz_success` without exposing sensitive tokens.

Fail-closed behavior ensures that unexpected errors deny access instead of granting it. In the Week 15 lab, the insecure service returned HTTP 200 and exposed the admin panel when an authentication error occurred, while the secure service returned HTTP 403. This demonstrates the importance of preventing fail-open behavior (OWASP A10 / CWE-636).

### 2. DevSecOps Security Pipeline

I used GitHub Actions to run three security scanners: Semgrep for insecure code patterns, Trivy for vulnerable dependencies and configuration issues, and Gitleaks for exposed secrets.

The pipeline used a report-then-gate approach. The report steps generated SARIF findings, while the security gate failed the build when a violation was detected. This helped identify vulnerabilities early and prevent insecure changes from passing the configured security checks.

### 3. Blue Team vs. Red Team

The Blue Team established a clean baseline where all three security scanners passed. For the Red Team test, I created a separate branch containing a Dockerfile with `USER root`.

Trivy detected the configuration as `DS-0002 (HIGH)` and failed the IaC security gate with exit code 1. After changing the Dockerfile to run as a non-root user in a separate verification Pull Request, all three security scanners passed. This demonstrated that the pipeline could detect the planted defect and accept the corrected configuration.

### 4. Lessons Learned

Automated security gates are effective only when their rules, severity thresholds, and permissions are correctly configured. A passing pipeline does not guarantee that an application is completely secure, because scanners may miss vulnerabilities or findings below the configured threshold.

This lab taught me the importance of combining security logging, fail-closed authentication, least-privilege container configuration, and automated security scanning. Testing both failing and passing builds helped me verify how the security controls behave in practice.

---

## Grading rubric (100)

| Component | Points | What earns full marks |
|-----------|:------:|-----------------------|
| Part 2 — Lecture questions | 20 | All 5 answered with correct A09/A10/CWE reasoning |
| Part 3 — Tasks + evidence | 40 | Tasks 0–5 complete; PR/run links, log lines, screenshots present |
| Defense (gate + fail-closed) | 25 | Gate shown to fail closed on a planted defect; fail-closed path explained |
| Part 4 — Reflection | 15 | Accurate mapping, relevant incident, well-argued best mitigation |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** FLAG{devsecops_d0bff6d628e0480a}
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*

### Explain in Your Own Words
**1. What did you do, and why did the vulnerability work?**

I tested a Dockerfile using `USER root`. This is insecure because the container runs with excessive privileges, increasing the impact of an attack. Trivy detected it as `DS-0002 (HIGH)` and failed the security gate.

**2. Why does your fix actually stop it, and what could still break it?**

Running the container as a non-root user reduces unnecessary privileges. However, other vulnerabilities or misconfigurations could still expose the application, so regular security scanning is necessary.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.
### 1. AI Response

**Prompt:** How can I fix the SARIF upload failure in my Week 15 GitHub Actions pipeline?

**AI Response:**

"Add `actions: read` to the workflow permissions to resolve the SARIF upload issue."

### 2. What Was Wrong or Risky?

**Problematic statement:**

"Add `actions: read` to the workflow permissions to resolve the SARIF upload issue."

The AI suggestion was incomplete because the actual problem was that Code Scanning was not enabled in the private repository. Adding `actions: read` alone did not resolve the error.

### 3. Corrected and Verified Solution

I used a separate public GitHub repository and kept the required permissions:

```yaml
permissions:
  contents: read
  actions: read
  security-events: write
```

**Verification Results:**

- Semgrep: PASSED
- Trivy: PASSED
- Gitleaks: PASSED
- Overall CI Pipeline: SUCCESS

**Explanation:**

The AI initially focused on token permissions without checking whether Code Scanning was enabled. Using a public test repository allowed SARIF uploads, and all three security jobs completed successfully.

**Evidence:**

![Week 15 - Green Build](img/week15_task3_blue_team_green_build.png)

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt

### A. Explain in Plain English (EiPE)

The insecure Dockerfile runs the application as the root user, giving it unnecessary privileges. If an attacker compromises the application, these privileges could increase the impact of the attack.

During my Red Team test, Trivy detected this misconfiguration as `DS-0002 (HIGH)` and failed the security gate with exit code 1.

### B. Prompt Problem

**Final Prompt:**

Fix the Dockerfile that uses `USER root`. Apply the principle of least privilege by creating a non-root user and running the application under that account. Keep the application functional and ensure the configuration addresses the Trivy finding `DS-0002`.

**AI-Recommended Fix:**

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY app.py .

RUN groupadd -r appuser && useradd -r -g appuser appuser

USER appuser

CMD ["python", "app.py"]
```

**Verification Results:**

| Test | Result |
|---|---|
| Before Fix — Red Team PR #1 | Trivy detected `DS-0002 (HIGH)` |
| Before Fix — Security Gate | FAILED — Exit Code 1 |
| Applied Fix — Blue Team PR #2 | Replaced `USER root` with `USER appuser` |
| After Fix — Semgrep | PASSED |
| After Fix — Trivy | PASSED |
| After Fix — Gitleaks | PASSED |
| After Fix — Overall CI Pipeline | SUCCESS |

**Explanation:**

I created a separate Pull Request to verify the corrected Dockerfile. After replacing `USER root` with a non-root account, all three security scanners passed, including the Trivy configuration security gate.

The result demonstrates that the corrected Dockerfile passed the configured security policy. Running the application as a non-root user also reduces unnecessary privileges and limits the potential impact of an application compromise.

**Conclusion:**

The Red Team test demonstrated that Trivy could detect and block the insecure root-user configuration with `DS-0002 (HIGH)`. After applying the non-root fix, the security pipeline passed successfully.

However, passing a security scan does not guarantee that an application is free from all vulnerabilities. Regular security testing, least-privilege configuration, and defense in depth remain necessary.

**Evidence:**

**Before Fix — Red Team (DS-0002 HIGH):**

![Task 4 - Trivy Root Detection](img/week15_task4_trivy_root_detection.png)

**After Fix — Blue Team (Security Pipeline Passed):**

![Week 15 - Non-Root Fix Verification](img/week15_nonroot_fix_verification.png)

**Pull Request References:**

- Before Fix: https://github.com/Pirisa08/week15-security-test/pull/1
- After Fix: https://github.com/Pirisa08/week15-security-test/pull/2