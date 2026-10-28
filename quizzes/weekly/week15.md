# Weekly Quiz — Week 15 (DevSecOps)

**~10 min · in-class · 6 questions · low-stakes** (drop lowest). No devices / locked browser.

**Name:** Pirisa Kitichai **Student ID:** 6631503031

## MCQ (5 × 1)
1. "**Shift left**" means moving security:
   a) to production only  b) earlier in the development pipeline  c) to the security team alone  d) after release
Ans. B

2. Leaking secrets in CI is best prevented by:
   a) printing them to logs  b) secret scanning + masked variables + short-lived OIDC tokens  c) emailing them  d) hardcoding them
Ans. B

3. A CI **security gate** does what?
   a) speeds up builds  b) blocks the merge when a policy check fails  c) deletes branches  d) formats code
Ans. B

4. Pinning a GitHub Action to a **commit SHA** (not a tag) prevents:
   a) slow runs  b) a hijacked/moved tag supply-chain attack  c) merge conflicts  d) flaky tests
Ans. B
5. **IaC scanning** (Checkov/tfsec) finds:
   a) UI bugs  b) misconfigurations in Terraform/IaC  c) memory leaks  d) typos in docs
Ans. B

## Short answer — 🔒 your own work (1 × 3)
**6. Describe one security gate you added to the pipeline this week and exactly what it blocks.**

I added a Trivy IaC security gate that blocks builds when HIGH or CRITICAL infrastructure misconfigurations are detected. During the Red Team test, Trivy detected `USER root` in the Dockerfile (`DS-0002`, HIGH) and failed the pipeline with exit code 1.

**Flag captured from the fail-open challenge:**
`FLAG{devsecops_fail_open_leaks_admin}`

**Week 15 code provided by the instructor:** `EA5FGSY3`
