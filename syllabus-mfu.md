# Software Security (1305315) — MFU Compressed-Format Syllabus

**Institution:** Mae Fah Luang University (MFU)
**Course code:** 1305315
**Course title:** ความมั่นคงของซอฟต์แวร์ (Software Security)
**Credits:** 2-2-5 (2 lecture-equivalent + 2 lab-equivalent + 5 self-study hours/week-equivalent)
**Instructor:** อ.ดร.ณัฐกรณ์ แฉล้มวงศ์วาน (Nutthakorn Chalaemwongwan)
**Coordinating instructor:** Dr. Nang Hsu Mon Pyae
**Semester:** 1/2569 (Aug–Nov 2026)
**Format:** 7 all-day weekend sessions, 08:00–12:00 (ภาคทฤษฎี — lecture) + 13:00–17:00 (ภาคปฏิบัติ — lab), same content and pedagogy as the parent [`software-security`](README.md) course, compressed from the 19-week weekly format into 7 all-day sessions. Sessions 1 and 2 run **back to back on the opening weekend (Sat 15 + Sun 16 Aug)**; the remaining five are fortnightly Saturdays.
**Relationship to the KOSEN-KMITL offering:** same course, same content family, same AIR-Sec pedagogy, part of the same preregistered multi-institution study (MFU is the single-section cross-institution replication arm — see `instructor/research/preregistration.md` and `site-logistics.md`). This file is MFU-specific scheduling; [`syllabus.md`](syllabus.md) is the canonical 19-week KOSEN-KMITL version this content is drawn from.
**Last updated:** ปีการศึกษา 2569

---

## 1. Course Description

This course teaches students how software fails under attack and how to build software that resists it. It blends timeless fundamentals (memory safety, injection, authentication, cryptography misuse) with the threats that dominate modern systems: **software supply-chain attacks, cloud and container misconfiguration, API abuse, and the security of AI/LLM-powered applications.**

The course is deliberately hands-on. Every topic pairs a lecture concept with a lab in which students either *break* an intentionally vulnerable target in a safe sandbox or *defend* code they write themselves. Students leave able to threat-model a system, find and exploit common vulnerability classes, remediate them, and integrate security checks into a CI/CD pipeline.

Aligned with the **OWASP Top 10 (2025)**, the **OWASP Top 10 for LLM Applications (2025)**, the **OWASP API Security Top 10**, **MITRE ATT&CK / CWE**, and the **SLSA** supply-chain framework — identical technical scope to the KOSEN-KMITL offering, delivered in 7 all-day weekend sessions instead of 16 weekly meetings.

---

## 2. Learning Outcomes

By the end of the course, students will be able to:

1. **Threat-model** a software system and reason about its attack surface, trust boundaries, and adversary capabilities.
2. **Identify and exploit** common vulnerability classes (injection, broken access control, memory-safety bugs, insecure design) in a controlled environment.
3. **Write and review secure code**, applying input validation, output encoding, safe defaults, and least privilege.
4. **Apply cryptography correctly**, recognizing common misuse and selecting appropriate primitives.
5. **Secure the modern software supply chain** using dependency analysis, SBOMs, artifact signing, and build provenance.
6. **Secure cloud, container, and API workloads**, including IAM, secrets management, and configuration hardening.
7. **Assess and defend AI/LLM-powered applications** against prompt injection, insecure output handling, and excessive agency.
8. **Integrate security into the development lifecycle** (SAST, DAST, SCA, secret scanning) within a CI/CD pipeline (DevSecOps).
9. **Disclose vulnerabilities responsibly** and communicate risk to technical and non-technical stakeholders.
10. **Reason adversarially** — given a system, generate plausible attacker goals, work out what an attacker with limited knowledge and budget would actually try first, and explain *why* a control does or does not stop them. This is the disposition the other nine outcomes are in service of, and it is assessed directly: in the Week 1 systems-level pass, in every worksheet's abuse cases, and as a scored dimension of the midterm and final CTF.

---

## 3. Format Note — Why 7 Sessions Instead of 19 Weeks

MFU delivers this course as 7 full-day weekend sessions rather than 19 weekly meetings. Each session keeps the same **lecture → lab** structure as the KOSEN offering, just compressed: the 08:00–12:00 block covers that session's lecture content for all topics assigned to it, and the 13:00–17:00 block runs the corresponding hands-on labs/games back to back. Total contact hours and technical content are unchanged from the 19-week version — only the calendar grouping differs.

**The opening weekend is a double session, and that has consequences worth naming.** Sessions 1 and 2 fall on consecutive days (Sat 15 + Sun 16 Aug), so the four topics of Weeks 1–4 — threat modeling, secure SDLC/tooling, cryptography and injection — land inside about 36 hours. Two things follow. First, there is no week between them to fix a broken environment, so the "Lab 0" setup below is not a suggestion; a laptop that cannot run Docker on Saturday morning will also not run it on Sunday morning. Second, the gap from Session 2 to Session 3 is three weeks (16 Aug → 5 Sep), the longest in the term — that gap, not the opening weekend, is where the Week 3–4 material should be consolidated through the take-home labs.

**A pacing note, stated plainly rather than smoothed over:** because the 19-week content splits 6 topics before the midterm and 7 after, but the calendar gives 3 sessions before the midterm and only 2 after, per-topic time is not perfectly even — Sessions 1–3 give each topic roughly 2 lecture hours + 2 lab hours, while Sessions 5–6 compress to roughly 1.3–2 hours each per topic. Session 6's original 4-topic load has been rebalanced below (see §5) by moving the Week 16 capstone-studio content to self-study/pre-final prep rather than new taught content that session — this is a deliberate adaptation, not an oversight, and matches how the source Week 16 was already designed (no vulnerable-target lab, practice-only — `labs/week16-capstone/` holds the scrimmage/worksheet materials but no Docker lab environment).

---

## 4. Lab Environment

Identical to the KOSEN offering — all offensive work is performed **only** against instructor-provided, intentionally vulnerable targets inside an isolated sandbox. Students never attack systems they do not own or lack written permission to test.

**Required toolkit (all free / open source) — Docker-first:**

- **Docker Desktop** (Windows / macOS / Linux) — runs every lab target via `docker compose up`. *No full VM required.*
- **Lab toolbox container** (`labs/toolbox`) — a small Linux image with `clang`+libFuzzer, `gdb`, `nmap`, `sqlmap` for the sessions that need Linux dev/attacker tools (mainly Session 5's memory-safety block).
- **Git + a GitHub account** — for labs, CI/CD, and the term project.
- Browser with **Burp Suite Community** or **OWASP ZAP** — web/API testing proxy.
- *Optional fallback:* a **Kali/Ubuntu VM** (VirtualBox/UTM) if your host can't run Docker.

**Pre-built vulnerable targets used during the term:** OWASP Juice Shop, OWASP WebGoat, DVWA, crAPI/Damn Vulnerable Web Services, pwn.college/picoCTF/OverTheWire, Gandalf (prompt-injection practice).

Bring a laptop able to run Docker Desktop to every session — the compressed format means there is no following week to catch up environment setup, so a working "Lab 0" (`labs/week01-threat-modeling/README.md`) is required **before** Session 1. This matters most on the opening weekend: Sessions 1 and 2 are consecutive days, so an unresolved setup problem on Sat 15 Aug costs you Sun 16 Aug as well.

---

## 5. Session-by-Session Schedule

| Session | Date | 19-wk equiv. | AM lecture (08:00–12:00) | PM lab (13:00–17:00) |
|---|---|---|---|---|
| 1 | Sat 15 Aug 69 | Wk 1–2 | Threat modeling + Secure SDLC/tooling | STRIDE game + Bug Triage/Fuzzing Race |
| **2** | **Sun 16 Aug 69** | Wk 3–4 | Cryptography + Injection | Capture the Hash + SQLi Warm-up |
| 3 | Sat 5 Sep 69 | Wk 5–6 | XSS/client-side + Authn/access control | XSS Golf + IDOR Treasure Hunt/JWT Forgery |
| **4** | **Sat 19 Sep 69** | **Wk 8–9** | **Midterm written exam** (covers Sessions 1–3) | **Midterm CTF practical** |
| 5 | Sat 10 Oct 69 | Wk 10–12 | API security + Memory-safety + Supply chain | crAPI Raid + Pwn the Binary + Dependency Confusion Heist |
| 6 | Sat 24 Oct 69 | Wk 13–15 | Cloud/container + AI/LLM security + DevSecOps | Misconfig Hunt + Gandalf Challenge + Break the Build |
| **7** | **Sat 7 Nov 69** | **Wk 18–19** | **Final written exam** (cumulative, emphasis Sessions 5–6) | **Capstone CTF tournament + team project demos** |

*Week 16 (capstone-studio content) is assigned as self-study/team-project work between Sessions 6 and 7 rather than new taught content in Session 6 — see §3.*

### Session 1 (Sat 15 Aug 69) — Wk 1–2: Foundations I

**AM — Security Mindset & Threat Modeling / Secure SDLC & Tooling**
- CIA triad; attacker vs. defender mindset; trust boundaries; attack surface; STRIDE; the OWASP/MITRE landscape (Top 10, CWE, ATT&CK); "Secure by Design" (CISA) framing. Maps to **A06:2025 Insecure Design**.
- Where security fits in the SDLC; SAST vs. DAST vs. SCA vs. fuzzing; secret scanning; "shift left" and DevSecOps overview.

**PM — Labs**
- 🎲 **"Elevation of Privilege"** — play Microsoft's STRIDE card deck against a provided app's DFD; build a STRIDE threat model + attack-surface map. Lab 0 environment setup confirmed.
- 🏁 **"Bug Triage Race" + "Fuzzing Race"** — run Semgrep + Gitleaks on a flawed repo and triage by CWE (scored); intro coverage-guided fuzzing (first crash wins).

### Session 2 (Sun 16 Aug 69) — Wk 3–4: Foundations II / Web App Security I

**AM — Cryptography Used Correctly (and Misused) / Injection & Input Handling**
- Hashing vs. encryption vs. encoding; symmetric/asymmetric basics; password storage (bcrypt/argon2); TLS overview; common failures (ECB, hardcoded keys, weak randomness, MD5/SHA-1). Maps to **A04:2025 Cryptographic Failures**.
- SQL injection, command injection, the general injection pattern; parameterized queries; output encoding. Maps to **A05:2025 Injection**.

**PM — Labs**
- 🔓 **"Capture the Hash"** — crack weak hashes + break an ECB oracle (speedrun), then remediate with a vetted KDF and authenticated encryption.
- ⚔️ **"SQLi Warm-up"** — tiered injection challenges in DVWA/Juice Shop; rewrite endpoints with prepared statements + validation.

### Session 3 (Sat 5 Sep 69) — Wk 5–6: Web App Security II

**AM — Cross-Site Scripting (XSS) & Client-Side Risks / Authentication, Sessions & Access Control**
- Reflected/stored/DOM XSS; CSRF; SameSite cookies; Content Security Policy; same-origin policy.
- Authn vs. authz; session management; JWT pitfalls; OAuth 2.0/OIDC overview; IDOR and privilege escalation. Maps to **A01:2025 Broken Access Control** and **A07:2025 Authentication Failures**.

**PM — Labs**
- ⛳ **"XSS Golf"** — shortest payload that pops `alert(1)`/steals a cookie wins; then deploy a CSP + escaping that blocks every payload; demo CSRF + defense.
- 🗺️ **"IDOR Treasure Hunt + JWT Forgery"** — reach other users' data via object-id tampering, forge a weak JWT; implement RBAC + fix token handling.

### Session 4 (Sat 19 Sep 69) — Wk 8–9: MIDTERM

**AM — Written exam.** Covers Sessions 1–3: threat modeling, CWE/OWASP mapping, "spot the vuln," secure-design short answers.
**PM — CTF practical.** Graded challenges across injection, XSS, auth/IDOR, and crypto in the sandbox.

### Session 5 (Sat 10 Oct 69) — Wk 10–12: Systems & Modern Stack I

**AM — API Security / Memory-Safety & Exploitation / Software Supply-Chain Security**
- REST/GraphQL attack surface; the OWASP API Security Top 10 (BOLA, broken authentication, excessive data exposure, mass assignment, resource consumption).
- C/C++ memory model; stack buffer overflows; integer overflow; use-after-free; format-string bugs; mitigations (ASLR, canaries, NX/DEP); intro to `gdb`/Ghidra; the global shift to memory-safe languages (CISA/ONCD roadmaps).
- Why the supply chain is now top-tier (**A03:2025**); dependency confusion, typosquatting, malicious/transitive packages; SBOMs (CycloneDX/SPDX); SLSA provenance; Sigstore/Cosign signing (**A08:2025**).

**PM — Labs**
- 🥷 **"crAPI Raid"** — exploit BOLA + mass assignment, then add authorization, schema validation, and rate limiting.
- 💥 **"Fuzzing Race → Pwn the Binary"** — fuzz to find the bug (AFL++/libFuzzer), exploit a stack overflow/format string, watch canaries+ASLR break it, then rewrite the routine in Rust and explain why the bug class disappears.
- 📦 **"Dependency Confusion Heist"** — plant/identify a typosquatted package in a controlled registry; generate an SBOM, sign & verify with Cosign, add a provenance gate.

*Note: this session covers three substantial topics in one day — plan for a brisk pace; the memory-safety and supply-chain labs are the most time-sensitive if running behind.*

### Session 6 (Sat 24 Oct 69) — Wk 13–15: Systems & Modern Stack II

**AM — Cloud & Container Security / Security of AI/LLM-Powered Applications / DevSecOps**
- Shared-responsibility model; IAM least privilege; secrets management; container image hardening; Kubernetes basics; **A02:2025 Security Misconfiguration**.
- OWASP Top 10 for LLM Applications (2025) — prompt injection (LLM01), sensitive info disclosure, insecure output handling, excessive agency, RAG/vector weaknesses, unbounded consumption; agentic-AI/MCP risks (MITRE ATLAS, post-Oct 2025).
- Logging, monitoring & alerting (**A09:2025**); failing safely (**A10:2025**); secure CI/CD; vulnerability management; coordinated disclosure & bug bounties; Secure by Design.

**PM — Labs**
- 🔍 **"Misconfig Hunt"** (CloudGoat-style) — find & fix an over-permissive IAM policy, an exposed bucket, env-var secrets, and a vulnerable Dockerfile (scan + harden with Trivy).
- 🧙 **"Gandalf Challenge"** — direct + indirect prompt injection to exfiltrate a secret; demo tool poisoning/excessive agency in an agent; add guardrails, output validation, and least-privilege tool access, then re-test.
- 🔴🔵 **"Break the Build"** (Red vs Blue) — Blue builds a GitHub Actions gate (Semgrep + Trivy + Gitleaks) that fails on high-severity findings; Red submits PRs trying to sneak vulns past it.

**Assigned between Session 6 and Session 7 (self-study/team time, not new taught content):** Capstone-studio prep — teams finalize their term project (threat model → vulns → remediation → SBOM/signing → CI pipeline) and rehearse for the Session 7 capstone CTF and project demo, using Session 6's Break the Build pipeline as their working baseline.

### Session 7 (Sat 7 Nov 69) — Wk 18–19: FINAL

**AM — Written exam.** Cumulative, with emphasis on Sessions 5–6 (API, memory safety, supply chain, cloud, AI/LLM, DevSecOps).
**PM — Capstone CTF tournament + final project demos.** A full term-spanning CTF plus each team's secured-build presentation (threat model → vulns → remediation → SBOM/signing → CI pipeline).

---

## 6. Assessment

Same weighting as the KOSEN-KMITL offering — content and grading are unchanged, only the calendar compresses:

| Component | Weight | Graded |
|---|---|---|
| Session lab worksheets — 5 graded sessions (1, 2, 3, 5, 6) | 30% | **Individual** |
| Midterm — Session 4 (AM written + PM CTF practical) | 20% | **Individual** |
| Final — Session 7 (AM written *individual* + PM capstone CTF *team*) | 25% | Mixed |
| Term project (secure build + threat model + remediation report) | 15% | **Team of 2–3** |
| Quizzes (drop lowest) + participation / Houses leaderboard | 10% | Individual + Houses |

**Individual vs team.** Your grade is dominated by **individual mastery** (worksheets, quizzes, exams ≈ 75%). **Team** work is bounded (project 15% + the Session 7 capstone CTF). The weekly-format signature games are compressed into the same PM lab blocks and score toward the **Houses leaderboard under participation** — they drive engagement, not the 30% worksheet grade.

**Term project.** Same as the KOSEN offering, and *not* tied to a single session — teams of 2–3 work on it across the whole term, with a dedicated prep window between Sessions 6 and 7 (see §5). Deliverables: a threat model, a vulnerability report mapped to CWE/OWASP, the fixed code, and a short demo. Each member's mark is scaled by a short peer-contribution evaluation (see [`project/README.md`](project/README.md)).

**Term project rubric (100 pts, scales the 15% above):**

| Criterion | Pts |
|---|---|
| Threat model quality & completeness | 20 |
| Vulnerability findings (correctness, CWE/OWASP mapping, depth) | 25 |
| Remediation quality (correct, minimal, well-explained) | 25 |
| Supply-chain hardening (SBOM + signing + provenance) | 15 |
| CI pipeline (works, fails build appropriately) | 10 |
| Presentation & report clarity | 5 |

**Late submissions.** Same policy as the KOSEN offering: −10% of that item's score per day late,
up to 3 days; not accepted after day 3 without an approved extension. In-session quizzes have no
late window (an absence is covered by the drop-lowest rule above). Documented emergencies get a
case-by-case extension at the instructor's discretion.

---

## 7. Academic Integrity & Ethics Policy

All offensive techniques are taught for **defensive and authorized testing** purposes only. Students must:

- Attack only the targets provided in the course sandbox or systems for which they hold **explicit written authorization**.
- Never use course material against third-party systems, the university network, or fellow students.
- Follow **responsible/coordinated disclosure** if they incidentally discover a real vulnerability.

Violations are treated as serious academic-integrity and conduct breaches. Students sign an ethics acknowledgment in Session 1. Full policy: [`ETHICS.md`](ETHICS.md).

---

## 8. Reference Materials

**Primary references (free, current):**

- OWASP Top 10:2025 — https://owasp.org/Top10/2025/
- OWASP Top 10 for LLM Applications (2025) — https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
- OWASP API Security Top 10 — https://owasp.org/API-Security/
- OWASP Cheat Sheet Series — https://cheatsheetseries.owasp.org/
- MITRE CWE Top 25 & ATT&CK — https://cwe.mitre.org/ , https://attack.mitre.org/
- SLSA (Supply-chain Levels for Software Artifacts) — https://slsa.dev/
- Sigstore — https://www.sigstore.dev/

**Recommended books:**

- *The Web Application Hacker's Handbook* — Stuttard & Pinto.
- *Hacking: The Art of Exploitation* — Jon Erickson (for the memory-safety block).
- *Alice and Bob Learn Application Security* — Tanya Janca (modern, beginner-friendly).
- *Building Secure and Reliable Systems* — Google/O'Reilly (free online).

**Practice platforms:** PortSwigger Web Security Academy (free), picoCTF, OverTheWire, pwn.college, Hack The Box/TryHackMe (intro tracks).

---

## 9. Mapping to OWASP Top 10:2025

| OWASP 2025 Category | Where covered (session) |
|---|---|
| A01 Broken Access Control | Session 3 |
| A02 Security Misconfiguration | Session 6 |
| A03 Software Supply Chain Failures | Session 5 |
| A04 Cryptographic Failures | Session 2 |
| A05 Injection | Sessions 2–3 |
| A06 Insecure Design | Sessions 1, 6 |
| A07 Authentication Failures | Session 3 |
| A08 Software or Data Integrity Failures | Session 5 |
| A09 Security Logging & Alerting Failures | Session 6 |
| A10 Mishandling of Exceptional Conditions | Session 6 |

*Plus dedicated modern coverage beyond the core Top 10: API Security, memory safety/exploitation + fuzzing, and supply-chain security (all Session 5); AI/LLM + agentic security (Session 6).*
