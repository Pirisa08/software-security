# Software Security — 19-Week Course Plan (KOSEN69)

> **Theme:** Every teaching week is built around **one signature game, lab, or competition** — students learn by *breaking* and *defending*, scored on a leaderboard. Lecture is the warm-up; the activity is the main event.

> ✅ **This is now the canonical plan.** `syllabus.md`, `README.md`, and the `labs/` directory scaffold (now `week01…week19`) have all been updated to match. It also folds in the three modernization upgrades from [curriculum-review.md](curriculum-review.md): **fuzzing** (Wk2 + Wk11), **memory-safe languages / Secure by Design** (Wk1, Wk11, Wk15), and **agentic-AI / MCP security** (Wk14).

---

## Structure at a glance

| Block | Weeks | Purpose |
|---|---|---|
| **Unit A — Foundations** | 1–3 | Mindset, SDLC tooling, crypto |
| **Unit B — Web App Security** | 4–6 | Injection, XSS, Authn/Access |
| **🔁 Reflection & Review** | **7** | Consolidate Wk 1–6, mock CTF, exam prep |
| **📝 MIDTERM** | **8–9** | Wk8 = written concepts · Wk9 = hands-on CTF practical |
| **Unit C — Systems & Modern Stack** | 10–16 | API, memory safety, supply chain, cloud, AI/LLM, DevSecOps, capstone |
| **🔁 Reflection & Review** | **17** | Consolidate Wk 10–16, mock CTF, exam prep |
| **📝 FINAL EXAM** | **18–19** | Wk18 = written (cumulative, emphasis Wk10–16) · Wk19 = capstone CTF tournament + project demos |

**12 teaching weeks** (1–6, 10–15) · **1 capstone week** (16) · **2 review weeks** (7, 17) · **2 exam blocks** (8–9, 18–19).

---

## What every teaching week includes

Beyond the signature game, each teaching week's worksheet carries the same evidence-based,
AI-resilient structure (see [AGENDA.md](AGENDA.md) for time-boxing):

- **Lecture (120 min)** → **lab (180 min)** = a signature game (break) + a defend/fix task.
- **Evidence & Integrity** — identity-stamped screenshots; **per-student flags** make copying traceable.
- **🤖 Audit the AI** — students critique an AI-generated exploit/fix (find the insecure/hallucinated parts).
- **🧠 Explain-in-Plain-English + Prompt Problem** — comprehension + AI-literacy (Denny et al. 2024).
- **Viva spot-checks** — 2–3 students reproduce/explain live (graded on understanding).
- **Engagement layer** — points feed a season-long **CTFd scoreboard**, **Houses**/XP, and a weekly Hall of Fame. Houses are persistent, mixed-ability, and **non-graded**; the graded project teams (2–3) nest inside them (see the syllabus *Teams & Houses*).

> A short **weekly quiz** opens each teaching week (drop lowest 1–2); the two cumulative review quizzes run in the **W7/W17** review weeks.

---

## UNIT A — Foundations

### Week 1 — Security Mindset & Threat Modeling
- **Concept:** CIA triad, attacker vs. defender mindset, trust boundaries, attack surface, STRIDE, the OWASP/MITRE landscape, **"Secure by Design" (CISA)** + the memory-safe-language shift as a course-framing slide. Lab 0 environment setup (`docker compose up`).
- **🎲 Signature game — "Elevation of Privilege" card game:** Microsoft's free STRIDE threat-modeling card deck. Teams play cards against a data-flow diagram of a provided app; each valid threat scores a point. Ends with a team-built STRIDE model + DFD.
- **Why it's exciting:** competitive, social, zero setup — gets everyone thinking like an attacker on day one.
- **♻️ Reuse from MFLU68:** *Week 1 Introduction to Software Security* slides + *Worksheet 1*.

### Week 2 — Secure SDLC, Tooling & Fuzzing
- **Concept:** Where security fits in the SDLC, SAST/DAST/SCA/secret-scanning **+ fuzzing** (the dominant modern bug-finding technique), "shift left," DevSecOps overview.
- **🏁 Signature activity — "Bug Triage Race" + "Fuzzing Race":** teams race to run **Semgrep + Gitleaks** on a deliberately flawed repo, then triage and map findings to the correct CWE (score = true positives − misclassified). Bonus round: a quick **coverage-guided fuzzing** intro (libFuzzer/AFL++) — first team to crash the target wins.
- **Why it's exciting:** speed + accuracy competition; mirrors a real bug-bounty triage queue, and fuzzing gives an instant "I found a crash" hit.
- **♻️ Reuse from MFLU68:** *Week 6 GHAS* (GitHub Advanced Security) decks — perfect intro to automated scanning.

### Week 3 — Cryptography Used Correctly (and Misused)
- **Concept:** Hash vs. encrypt vs. encode, password storage (bcrypt/argon2), TLS overview, classic failures (ECB, hardcoded keys, weak RNG, MD5/SHA-1). → **A04:2025**.
- **🔓 Signature game — "Capture the Hash" speedrun:** crack unsalted/MD5 hashes and break an **ECB-mode oracle**, fastest team first. Round 2 = *defend*: rewrite the code to use a vetted KDF + authenticated encryption.
- **Why it's exciting:** instant feedback (the password either cracks or it doesn't), then a flip to the defender side.
- **♻️ Existing repo assets:** `labs/week03-cryptography/` already has `vulnerable_crypto.py`, `hashes.txt`, `solution_skeleton.py`.

---

## UNIT B — Web Application Security

### Week 4 — Injection & Input Handling
- **Concept:** SQL injection, command injection, the general injection pattern, parameterized queries, output encoding. → **A05:2025**.
- **⚔️ Signature game — "SQLi Warm-up":** tiered injection challenges in **DVWA / Juice Shop** (easy → boss). Each cleared level unlocks a flag. Round 2 = patch the endpoints with prepared statements + validation.
- **Why it's exciting:** RPG-style difficulty curve; the "boss" is a stacked filter students must bypass.
- **♻️ Reuse from MFLU68:** *Week 2 Input Validation & Injection Attacks* deck + *Worksheet 2*; *Introduction to Burp Suite* deck.

### Week 5 — Cross-Site Scripting (XSS) & Client-Side Risks
- **Concept:** Reflected/stored/DOM XSS, CSRF, SameSite cookies, CSP, same-origin policy.
- **⛳ Signature game — "XSS Golf":** craft the **shortest payload** that pops `alert(1)` / steals a cookie in Juice Shop. Leaderboard by character count. Round 2 = deploy a **CSP + proper escaping** that blocks every submitted payload.
- **Why it's exciting:** "shortest wins" sparks fierce creativity; defenders then try to break each other's CSPs.

### Week 6 — Authentication, Sessions & Access Control
- **Concept:** Authn vs. authz, session management, JWT pitfalls, OAuth2/OIDC overview, IDOR & privilege escalation. → **A01 / A07:2025**.
- **🗺️ Signature game — "IDOR Treasure Hunt + JWT Forgery":** hunt other users' data by tampering object IDs, then **forge a weak JWT** to become admin. Each secret retrieved = a flag. Round 2 = implement RBAC checks + fix token signing.
- **Why it's exciting:** the "aha" of seeing someone else's data by changing a single number is unforgettable.
- **♻️ Reuse from MFLU68:** *Week 3 Authentication & Session Management* deck + *Worksheet 3* (multiple versions exist).

---

## 🔁 Week 7 — Reflection & Review (pre-Midterm)
- **Format:** No new content. Consolidate Weeks 1–6.
- **🎯 Signature activity — "Security Jeopardy":** team quiz-show across all 6 topics (Threat Modeling / Tooling / Crypto / Injection / XSS / Auth) with point values and a final wager.
- **🧪 Mock CTF:** a short, mixed mini-CTF mirroring the midterm format so there are no surprises.
- **Deliverable:** each student submits a one-page "cheat sheet" (allowed into the exam if you choose open-note).

## 📝 Weeks 8–9 — MIDTERM
- **Week 8 — Written/concept exam:** threat modeling, CWE/OWASP mapping, "spot the vuln in this code," **applied SQL injection (a full 30-pt section: payload + reasoning, no fix credit — that's Section D)**, secure-design short answers.
- **Week 9 — Hands-on CTF practical:** individually solve graded challenges covering injection, XSS, auth/IDOR, and crypto in the sandbox. Flags = points.
- *Covers Weeks 1–6.*

---

## UNIT C — Systems & Modern Stack

### Week 10 — API Security
- **Concept:** REST/GraphQL attack surface, **OWASP API Security Top 10** (BOLA, broken authn, excessive data exposure, mass assignment, rate limiting).
- **🥷 Signature game — "crAPI Raid":** exploit **BOLA + mass assignment** in the crAPI target to take over accounts/vehicles. Round 2 = add authorization checks, schema validation, rate limiting.
- **Why it's exciting:** real-world API takeover scenario; feels like a genuine bug-bounty find.

### Week 11 — Memory-Safety & Exploitation *(merged: old Wk 8 + 9)*
- **Concept:** C/C++ memory model, stack buffer overflows, integer overflow, use-after-free, format-string bugs, mitigations (ASLR, canaries, NX/DEP); intro to `gdb`/Ghidra; **the global shift to memory-safe languages** (CISA/ONCD memory-safety roadmaps — why industry & government are mandating Rust/Go).
- **💥 Signature game — "Fuzzing Race → Pwn the Binary":** Round 1 = **fuzz** the binary to find the bug (AFL++/libFuzzer), first crash wins. Round 2 = smash the stack / format string to hijack control flow (picoCTF / pwn.college style); watch a canary + ASLR change the game. Round 3 = patch it safely, then **rewrite the routine in Rust** and explain why the bug class becomes impossible.
- **Why it's exciting:** the classic hacker rite of passage — fuzzing to find it, getting a shell, then proving memory-safe languages kill the bug.

### Week 12 — Software Supply-Chain Security *(merged: old Wk 10 + 11)*
- **Concept:** Why the supply chain is now top-tier (**A03:2025**); dependency confusion, typosquatting, malicious packages, transitive risk; SBOMs (CycloneDX/SPDX), **SLSA** provenance, **Sigstore/Cosign** signing (**A08:2025**).
- **📦 Signature game — "Dependency Confusion Heist":** in a controlled registry, students plant/identify a typosquatted package and watch it get pulled into a build. Round 2 = generate an SBOM, **sign & verify** the artifact with Cosign, add a provenance gate.
- **Why it's exciting:** a live "supply-chain attack" they can actually pull off safely, then shut down.

### Week 13 — Cloud & Container Security
- **Concept:** Shared-responsibility model, IAM least privilege, secrets management, container image hardening, K8s basics. → **A02:2025**.
- **🔍 Signature game — "Misconfig Hunt" (CloudGoat-style):** find & fix an over-permissive IAM policy, an exposed storage bucket, secrets in env vars, and a vulnerable Dockerfile (scan + harden with **Trivy**). Each fix = a flag.
- **Why it's exciting:** scavenger-hunt format; mirrors how real cloud breaches start.

### Week 14 — AI / LLM Application Security
- **Concept:** **OWASP Top 10 for LLM Apps (2025)** — prompt injection (LLM01), sensitive info disclosure, insecure output handling, excessive agency, RAG/vector risks, unbounded consumption; **agentic-AI / MCP security** (tool poisoning, excessive agency in agent tooling — MITRE ATLAS, post-Oct 2025).
- **🧙 Signature game — "Gandalf Challenge":** beat Lakera's **Gandalf** levels (or a self-hosted vulnerable chatbot) via direct + indirect **prompt injection** to exfiltrate a hidden secret. Leaderboard by level reached. Then demo **tool poisoning / excessive agency** against an agent with tools (e.g. an MCP server). Round 2 = add input/output guardrails, output validation, **least-privilege tool access** + human-in-the-loop, then re-test.
- **Why it's exciting:** genuinely addictive, hugely current, and a great talking point — students love beating Gandalf.

### Week 15 — DevSecOps: Putting It Together
- **Concept:** Logging/monitoring/alerting (**A09**), failing safely (**A10**), secure CI/CD, vulnerability management, coordinated disclosure & bug bounties, **"Secure by Design" (CISA)**.
- **🔴🔵 Signature game — "Break the Build" (Red vs Blue):** Blue team builds a **GitHub Actions** pipeline running SAST (Semgrep) + SCA (Trivy) + secret scanning (Gitleaks) that **fails on high-severity findings**; Red team submits PRs trying to sneak vulns past it. Points for each catch / each bypass.
- **Why it's exciting:** direct adversarial competition; ties every prior week together.
- **♻️ Existing repo:** `labs/week15-devsecops-pipeline/` already built.

### Week 16 — Capstone Studio & CTF Warm-up
- **Format:** Team capstone work-in-progress demos (attack → root cause → fix walkthrough) + a **practice CTF tournament** that previews the final.
- **🏆 Signature activity:** cross-team CTF scrimmage; teams also peer-review each other's term projects.

---

## 🔁 Week 17 — Reflection & Review (pre-Final)
- **Format:** Consolidate Weeks 10–16 (+ quick callback to core concepts from the first half).
- **🎯 Signature activity — "Security Jeopardy: Champions Edition"** spanning the whole course.
- **🧪 Mock final CTF** in the exact format of Week 19.

## 📝 Weeks 18–19 — FINAL EXAM
- **Week 18 — Written exam:** cumulative, with emphasis on Weeks 10–16 (API, memory safety, supply chain, cloud, AI/LLM, DevSecOps) — this is what `labs/week18-final-written/exam.md` implements.
- **Week 19 — Capstone CTF tournament + final project demos:** the big finale — a full CTF covering the whole term, plus each team presents their secured build (threat model → vulns → remediation → SBOM/signing → CI pipeline).

---

## Suggested assessment (replaces the old 2-CTF model)

| Component | Weight |
|---|---|
| Weekly lab worksheets (13 graded) *(individual)* | 30% |
| Midterm — Wk 8 written + Wk 9 CTF practical *(individual)* | 20% |
| Final — Wk 18 written *(individual)* + Wk 19 capstone CTF *(team)* | 25% |
| Term project — secure build + threat model + remediation report *(team of 2–3)* | 15% |
| Weekly quizzes (drop lowest 1–2) + participation / **Houses** leaderboard | 10% |

*See the syllabus **Assessment** + **Teams & Houses** for the individual-vs-team split and the non-graded Houses engagement layer.*

---

## Migration notes — ✅ applied

This 19-week plan is now canonical across the repo:

1. ✅ **`syllabus.md`** §5 (weekly outline), §6 (assessment), §9 (OWASP map) rewritten for 19 weeks with the midterm/final model.
2. ✅ **`README.md`** "Course at a glance" table (19 rows + game column), repo layout, and grading updated.
3. ✅ **`labs/`** re-scaffolded to `week01…week19`: API→Wk10, memory-safety+RE merged→Wk11, supply-chain deps+integrity merged→Wk12, cloud→Wk13, AI/LLM→Wk14, DevSecOps→Wk15, capstone→Wk16; new review weeks (7, 17) and exam weeks (8–9, 18–19) added.

Modernization upgrades from [curriculum-review.md](curriculum-review.md) folded in: fuzzing (Wk2, Wk11), memory-safe languages / Secure by Design (Wk1, Wk11, Wk15), agentic-AI / MCP security (Wk14).
