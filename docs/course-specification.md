# Course Specification — Software Security

Outcome-based (OBE) course specification. It maps what students are expected to be able to do
(CLOs) to how they are taught and how each outcome is evidenced and graded. Written to satisfy
the usual programme-review asks (AUN-QA criteria 1–5; the fields a TQF/มคอ.3-style form expects)
without being tied to one institutional template — sections can be lifted into whichever form the
faculty issues.

> **Fill before submission.** Fields marked ⬚ are institution-specific and are not recorded
> anywhere in this repository: course code, semester/academic year, section, room, and the
> programme's own PLO list.

---

## 1. Course identification

| Field | Value |
|---|---|
| Course title | Software Security |
| Course code | ⬚ |
| Credits | 3 (2 lecture hours + 3 laboratory hours per week, 19 weeks) |
| Level | Undergraduate, 3rd–4th year |
| Prerequisites | Programming (Python/C), Data Structures, Operating Systems basics; Computer Networks recommended |
| Delivery | On-site lecture + hands-on laboratory; all lab targets run locally in Docker |
| Instructor | Nutthakorn Chalaemwongwan |
| Semester / Year | ⬚ |
| Programme | ⬚ |

## 2. Course description

Students learn how software fails under attack and how to build software that resists it. The
course pairs timeless fundamentals — memory safety, injection, authentication, cryptographic
misuse — with the threats that dominate current systems: software supply-chain attacks, cloud and
container misconfiguration, API abuse, and the security of AI/LLM-powered applications.

Each teaching week follows the same rhythm: a 120-minute lecture, then a 180-minute laboratory
built around one *signature exercise* in which students first break a deliberately vulnerable
target, then defend it and prove the defence holds. All exploitation is performed against targets
supplied by the course, inside containers on the student's own machine, under the rules in
[ETHICS.md](../ETHICS.md).

## 3. Course learning outcomes (CLOs)

On completion, students will be able to:

| # | Outcome | Bloom |
|---|---|---|
| **CLO1** | **Model** the security of a software system: identify assets, trust boundaries and attacker goals, and derive the design weaknesses that follow from them. | Analyse |
| **CLO2** | **Exploit** the major vulnerability classes — injection, XSS, broken authentication and access control, API flaws, memory-safety bugs, container and cloud misconfiguration — against a controlled target, and explain the mechanism that makes each work. | Apply / Analyse |
| **CLO3** | **Remediate** those vulnerabilities with the control that actually addresses the root cause, and demonstrate empirically that the original attack no longer succeeds. | Create / Evaluate |
| **CLO4** | **Operate** security tooling across the SDLC — SAST, SCA and dependency review, secret scanning, fuzzing, container and IaC scanning — and interpret, triage and act on its findings, including its false negatives. | Apply / Analyse |
| **CLO5** | **Evaluate** security work produced by others, including AI-generated code and advice, and communicate a finding, its impact and its fix to both a technical and a non-technical audience. | Evaluate |
| **CLO6** | **Practise** security work within legal, ethical and professional limits, and produce evidence of their own work that withstands scrutiny. | Apply / Value |

## 4. CLO → assessment alignment

Weights follow the course syllabus §6. Every CLO is assessed by at least two independent
instruments, and every instrument maps to at least one CLO.

| Assessment | Weight | Mode | CLO1 | CLO2 | CLO3 | CLO4 | CLO5 | CLO6 |
|---|---|---|:--:|:--:|:--:|:--:|:--:|:--:|
| Weekly lab worksheets (13 graded) | 30% | Individual | ● | ● | ● | ● | ● | ● |
| Midterm — W8 written + W9 CTF practical | 20% | Individual | ● | ● | ● | ● | | ● |
| Final — W18 written (individual) + W19 capstone CTF (team) | 25% | Mixed | ● | ● | ● | ● | ● | ● |
| Term project — secure build, threat model, remediation report | 15% | Team of 2–3 | ● | | ● | ● | ● | ● |
| Weekly quizzes (drop lowest 1–2) + participation / Houses | 10% | Individual | | ● | | ● | | |

Within each weekly worksheet, four graded parts recur and carry specific outcomes:

| Worksheet part | Assesses |
|---|---|
| Exploitation tasks | CLO2 |
| Defend / fix task | CLO3 |
| **Audit the AI** — critique an AI-generated exploit or fix | CLO5 |
| **Explain-in-Plain-English + Prompt Problem** | CLO5 |
| **Evidence & Integrity** — identity-stamped proof, per-student flags | CLO6 |
| Viva spot-check / rotating micro-demo | CLO2, CLO3, CLO5 |

## 5. CLO → PLO mapping

⬚ Replace `PLO1…PLOn` with the programme's own outcome statements. Contribution level:
**I** = Introduced, **R** = Reinforced, **M** = Mastered (assessed for mastery).

| CLO | ⬚ PLO1 | ⬚ PLO2 | ⬚ PLO3 | ⬚ PLO4 | ⬚ PLO5 |
|---|:--:|:--:|:--:|:--:|:--:|
| CLO1 Threat modelling | R | | I | | |
| CLO2 Exploitation | M | R | | | |
| CLO3 Remediation | M | M | | R | |
| CLO4 Security tooling / SDLC | R | M | | R | |
| CLO5 Evaluation & communication | | | M | | R |
| CLO6 Ethics & evidence | | | R | | M |

## 6. Weekly schedule

5 contact hours per week (2 lecture + 3 lab). Lab folder names are the canonical reference; each
folder holds the week's README, worksheet and runnable target.

| Wk | Topic | L / Lab | Lab folder | Signature exercise | CLOs |
|---:|---|:--:|---|---|---|
| 1 | Security mindset & threat modelling | 2 / 3 | `labs/week01-threat-modeling` | "Elevation of Privilege" STRIDE card game | 1, 6 |
| 2 | Secure SDLC, tooling & fuzzing | 2 / 3 | `labs/week02-sdlc-tooling` | "Bug Triage Race" | 4 |
| 3 | Cryptography used correctly (and misused) | 2 / 3 | `labs/week03-cryptography` | "Capture the Hash" speedrun | 2, 3 |
| 4 | Injection & input handling | 2 / 3 | `labs/week04-injection` | "SQLi Warm-up" | 2, 3 |
| 5 | XSS & client-side risks | 2 / 3 | `labs/week05-xss-client-side` | "XSS Golf" | 2, 3 |
| 6 | Authentication, sessions & access control | 2 / 3 | `labs/week06-authn-authz` | "IDOR Treasure Hunt + JWT Forgery" | 2, 3 |
| 7 | **Reflection & review** (pre-midterm) | 2 / 3 | `labs/week07-review-midterm-prep` | Mock CTF + cumulative quiz | 1–4 |
| 8 | **Midterm — written** | — | `labs/week08-midterm-written` | — | 1–4, 6 |
| 9 | **Midterm — CTF practical** | — | `labs/week09-midterm-practical` | — | 2, 3, 6 |
| 10 | API security | 2 / 3 | `labs/week10-api-security` | "crAPI Raid" (BOLA + mass assignment) | 2, 3 |
| 11 | Memory safety & exploitation | 2 / 3 | `labs/week11-memory-safety-exploitation` | "Fuzzing Race → Pwn the Binary" | 2, 3, 4 |
| 12 | Software supply-chain security | 2 / 3 | `labs/week12-supply-chain` | "Dependency Confusion Heist" | 4, 5 |
| 13 | Cloud & container security | 2 / 3 | `labs/week13-cloud-container` | "Misconfig Hunt" (CloudGoat-style) | 3, 4 |
| 14 | AI / LLM application security | 2 / 3 | `labs/week14-ai-llm-security` | "Gandalf Challenge" + tool poisoning | 2, 3, 5 |
| 15 | DevSecOps: putting it together | 2 / 3 | `labs/week15-devsecops-pipeline` | "Break the Build" (Red vs Blue) | 4, 5 |
| 16 | Capstone studio & CTF warm-up | 2 / 3 | `labs/week16-capstone` | Project work-in-progress review | 1, 3, 5 |
| 17 | **Reflection & review** (pre-final) | 2 / 3 | `labs/week17-review-final-prep` | Mock CTF + cumulative quiz | 1–5 |
| 18 | **Final — written** (cumulative) | — | `labs/week18-final-written` | — | 1–5 |
| 19 | **Final — capstone CTF + project demos** | — | `labs/week19-final-ctf-capstone` | Team tournament + demo | 2, 3, 5, 6 |

12 teaching weeks (1–6, 10–15) · 1 capstone week (16) · 2 review weeks (7, 17) · 2 exam blocks (8–9, 18–19).

## 7. Teaching and learning methods

- **Break-then-defend laboratories.** Every teaching week's target ships in two forms — a
  vulnerable app and a correct one. Students exploit the first, then apply and *verify* the fix.
- **Retrieval practice.** A ~10-minute low-stakes quiz opens each teaching week; the lowest 1–2
  are dropped. Two cumulative review quizzes run in weeks 7 and 17.
- **AI-resilient tasks.** Each worksheet asks students to critique an AI-generated answer
  (*Audit the AI*), restate a mechanism in plain English, and write a prompt that would have
  produced a correct answer — engaging AI use directly rather than pretending it is absent.
- **Live accountability.** Rotating 2–3 minute micro-demos and random viva spot-checks require
  students to reproduce and explain their own submitted work.
- **Per-student evidence.** Flags are minted per student, so a submitted flag identifies who
  produced it; screenshots are identity-stamped.
- **Engagement layer.** Points feed a season-long scoreboard and non-graded Houses, keeping
  competition motivating without letting a teammate's effort affect an individual's grade.

## 8. Assessment criteria and grading

- Individual work accounts for approximately 75% of the final mark (worksheets, quizzes, written
  exams, midterm practical). Team-graded work is bounded: the term project (15%) and the Week 19
  capstone CTF, with each project member's mark scaled by a peer-contribution evaluation.
- Worksheets are graded against the rubric published in each week's worksheet; partial credit is
  available for a correct mechanism explained without a working exploit.
- Grading scale: ⬚ (institutional scale).

## 9. Verification of student achievement

- Every graded worksheet has a written answer key held by the instructor; keys are reviewed
  against the published worksheet whenever lab content changes.
- Exams exist in two parallel forms (A/B) drawn from a maintained item bank, supporting make-up
  sittings and reducing answer sharing.
- Viva spot-checks and micro-demos sample submitted work live each week; a student who cannot
  reproduce their own submission is followed up individually.
- Flag values are per-student, so a duplicate flag is detectable rather than a matter of judgement.
- Outcome attainment is reviewed at the end of term by mapping the assessment scores back to the
  CLO table in §4.

## 10. Resources

- Course repository: labs, worksheets, slides and runnable targets (this repository).
- `labs/toolbox` — a container image carrying clang/libFuzzer, gdb and recon tools for students
  whose host OS cannot run them natively.
- Docker Desktop on the student's own machine; no cloud account required for the core labs.
- Reading list: [readings.md](../readings.md). Submission channels: [SUBMISSION.md](../SUBMISSION.md).
- Rules of engagement and legal boundaries: [ETHICS.md](../ETHICS.md).

## 11. Academic integrity and AI policy

AI assistants are permitted and are addressed explicitly by the *Audit the AI*, *Explain-in-Plain-English*
and *Prompt Problem* tasks. What is assessed is the student's own understanding, which is why
per-student flags, identity-stamped evidence, live viva spot-checks and micro-demos exist. Passing
off unverified AI output as one's own work — in particular, submitting a fix a student cannot
explain or reproduce — is treated as an academic-integrity matter under ⬚ (institutional policy).

---

*Weekly lesson plans that instantiate this specification: [`docs/lesson-plans/`](lesson-plans/).*
