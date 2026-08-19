# Lesson Plan — Week 7: Reflection & Review (pre-Midterm)

| | |
|---|---|
| **Course** | Software Security (⬚ course code) |
| **Week / date** | 7 · ⬚ |
| **Contact time** | 300 min (course specification §6 records 2 lecture + 3 laboratory hours; AGENDA.md runs the review weeks as one continuous block) |
| **Lab folder** | `labs/week07-review-midterm-prep` |
| **Slides** | `slides/week07.md` |
| **Type** | Review — **no new content**. Consolidates Weeks 1–6 |
| **Standards consolidated** | OWASP 2025 **A01** Broken Access Control · **A02** Security Misconfiguration · **A04** Cryptographic Failures · **A05** Injection · **A06** Insecure Design · **A07** Authentication Failures · CWE-501, 798, 489, 327, 916, 330, 89, 78, 434, 79, 352, 1004, 639, 287, 347, 321 |
| **CLOs addressed** | **CLO1–CLO4** (course specification §6, week 7 row) |

---

## 1. Session objectives

By the end of this week a student can:

**Knowledge (K)**
- K1 — Recall, without notes, the one-line core of each of Weeks 1–6 and name the CWE and OWASP 2025 category that goes with it.
- K2 — State which of the six half-term topics is exercised by each mock-CTF challenge, and which two (threat modelling and tooling) are examined only in writing.
- K3 — Describe the shape of both midterm papers — what the Week 8 written exam asks for and what the Week 9 practical asks for — well enough to plan revision time against it.

**Skills (P)**
- P1 — Re-land each of the six mock-CTF challenges under exam conditions and timing, unaided by the worksheet's step-by-step instructions.
- P2 — For each challenge solved, give the one-line fix/mitigation — one of the three things the Week 9 submission table requires (flag, payload/command, one-line mitigation) — and, separately, name the CWE, which today's mock-CTF warm-up requires (`mock-ctf.md`) but the Week 9 table does not.
- P3 — Produce a one-page cheat sheet that is their own compression of the half-term, not a transcription of the slides.
- P4 — Identify, honestly, which topics they cannot yet do unaided, and say so in the debrief.

**Attitude (A)**
- A1 — Test only the sandbox targets supplied by the course, under [ETHICS.md](../../ETHICS.md) — this holds in a practice CTF exactly as it does in a graded one.
- A2 — Treat the mock as calibration rather than performance: an unsolved challenge found today is worth more than a solved one copied from a neighbour.
- A3 — Use the hints in `mock-ctf.md` after trying, not instead of trying — Week 9 offers none.

## 2. Key ideas (the through-line)

Weeks 1–6 look like six separate topics and are really one question asked six times: *where does
untrusted data cross a boundary, and what does it get to control on the other side?* In Week 1 the
boundary is drawn on a diagram; in Week 4 the data crosses it into a SQL parser; in Week 5 into an
HTML parser; in Week 6 into an authorisation decision; in Week 3 into a key or a hash; in Week 2 a
tool looks for the crossing on the developer's behalf and misses some of them. The review week's
job is to make that single question retrievable under time pressure, because the exam will present
it in an unfamiliar wrapper. The second job is calibration: students consistently over-rate what
they can reproduce without the worksheet open beside them, and the mock CTF is the cheapest place
to discover that.

## 3. Prior knowledge and preparation

- **Students, before class:** review Weeks 1–6 — slides, their own submitted worksheets, and the
  CWE/OWASP list (`labs/week07-review-midterm-prep/README.md`, step 1). Bring the machine they will
  sit Week 9 on.
- **Instructor, before class — the four mock-CTF targets:** pull `python:3.12-slim` and bring up
  `labs/week03-cryptography`, `labs/week04-injection`, `labs/week05-xss-client-side` and
  `labs/week06-authn-authz` once on the room network the day before. Each of the four compose files
  runs its own `pip install` *at container start* (see §10) — this is four network round-trips per
  student, not one.
- **Instructor, before class — the Jeopardy board:** no board file ships in the repo. The presenter
  note in `slides/week07.md` says to prepare it beforehand — 6 categories × 5 values, questions
  seeded from the exam item bank (the banks live in the git-ignored `instructor/` directory:
  `instructor/exams/item-bank.md`, `instructor/quizzes/review-quiz-item-bank.md`).
- **Instructor, before class — the quiz:** decide whether Quiz 1 runs closed book (`quizzes/quiz1.md`
  reads "Closed book unless your instructor says otherwise") and whether the cheat sheet will be
  admitted to the Week 8 written exam. `slides/week07.md` asks for that decision to be **announced
  today**, because it changes how students build the sheet.
- **Prerequisite state:** the Week 3, 4, 5 and 6 labs have been completed and submitted. A student
  who never stood up one of those targets will lose the mock-CTF block to environment setup.

## 4. Consolidation plan — the six weeks under review

| Wk | Topic | Signature exercise | Must be retrievable cold | Re-tested today by |
|---:|---|---|---|---|
| 1 | Security mindset & threat modelling | "Elevation of Privilege" STRIDE card game | STRIDE letters → property violated; what a trust boundary is; attack surface | Jeopardy (*Threat Modeling*); mock-CTF **warm-up** (3-element STRIDE table); Quiz 1 Part B |
| 2 | Secure SDLC, tooling & fuzzing | "Bug Triage Race" | SAST vs DAST vs SCA vs fuzzing — what each sees, when it runs; true vs false positive | Jeopardy (*Tooling*); Quiz 1 Part A |
| 3 | Cryptography used correctly (and misused) | "Capture the Hash" speedrun | hashing vs encryption vs encoding; why MD5 is wrong for passwords; salts; why ECB leaks; CSPRNG vs `random` | Mock-CTF **#6**; Jeopardy (*Crypto*) |
| 4 | Injection & input handling | "SQLi Warm-up" | data vs code; why a parameterised query wins and escaping does not; `shell=True` → CWE-78 | Mock-CTF **#1, #2**; Jeopardy (*Injection*); Quiz 1 Part C |
| 5 | XSS & client-side risks | "XSS Golf" | reflected vs stored vs DOM; contextual output encoding; CSP; `HttpOnly`/`SameSite`/`Secure` | Mock-CTF **#3**; Jeopardy (*XSS*) |
| 6 | Authentication, sessions & access control | "IDOR Treasure Hunt + JWT Forgery" | authentication ≠ authorisation; IDOR; `alg:none`; weak HMAC secret; `exp`/`aud` | Mock-CTF **#4, #5**; Jeopardy (*Auth & Access*); Quiz 1 Part C |

**Coverage gap to name out loud.** The mock CTF has no challenge for Week 1 or Week 2 — its six
challenges are drawn from Weeks 3–6 only. Threat modelling and tooling are carried by the warm-up,
the Jeopardy board and Quiz 1, and they are examined in the **Week 8 written paper**. A student who
revises only from the mock CTF will walk into Week 8 having skipped two of the six weeks.

## 5. Session run-sheet — 300 min

Timings are AGENDA.md's review-week agenda (Weeks 7 & 17).

| Time | Block | What happens |
|---|---|---|
| 0:00–0:30 | **Cumulative review quiz** | Quiz 1 (`quizzes/quiz1.md`) — 25 pts, 30 min |
| 0:30–1:45 | **Security Jeopardy** | Team quiz-show across the six topics |
| 1:45–2:00 | **Break** | Students bring up their mock-CTF targets during the break |
| 2:00–4:30 | **Mock CTF** | `labs/week07-review-midterm-prep/mock-ctf.md`, in the Week 9 format |
| 4:30–5:00 | **Debrief** | Common mistakes (§6) + midterm logistics (§7) |

*(The presenter notes in `slides/week07.md` sketch a shorter shape — roughly 60–75 min of Jeopardy
and ~90 min of mock CTF. AGENDA.md and `mock-ctf.md` both say ~150 min for the CTF; follow AGENDA.
This is documentation drift, in the same family as AGENDA.md's own "drift to resolve" note.)*

### 5.1 Cumulative review quiz — 0:00–0:30

| Field | Value |
|---|---|
| Instrument | `quizzes/quiz1.md` — "Quiz 1 — Foundations & Web Security (Weeks 1–6)" |
| Weight | 25 pts, 30 min |
| Blueprint | Part A multiple choice 10 × 1 pt · Part B short answer 3 × 3 pts · Part C spot-the-vulnerability 2 × 3 pts |
| Covers | Threat modeling · SDLC/tooling/fuzzing · Cryptography · Injection · XSS · Auth & access control |
| Conditions | Closed book unless the instructor states otherwise |
| Delivery | Google Form (SUBMISSION.md; Forms are built with `instructor/make_quiz_forms.gs`), individual, one attempt, shuffled, locked to the school account. `quiz1.md` prints as the paper fallback |
| Where it counts | The 10% weekly-quizzes / participation component |

Weeks 7 and 17 deliberately have **no** `quizzes/weekly/weekNN.md` 6-question quiz — the cumulative
quiz *is* this week's retrieval practice.

**Cohort rotation.** `quiz1.md` is a static file reused every cohort, which is a leak risk. Swap two
or three MCQs and/or the Part B/C alternates from the review-quiz item bank into a cohort copy,
keeping the total at 25 pts (10 × 1 + 3 × 3 + 2 × 3).

### 5.2 Security Jeopardy — 0:30–1:45

- **Categories** — exactly the six in the lab README, one per week under review:
  *Threat Modeling · Tooling · Crypto · Injection · XSS · Auth & Access*.
- **Board** — 6 categories × 5 point values, plus a **Final Jeopardy wager** at the end
  (`slides/week07.md` presenter note). Prepare it before the session; nothing ships in the repo.
- **Teams** — run by Houses (non-graded engagement layer, per course specification §7).
- **Rules** — the team picks a square and answers; a wrong answer *loses* the points. Keep it fast.
- **Points** — award them into the CTFd / Houses board if the scoreboard is running; the Awards
  mechanism for non-flag games is documented in `instructor/CTFd-SETUP.md` §6.
- **Purpose** — this is the retrieval-practice slot for Weeks 1 and 2, which the mock CTF does not
  reach. Weight the board accordingly rather than filling it with injection questions.

### 5.3 Mock CTF — 2:00–4:30

**How it is run.** `labs/week07-review-midterm-prep/mock-ctf.md`: ~150 min, individual **or pairs**,
sandbox targets only, **hints included**, **ungraded (participation)**, no real exam flags. For each
challenge the student records their payload/command plus a one-line fix, then self-checks against the
linked solution file. Warm-up (concepts): draw a 3-element STRIDE table for any one target, and name
the CWE for each challenge solved.

| # | Challenge | Topic | Hint given in the file | Self-check against |
|---|---|---|---|---|
| 1 | Log in as another user without their password | SQLi (W4) | the username field isn't parameterized | `solution_app.py` |
| 2 | Run a command on the server | cmd injection (W4) | `host` is passed to a shell | `solution_app.py` |
| 3 | Pop `alert(1)` that another user would trigger | stored XSS (W5) | the comment body is rendered raw | `fixed_app.py` (CSP) |
| 4 | Read an order that isn't yours | IDOR (W6) | change the id; no ownership check | `attack.md` |
| 5 | Become admin with a crafted token | weak JWT (W6) | `alg:none` / weak secret `"secret"` | `attack.md` |
| 6 | Recover a password from its hash | crypto (W3) | unsalted MD5 + a wordlist | `solution_skeleton.py` |

**Infrastructure needed.**

| Target | Start | Published port | Installed at container start | Also needed |
|---|---|---|---|---|
| `labs/week03-cryptography` | `docker compose up` | none | `pycryptodome`, `argon2-cffi` | `hashcat` or `john` + the `rockyou.txt` wordlist (worksheet 3 prerequisites) — **not** installed by the compose file |
| `labs/week04-injection` | `docker compose up` | `8080:5000` | `flask` | a browser or `curl` |
| `labs/week05-xss-client-side` | `docker compose up` | `8080:5000` | `flask` | a browser with DevTools |
| `labs/week06-authn-authz` | `docker compose up` | `8080:5000` | `flask`, `pyjwt` | `curl` and host-side `python3` with `pyjwt` (worksheet 6 prerequisites) |

Three of the four targets publish host port **8080** — see §10, risk 1. No per-student flag seeding
is required for the mock: `vulnerable_app.py` in Weeks 4 and 6 falls back to public placeholder
values when the `FLAG_*` environment variables are unset (`labs/week04-injection/vulnerable_app.py`
L10–11, `labs/week06-authn-authz/vulnerable_app.py` L11–12). Flag seeding
(`instructor/seed_flags.py env <STUDENT_ID> > .env`) matters for **Week 9**, not today.

**How scoring works.** The mock CTF is **ungraded** — `mock-ctf.md` marks it participation, with no
flags and no point values, and the student's feedback loop is the self-check column above. The repo
defines no scoring scheme for it: any points beyond participation are ⬚ (instructor's choice). If
the CTFd scoreboard is running, the documented way to put the session on the same leaderboard as the
weekly games is CTFd **Awards** (`instructor/CTFd-SETUP.md` §6: 1st/2nd/3rd = 300/200/100,
first-blood +100, most creative +50). Do not describe CTFd's dynamic scoring or point-costing hints
as the mock's scoring model — those apply to the flag-bearing challenge set, not to this session.

**Formative checkpoints.** By 3:00 every student should have landed at least challenges 1 and 4 —
they are the two shortest paths and the two whose Week 9 counterparts carry 15 pts each. A student
still stuck on #1 at 3:00 is usually re-typing a payload rather than reading the query it produces;
send them to the query comment in `labs/week04-injection/vulnerable_app.py` (lines 61–63). A student
who has solved everything by 3:30 should attempt the ECB-oracle work from Week 3 — Week 9 has such a
challenge and the mock does not (§7).

### 5.4 Debrief — 4:30–5:00

Run §6's misconception list against the room ("hands up who is shaky on this one") and drill the two
or three that draw the most hands, then give the Week 8/9 logistics from §7. Close by collecting or
sighting the one-page cheat sheet.

## 6. Common misconceptions to re-test

The first four are the ones `slides/week07.md` names as the recurring point-losers. The rest are
drawn from the specific corrections carried in the Weeks 1–6 worksheets — every one of them exists
because the naive version was wrong under reproduction.

| # | Misconception | Where it comes from | How to re-test it today |
|---|---|---|---|
| 1 | Encoding, encryption and hashing are interchangeable | `slides/week07.md`; Week 3 lecture Q1 | Jeopardy *Crypto*; Quiz 1 Part B |
| 2 | "The input was validated, so it's safe" — validation substitutes for parameterisation | `slides/week07.md`; Week 4 lecture Q3 | Ask for the fix line, not the payload, on mock-CTF #1 |
| 3 | Authentication implies authorisation | `slides/week07.md`; Week 6 lecture Q1 — `get_order` *calls* `current_user()` and then ignores the result (`vulnerable_app.py` L63) | Mock-CTF #4, then "which line is missing?" |
| 4 | Client-side checks are a control | `slides/week07.md` | Jeopardy *Auth & Access* |
| 5 | `' OR '1'='1` alone bypasses the login | Week 4 worksheet Task 1 — the trailing `--` is required: without it SQL binds `AND` tighter than `OR`, so `... OR '1'='1' AND password='x'` matches no row | Have them state, from the resulting SQL, why the comment is load-bearing |
| 6 | The `<img>` XSS vector is the *shorter* payload | Week 5 worksheet Task 1 — `<img src=x onerror=alert(1)>` is actually 3 characters **longer** than `<script>alert(1)</script>`; it earns its place when `<script>` specifically is filtered, not on length | Jeopardy *XSS*: "why would you ever reach for `onerror`?" |
| 7 | Hardening the cookie fixes CSRF | Week 5 worksheet Task 5 — the Task 4 PoC **still posts** against `fixed_app.py`, because `/comments` never checks the session cookie or a CSRF token before accepting the POST | "The CSP header is present and the attack still worked — why?" |
| 8 | An accepted upload is remote code execution | Week 4 worksheet Task 4 — `UPLOAD_DIR` is not web-served in this lab, so the honest answer is *the missing control*, not a claimed RCE | Ask what two properties the directory and filename would both need |
| 9 | Pinning the JWT algorithm alone secures the token | Week 6 lecture Q4 — the hardcoded HMAC secret `"secret"` is exploitable with `alg` pinned; the fix needs a strong random secret plus required `exp`/`aud` | Mock-CTF #5 — make them do the weak-secret variant, not just `alg:none` |
| 10 | Scanner-clean means bug-free | Week 2 worksheet Task 8 (find a real bug Semgrep did not flag) and Task 4 (fuzzing finds what a pattern-matcher over the same four-line check will not) | Jeopardy *Tooling* |

Two operational stumbles worth pre-empting in the same breath, because they cost minutes rather than
marks: `hashes.txt` needs its comment lines stripped before `hashcat` will read it (Week 3 Task 1),
and the PyJWT `alg:none` forgery needs `key=""` (Week 6 Task 2).

## 7. Exam preparation

### 7.1 Week 8 — written, 120 min, 100 pts

Closed book unless stated otherwise. Blueprint, from `labs/week08-midterm-written/exam.md`:

| Section | Focus | Marks |
|---|---|---|
| A | Concepts | 30 (6 × 5) |
| B | Spot the Vulnerability — name it, give the CWE, give the fix | 20 (4 × 5) |
| C | Applied SQL Injection | 30 |
| D | Defense & Design | 20 (2 × 10) |

**It will ask** for the four question types listed in `labs/week08-midterm-written/README.md`:
build or critique a STRIDE model and identify trust boundaries; classify given vulnerabilities by
CWE/OWASP; find and explain the flaw in a code snippet (injection, XSS, auth, crypto misuse); and
secure-design short answers (least privilege, defence in depth, fail closed). For code answers it
wants the **exact** payload or fix written out, in the student's own words otherwise.

**It will not ask** for anything outside those four types, and it covers Weeks 1–6 only — no
material from Weeks 10–19. Techniques that were *named but not examined* in the teaching weeks stay
unexamined: blind and time-based SQL injection, for instance, were named in Week 4 and are not exam
material ([week04 lesson plan](week04-injection.md) §4).

**Section C reaches past the Week 4 lab — close the gap today.** Week 4 taught auth bypass, UNION
with column matching, `shell=True` and unrestricted upload, all against a string-context SQLite
login. Three of Section C's five sub-questions go further: injection into an **integer** parameter
(C1), DBMS version fingerprinting across MySQL/MSSQL, Oracle and SQLite (C4), and a
`group_concat` + `sqlite_master` subquery to dump table names (C5). None of those three appear
anywhere in the Weeks 1–6 slides or labs — verified by search, not assumed. That is up to 18 of the
paper's 100 marks on material a student revising only from their own worksheets has never met.
Cover it in the Jeopardy *Injection* category, which is the natural slot and is otherwise the block
with the least new work to do, and say plainly in the debrief that quoted-vs-unquoted context and
DBMS fingerprinting are examinable.

### 7.2 Week 9 — CTF practical, 150 min, 100 pts

Individual, sandbox targets only, targets started by the instructor. Seven challenges: six at 15 pts
and one at 10. For each challenge the submission table wants three things — the **flag**, the
**payload or command**, and a **one-line mitigation**. There is partial credit for documented
progress without the flag, which is the single most under-used mark on the paper: a student who can
describe the mechanism and the fix should always write it down.

Flags are **per-student** in Week 9 (SUBMISSION.md: a flag is traceable to the person it was issued
to, and a duplicate implicates both parties). Submission route: flags + payload + mitigation via the
CTF Form / Classroom.

### 7.3 What today's mock does *not* cover — say this explicitly

`mock-ctf.md` promises the "exact format of Week 9", and the six challenges do map one-to-one onto
Week 9's first six. Three differences remain, and students should hear all three today:

| | Mock CTF (today) | Week 9 |
|---|---|---|
| Challenges | 6 | **7** — the extra one is an ECB-oracle challenge (10 pts) drawn from Week 3, with **no counterpart in the mock** |
| Working | individual **or pairs** | individual |
| Hints | included in the file | none |
| Stakes | ungraded, participation | 100 pts |

Anyone who reaches the end of the mock early should spend the remaining time on the Week 3 ECB
oracle (`labs/week03-cryptography`, worksheet 3 Task 2) rather than polishing a solved challenge.

### 7.4 Logistics to read out in the debrief

`slides/week07.md`'s closing note asks for the exam logistics to be stated in this session, and none
of them are recorded in the repository:

- Week 8 (written) — date / time / room: ⬚
- Week 9 (CTF practical) — date / time / room: ⬚
- What to bring; whether the cheat sheet is admitted: ⬚
- Week 9 machine readiness — students sit it on the machine they used today; anyone whose targets
  did not come up in the mock must be fixed before Week 9, not on the day.

### 7.5 Deliverable — the one-page cheat sheet

Each student submits their own one-page cheat sheet. Building it *is* the studying — the compression
is the learning, which is why it must not be a shared file. Whether it may be carried into the
Week 8 written exam is the instructor's decision (⬚), and `slides/week07.md` asks for that decision
to be announced **today** so students build the right artefact.

## 8. Assessment for this week

| Instrument | Evidence | Outcome | Weight |
|---|---|---|---|
| Cumulative review quiz — Quiz 1 (25 pts) | Quiz score | K1, K2 | Part of the 10% quizzes / participation component |
| Mock CTF | Payload + one-line fix recorded per challenge, plus CWE named per challenge in the warm-up | P1, P2, A1 | **Ungraded** — participation |
| Security Jeopardy | Team points | K1 | Non-graded engagement (Houses); CTFd Awards if the scoreboard is running |
| One-page cheat sheet | The sheet | P3 | ⬚ (the repo states the deliverable, not a mark for it) |
| Debrief self-assessment | Named weak areas | P4, A2 | Formative — feeds the instructor's Week 8/9 support list |

There is **no worksheet** for Week 7: the lab folder holds `README.md` and `mock-ctf.md` only, and
the week carries none of the 13 graded worksheets. The graded midterm follows in Weeks 8–9 (20% of
the course mark, course specification §4).

## 9. Materials

- Lab: `labs/week07-review-midterm-prep/` — `README.md`, `mock-ctf.md`
- Quiz: `quizzes/quiz1.md` (25 pts, 30 min) · quiz mechanics: `quizzes/README.md`
- Slides: `slides/week07.md`
- Mock-CTF targets: `labs/week03-cryptography`, `labs/week04-injection`,
  `labs/week05-xss-client-side`, `labs/week06-authn-authz` (`docker compose up` in each)
- Solution files the mock self-checks against: `solution_app.py` (W4, W6), `fixed_app.py` (W5),
  `solution_skeleton.py` (W3), `attack.md` (W6)
- What comes next: `labs/week08-midterm-written/` · `labs/week09-midterm-practical/`
- Instructor-only (git-ignored): `instructor/CTFd-SETUP.md` (scoreboard, Houses, Awards),
  `instructor/make_quiz_forms.gs` (build the quiz Form), `instructor/seed_flags.py` (per-student
  flags — needed for Week 9, not for today), the item banks under `instructor/exams/` and
  `instructor/quizzes/`
- Submission channels: [SUBMISSION.md](../../SUBMISSION.md) · Rules of engagement:
  [ETHICS.md](../../ETHICS.md)

## 10. Risks and contingencies

| Risk | Mitigation |
|---|---|
| **Host port 8080 is a three-way clash.** `labs/week04-injection`, `labs/week05-xss-client-side` and `labs/week06-authn-authz` all publish `8080:5000`, and the mock CTF needs all three. A student who runs `docker compose up` in a second lab folder without stopping the first gets a bind failure | Run one target at a time — the six challenges are independent, so #1/#2 (W4), then #3 (W5), then #4/#5 (W6) — or override the published port in the second and third compose files. Note that macOS AirPlay squats on port **5000**, which here is the *container-side* port and therefore not the cause of this clash |
| **Four `pip install` runs on the room network.** Each compose file installs at container start: `pycryptodome argon2-cffi` (W3), `flask` (W4), `flask` (W5), `flask pyjwt` (W6). In a teaching week that is one round-trip; today it is four per student, and a weak network takes down the whole mock CTF rather than one task | Pre-pull `python:3.12-slim` and bring all four targets up once the day before; have students start their containers during the 1:45–2:00 break, not at 2:00; keep the offline image copy (`docker save` / `docker load`) ready. Students who completed Weeks 3–6 on the same machine already have the layers cached |
| **Challenge 6 has an uninstalled prerequisite.** Cracking the hash needs `hashcat` or `john` plus the `rockyou.txt` wordlist (worksheet 3 prerequisites); the Week 3 compose file installs neither, so the challenge can silently be un-completable | Verify the cracker and wordlist on a representative machine before class. A student without them should do the challenge by reasoning — state why unsalted MD5 falls to a wordlist (CWE-916/327) and what argon2id changes — which is also what the Week 9 partial-credit column rewards. Remember to strip the comment lines from `hashes.txt` first |
| **Challenges 4 and 5 need host-side `pyjwt`.** `pip install … pyjwt` inside the Week 6 container does not help the forging snippets, which run `python3` with `import jwt` on the *host* (worksheet 6 prerequisites) | Have students install `pyjwt` on the host before the session; failing that, pair them for the JWT challenges and require them to write the forged-token reasoning themselves |
| **The Jeopardy board does not exist until someone makes it.** Nothing ships in the repo; if it is not prepared, the 75-minute middle block has no content | Build the 6 × 5 board plus the Final Jeopardy wager beforehand from the item banks in `instructor/`. Fallback if it is unprepared: run the "Map of the half" cold-call recap from `slides/week07.md` and extend the mock-CTF block |
| **The CTFd scoreboard may not be up.** AGENDA.md hedges it as "if running", so points from Jeopardy and the mock may have nowhere to land | Tally on the whiteboard during the session and enter CTFd Awards afterwards (`instructor/CTFd-SETUP.md` §6). Nothing today is graded on those points, so a missing scoreboard costs energy, not marks |
| **A student cannot sit the Form quiz** — the review quizzes run as a Google Form locked to the school account (SUBMISSION.md) | Print `quizzes/quiz1.md`; it carries name/ID/date fields and marks up to the same 25 |
| **Pairs on the mock hide an individual gap.** `mock-ctf.md` allows pairs; Week 9 does not | Require each student to name, in the debrief, one challenge they could not have landed alone — and put that name on the instructor's Week 8/9 support list |
| **Quiz-item leakage between cohorts.** `quiz1.md` is a static file reused each term | Swap two or three MCQs and/or the Part B/C alternates from the review-quiz item bank into a cohort copy, holding the total at 10 × 1 + 3 × 3 + 2 × 3 = 25 |

## 11. Post-teaching reflection

*Complete after the session — this also feeds the course's engagement data.*

- Attendance / completion: ⬚
- Time actually taken per block (vs. plan): ⬚
- Where the class got stuck, and what unblocked them: ⬚
- Mock-CTF challenges left unsolved by more than a third of the room: ⬚
- Misconceptions from §6 that actually surfaced in the debrief (and any new ones): ⬚
- Anything to change before this week runs again: ⬚
