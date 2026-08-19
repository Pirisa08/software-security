# Lesson Plan — Week 4: Injection & Input Handling

| | |
|---|---|
| **Course** | Software Security (⬚ course code) |
| **Week / date** | 4 · ⬚ |
| **Contact time** | 300 min = 120 lecture + 180 laboratory |
| **Lab folder** | `labs/week04-injection` |
| **Slides** | `slides/week04.md` |
| **Standards** | OWASP 2025 **A05 Injection** · CWE-89 (SQL injection), CWE-78 (OS command injection), CWE-434 (unrestricted upload) |
| **CLOs addressed** | **CLO2** exploit · **CLO3** remediate · **CLO5** evaluate & communicate · **CLO6** evidence & ethics |

---

## 1. Session objectives

By the end of this week a student can:

**Knowledge (K)**
- K1 — State why string-concatenated queries and `shell=True` are the root cause of injection, in terms of data being parsed as code.
- K2 — Explain why a parameterised query defeats SQL injection where escaping and blocklists do not.
- K3 — Distinguish input *validation* (allow-listing what is accepted) from output *handling* (encoding for the destination interpreter).

**Skills (P)**
- P1 — Bypass a login with an SQL-injection payload and explain, from the resulting SQL, why it works.
- P2 — Extract data from another table using a UNION-based payload, matching column count and types.
- P3 — Achieve OS command execution through an unsanitised parameter passed to a shell.
- P4 — Upload a file the application should have rejected, and state the control that would have stopped it.
- P5 — Apply the correct fix to each of the four flaws and demonstrate that the original payload now fails.

**Attitude (A)**
- A1 — Test only the targets supplied by the course, under [ETHICS.md](../../ETHICS.md).
- A2 — Submit evidence that is identifiably their own work, and be able to reproduce it live on request.
- A3 — Treat AI-generated security code as something to be verified, not trusted.

## 2. Key ideas (the through-line)

Injection is not a family of unrelated tricks; it is one mistake repeated in different
interpreters. Whenever an application builds a *program* (SQL statement, shell command, file path,
HTML document) by pasting untrusted *data* into it, the interpreter cannot tell which part the
developer meant and which part the attacker supplied. The fix is always structural — hand the data
to the interpreter through a channel that keeps it data (bound parameter, `argv` array,
allow-listed value) — never a smarter filter.

## 3. Prior knowledge and preparation

- **Students, before class:** Docker Desktop running (Week 1 Lab 0); skim the Week 3 recap.
- **Instructor, before class:** pull the lab images ahead of the session (`docker compose pull` in
  the lab folder) — a room of students pulling `python:3.12-slim` at once is the single most
  common way to lose 20 minutes; have the offline fallback ready (see §8).
- **Prerequisite concept:** basic SQL `SELECT … WHERE`, and what a shell metacharacter is.

## 4. Lecture — 120 min

| Time | Block | Content | Method |
|---|---|---|---|
| 0:00–0:10 | Weekly quiz + recap | ~10-min retrieval quiz on Week 3 (crypto misuse); today's agenda | Individual quiz, lowest 1–2 dropped |
| 0:10–0:55 | Core concept | Data vs. code: how an interpreter parses; what "injection" means across SQL, shell, path and HTML; walk one query being built by concatenation and show where control transfers to the attacker | Lecture + live coding on the projector |
| 0:55–1:05 | Break | | |
| 1:05–1:35 | Deep dive + real cases | SQLi variants (auth bypass, UNION, blind/time-based — the last two named, not examined); command injection through `shell=True`; unrestricted upload as "injection into the filesystem"; two brief real breaches | Lecture + short discussion: "what would have stopped this?" |
| 1:35–1:55 | Defences | Parameterised queries and why they are not "escaping"; `subprocess` with `shell=False` and an argv list; regex/allow-list validation; `secure_filename` + extension allow-list; where an ORM helps and where it does not | Lecture with code-diff comparisons |
| 1:55–2:00 | Brief the game | "SQLi Warm-up" — four hits, then the boss is defeated by defending it | Instruction |

**Checks for understanding during lecture**
- After the core concept: cold-call *"which part of this string is code, and who wrote it?"*
- Before the break: one-minute paper — *"why doesn't escaping quotes fix this?"*

## 5. Laboratory — 180 min

Target: `docker compose up` in `labs/week04-injection` → `http://localhost:8080`
(vulnerable app; `solution_app.py` is the correct version).

| Time | Task | Student does | Evidence produced |
|---|---|---|---|
| 0:00–0:15 | **Task 0 — Onboarding** | Stand the app up; log in as `alice`; note seeded users | Screenshot of working app |
| 0:15–0:40 | **Task 1 — Auth bypass (Hit #1)** | `/login?user=alice'--&pw=x`, then `/login?user=x' OR '1'='1'--&pw=x`; read the comment at `vulnerable_app.py:61–63` | Both URLs + `Welcome alice` + why `--` and `OR '1'='1'--` work |
| 0:40–1:10 | **Task 2 — UNION dump (Hit #2)** | Extract credentials from another table; match the column count | Payload + screenshot + note on column matching |
| 1:10–1:40 | **Task 3 — Command injection (Hit #3)** | Reach `id` / `whoami` through the vulnerable parameter | Payloads + output + explanation of the `shell=True` flaw |
| 1:40–2:05 | **Task 4 — Unrestricted upload (Hit #4)** | Upload a file type the app should refuse | Upload evidence + why extension allow-listing matters |
| 2:05–2:40 | **Task 5 — Defend (boss defeated)** | Run the fixed app: `docker compose run --rm --service-ports injection-lab bash -c "pip install --no-cache-dir flask && python solution_app.py"`; re-fire all four payloads | Four failure screenshots + the fix line for each (L52–55 / L62–66 login+search, L74–77 ping, L86–93 upload) |
| 2:40–2:55 | **AI-resilient tasks** | *Audit the AI* (critique an AI-written "fix"), *Explain-in-Plain-English*, *Prompt Problem* | Written answers (start in class, finish as homework) |
| 2:55–3:00 | **Micro-demo + submit** | 2–3 rotating students give a 2–3 min "show your exploit/fix"; everyone submits | Worksheet PDF → Classroom; fixed code → GitHub |

**Formative checkpoints.** A student who is stuck on Task 2 after 15 minutes is almost always
guessing the column count instead of deriving it — prompt them to error out first with `ORDER BY`.
Tasks 1 and 3 must be finished by 1:40 for the defend task to fit; students still stuck at that
point should switch to Task 5 and return afterwards.

## 6. Assessment for this week

| Instrument | Evidence | Outcome | Weight |
|---|---|---|---|
| Worksheet 4, Parts 1–4 | Payloads, screenshots, fix lines, written answers | K1–K3, P1–P5, A2 | Part of the 30% worksheet component |
| Weekly quiz (start of lecture) | Quiz score | K1–K2 | Part of the 10% quiz/participation component |
| Viva spot-check / micro-demo | Live reproduction and explanation | P1–P5, A2 | Pass/flag for follow-up |
| Per-student flag | Flag value tied to the individual student | A2 | Integrity control, not a mark |

Grading detail is in the worksheet's own rubric. Partial credit is available where a student
explains the mechanism correctly but could not land the exploit.

## 7. Materials

- Lab: `labs/week04-injection/` — `vulnerable_app.py`, `solution_app.py`, `docker-compose.yml`, `worksheet.md`
- Slides: `slides/week04.md`
- Optional bosses for the signature game: DVWA (`vulnerables/web-dvwa`), Juice Shop (`bkimminich/juice-shop`)
- Reference: OWASP SQL Injection Prevention Cheat Sheet
- Submission channels: [SUBMISSION.md](../../SUBMISSION.md) · Rules of engagement: [ETHICS.md](../../ETHICS.md)

## 8. Risks and contingencies

| Risk | Mitigation |
|---|---|
| Slow/failed image pulls in class | Pre-pull before the session; keep a USB copy of the image (`docker save`/`docker load`) |
| Port 8080 already in use on a student's machine | Override the published port in `docker-compose.yml`; students on macOS should note AirPlay squats on 5000, not 8080 |
| A student finishes all four hits by 1:10 | Extension: make the UNION payload work without knowing the column count in advance; or write the regression test that proves the fix stays fixed |
| A student cannot get any exploit to land | Pair them with a House member for Task 1 only, then require they land Tasks 3–5 alone; mark the mechanism explanation, not the keystrokes |
| Copy-paste of a classmate's payload | Per-student flags make the submitted evidence attributable; viva spot-check the pair |

## 9. Post-teaching reflection

*Complete after the session — this also feeds the course's engagement data.*

- Attendance / completion: ⬚
- Time actually taken per task (vs. plan): ⬚
- Where the class got stuck, and what unblocked them: ⬚
- Misconception that showed up in the *Explain-in-Plain-English* answers: ⬚
- Quality of the *Audit the AI* critiques (did students catch the planted flaw?): ⬚
- Anything to change before this week runs again: ⬚
