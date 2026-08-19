# How to Do & Submit Work

**Platforms:** the **course platform** (material, quizzes, arena) + **GitHub** (your code fixes).
All offensive work is on the provided sandbox targets only — see [ETHICS.md](ETHICS.md).

| What | Where |
|---|---|
| Course material — worksheets, lab guides | **`learn.zcr.ai/learn`** — no sign-in needed |
| Weekly quiz | **`learn.zcr.ai/quiz`** — the one-time code on your slip |
| Labs / CTF / scoreboard | **`ctf.zcr.ai`** — your account is issued to you, username = your student ID. Private-network challenges need WireGuard: see [docs/arena-vpn-guide.md](docs/arena-vpn-guide.md). |
| Code fixes | **GitHub** — your own fork |
| Worksheet PDFs, project report | **`learn.zcr.ai/submit`** — the submission code on your slip |

> **No Google.** Material, quizzes and worksheet submission all run on the course
> platform. You will not be asked for a Google account.

---

## One-time setup (Week 1)

**Every lab starts with `cd labs/weekNN-…`, so you need the repository on your own
machine before Week 1. Nothing on the website will work without this step.**

1. Create a GitHub account, then **fork** the course repo:
   <https://github.com/nutthakorn7/software-security>
2. Clone your fork and check it out:
   ```bash
   git clone https://github.com/<your-github-username>/software-security.git
   cd software-security
   ```
3. Stand up the environment (Docker Desktop, Burp/ZAP; a Linux VM is an optional
   fallback) — this is **Week 1 Lab 0**.
4. Sign in to **`ctf.zcr.ai`** with the account slip you are given (username = your
   student ID). All the reading is at **`learn.zcr.ai`** — no sign-in needed.

---

## Weekly LAB — how to do & submit

**Do it:**
1. In your fork, create a branch `wk<NN>` (e.g. `wk04`).
2. Stand up the week's target: `docker compose up` (or the command in that lab's README).
3. Work through the **worksheet** (`labs/week<NN>…/worksheet.md`): for each task record the **payload/command**, a **screenshot** of the result, and a **2–3 sentence mitigation**.
4. For the **Defend / fix** task: edit the code, **commit to your `wk<NN>` branch**, and note the **commit hash** in the worksheet.

**Submit (two parts):**
| Part | Where | What |
|------|-------|------|
| Worksheet | **`learn.zcr.ai/submit`** | the completed worksheet exported to **PDF** (screenshots embedded). You can replace it any time before the deadline. |
| Code fix | **GitHub** | push branch `wk<NN>`, open a PR (paste the commit link in the worksheet) |

**File name:** `Wk<NN>_<StudentID>.pdf`  (e.g. `Wk04_65123456.pdf`)
**Deadline:** before the next class session (unless told otherwise).
**Grading:** the 100-pt rubric in each worksheet (Lecture Qs 20 / Tasks+evidence 40 / Defense 25 / Reflection 15).

---

## QUIZ — how it works
- **On the course platform**: go to **`learn.zcr.ai/quiz`** and enter the **one-time
  code on your slip**. It works once, for you only, and you cannot go back to a
  previous question once you continue.
- **Weekly quiz:** a short **~10-min quiz at the start of every teaching week** (6 Q: 5 MCQ + 1 short, **individual**). Low-stakes — the **lowest 1–2 are dropped**.
- **Cumulative review quizzes:** two bigger 25-pt quizzes in the **review weeks** (W7 pre-midterm, W17 pre-final).
- No separate file to submit — the Form **is** the submission.

---

## EXAMS
| Exam | How submitted |
|------|---------------|
| W8 Midterm written | on paper in class (120 min) |
| W9 Midterm CTF | flags in **`ctf.zcr.ai`**; payload + mitigation via **`learn.zcr.ai/submit`** (150 min) |
| W18 Final written | on paper (150 min) |
| W19 Final CTF + demo | flags in **`ctf.zcr.ai`**; recorded video walkthrough submitted **before** the session (graded by rubric) + 3-min live Q&A on the day |

## TERM PROJECT
- Report: fill [project/REPORT-TEMPLATE.md](project/REPORT-TEMPLATE.md) → export PDF → **`learn.zcr.ai/submit`**.
- Code + SBOM + signed artifact + CI pipeline: in the team's **GitHub** repo (link in the report).
- Milestones per [project/README.md](project/README.md).

---

## Rules for every submission
- **Name + Student ID** on every file; teamwork only where stated (labs/quizzes/exams are individual).
- **AI-tool disclosure:** state how you used any AI tool (search, code, translate) — a section is built into the worksheet/report.
- **Late:** −10%/day, up to 3 days (see `syllabus.md` §6); submit what you have.

---

## Academic Integrity & Anti-Cheating

This is a security course — we practice the same rigor on your own work. The following controls are in place; assume your submission is checked.

- **Your flags are unique to you.** Each student receives **personalized CTF/lab flags** derived from your student ID. A flag is traceable to the person it was issued to — submitting someone else's flag is detected automatically and counts as a violation for **both** parties.
- **Your screenshots must show you.** Evidence must include a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in
  the same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed screenshots are not accepted.
- **Your code is attributable.** Work in **your own GitHub fork** with your own commits. Submissions are run through **code-similarity tools (MOSS/JPlag)** against classmates and previous cohorts. A single "paste-everything" commit with no history is a red flag.
- **Quizzes** are individual, time-limited and **one attempt** — your access code is
  single-use and tied to you. Question order *and* option order are shuffled
  per-student, and the quiz only moves forward, so no two people see the same paper
  and nobody can revisit an earlier question.
- **Random live checks.** You may be asked to **reproduce a task or explain your fix live**. Answers you can't explain in your own words score zero.
- **Explain, don't copy.** Reflection questions are graded on *your* reasoning about *your* results.

**Allowed:** discussing concepts, helping a classmate debug their *own* setup, using AI tools **if disclosed**.
**Not allowed:** sharing flags/answers/code, submitting another's screenshots, copying a report.

Violations follow the [ethics & academic-integrity policy](ETHICS.md) and KOSEN's conduct process.
