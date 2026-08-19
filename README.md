# Software Security

A modern, hands-on undergraduate course in software security. Every week pairs a lecture concept with a lab in which students either **break** an intentionally vulnerable target in a safe sandbox or **defend** code they write themselves.

Aligned with **OWASP Top 10 (2025)**, **OWASP Top 10 for LLM Applications (2025)**, the **OWASP API Security Top 10**, **MITRE CWE/ATT&CK**, and the **SLSA** supply-chain framework.

> ⚠️ **Ethics first.** All offensive techniques are taught for **defensive and authorized testing only**. Read [ETHICS.md](ETHICS.md) before starting any lab. Attack only the provided sandbox targets or systems you have **explicit written permission** to test.

---

## Quick start

```bash
git clone <this-repo-url>
cd software-security
# each lab is self-contained:
cd labs/week01-threat-modeling
cat README.md            # follow the lab guide
docker compose up        # (where a target is provided)
```

**Base requirements (Docker-first):** **Docker Desktop**, Git, and a browser proxy (Burp Suite Community or OWASP ZAP) — every lab runs via `docker compose up`, no full VM needed. A few weeks (mainly W11) use the **`labs/toolbox`** container for Linux dev/attacker tools; a Kali/Ubuntu VM is an optional fallback. See [labs/week01-threat-modeling/README.md](labs/week01-threat-modeling/README.md) for the full "Lab 0" setup.

To reach the CTF arena's private-network challenges you'll also need WireGuard — see [docs/arena-vpn-guide.md](docs/arena-vpn-guide.md) for install + connect steps.

---

## Course at a glance

| Wk | Topic | OWASP 2025 | 🎮 Signature game / activity |
|----|-------|-----------|------------|
| 1  | Security mindset & threat modeling | A06 | "Elevation of Privilege" STRIDE card game |
| 2  | Secure SDLC, tooling & fuzzing | — | "Bug Triage Race" + "Fuzzing Race" |
| 3  | Cryptography used correctly | A04 | "Capture the Hash" speedrun + ECB oracle |
| 4  | Injection & input handling | A05 | "SQLi Warm-up" (DVWA / Juice Shop) |
| 5  | XSS & client-side risks | A05 | "XSS Golf" (shortest payload wins) |
| 6  | Authn, sessions & access control | A01, A07 | "IDOR Treasure Hunt + JWT Forgery" |
| **7**  | **🔁 Reflection & Review (pre-midterm)** | — | "Security Jeopardy" + mock CTF |
| **8–9** | **📝 Midterm** (Wk8 written · Wk9 CTF practical) | — | covers Weeks 1–6 |
| 10 | API security | API Top 10 | "crAPI Raid" (BOLA, mass assignment) |
| 11 | Memory-safety & exploitation | — | "Fuzzing Race → Pwn the Binary" + Rust rewrite |
| 12 | Software supply chain (deps + integrity) | A03, A08 | "Dependency Confusion Heist" + Cosign signing |
| 13 | Cloud & container security | A02 | "Misconfig Hunt" (CloudGoat-style) |
| 14 | AI / LLM + agentic security | LLM Top 10 | "Gandalf Challenge" (prompt injection) |
| 15 | DevSecOps: putting it together | A09, A10 | "Break the Build" (Red vs Blue) |
| 16 | Capstone studio & CTF warm-up | — | Practice CTF + peer review |
| **17** | **🔁 Reflection & Review (pre-final)** | — | "Jeopardy: Champions Edition" + mock final |
| **18–19** | **📝 Final** (Wk18 written · Wk19 capstone CTF) | — | cumulative, emphasis Wk 10–16 |

Full details: [syllabus.md](syllabus.md). Expanded design rationale: [course-plan-19weeks.md](course-plan-19weeks.md) · curriculum benchmark vs. top universities: [curriculum-review.md](curriculum-review.md) · per-week readings & resources: [readings.md](readings.md).

---

## Repository layout

```
software-security/
├── README.md                 ← you are here (course landing page)
├── syllabus.md               ← full syllabus, outcomes, assessment, references
├── ETHICS.md                 ← authorized-use policy (read first)
├── slides/                   ← lecture slides (see slides/README.md)
├── labs/
│   ├── week01-threat-modeling/ … week19-final-ctf-capstone/   (each: README + worksheet + materials)
│   │   (teaching: 1–6, 10–15 · capstone: 16 · review: 7, 17 · exams: 8–9 midterm, 18–19 final)
├── worksheets/               ← worksheet template (per-week sheets live in each lab dir)
├── quizzes/                  ← Quiz 1 (Wk 1–6) & Quiz 2 (Wk 10–15) + answer keys
├── project/                  ← term project brief & rubric
└── .github/workflows/        ← security CI pipeline (also the Week 15 demo)
```

---

## Grading

| Component | Weight |
|---|---|
| Weekly labs/games (13 graded) | 30% |
| Midterm (Wk 8 written + Wk 9 CTF practical) | 20% |
| Final (Wk 18 written + Wk 19 capstone CTF) | 25% |
| Term project | 15% |
| Participation / leaderboard / quizzes | 10% |

---

## License

Two licences, because this repository holds two kinds of work:

- **Course material** (worksheets, slides, lab guides, exams, CTF briefs) — **CC BY-NC-SA 4.0**. See [LICENSE-CONTENT](LICENSE-CONTENT).
- **Platform code** (`labs/live-quiz/`, `tools/`, scripts) — **MIT**. See [LICENSE](LICENSE).

Third-party vulnerable targets (Juice Shop, DVWA, crAPI, etc.) keep their own licences and are *referenced, not redistributed*. Files that ARE bundled — the Inter font (OFL) and the Socket.IO client (MIT) — are listed in [NOTICE](NOTICE).

The deliberately vulnerable lab code carries the MIT licence's "AS IS", no-warranty terms, and they are meant literally: don't deploy it, don't copy patterns out of it, don't expose it to an untrusted network.
