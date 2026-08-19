---
marp: true
theme: default
paginate: true
header: "Software Security · Week 10"
---

# Week 10
## API Security
Software Security · Nutthakorn Chalaemwongwan

<!-- Welcome back after midterm. Hook: change one number in an API URL and read a stranger's car location — that's the #1 API bug, and it's everywhere. Today: the OWASP API Top 10, hands-on. ~2 min. -->

---

## Today

- REST/GraphQL attack surface
- OWASP **API Security Top 10**
- BOLA & mass assignment
- Rate limiting & resource consumption
- 🎮 Game: **crAPI Raid**

<!-- Roadmap, 1 min. Frame: APIs are where the web bugs (IDOR, injection) reappear without a browser to hide behind. Lab = raid the deliberately vulnerable crAPI app, then fix it. -->

---

## Recap — Web half

- Injection, XSS, auth/IDOR
- APIs concentrate all of these — and add their own

<!-- 1-min bridge from the web unit. The midterm tested W1-6; APIs reuse all of it. Ask: "what was IDOR?" — because BOLA (the #1 API risk) is literally IDOR at API scale. -->

---

## Why APIs are different

- Machine-to-machine, no browser to "protect" them
- Object IDs everywhere → ripe for IDOR/BOLA
- Clients can send any field → mass assignment
- Maps to the **OWASP API Security Top 10:2023** (still current — no 2025 revision)

<!-- Key framing. No browser = no SameSite/CSP safety net; the API is the raw attack surface. APIs expose object ids by design (REST). Mobile/SPA clients are fully attacker-controlled — never trust what they send. ~5 min. -->

---

## BOLA (API1) — the #1 API risk

```text
GET /api/users/2/orders   → bob's orders — while authenticated as alice
```

- Broken Object Level Authorization = IDOR, at API scale
- The catch: the vulnerable endpoint doesn't check ownership **at all** — it hands back whatever `<id>`'s orders you ask for, full stop. There's no spoofable-but-present check to defeat; there's no check. (The `X-User-Id` header exists as this lab's stand-in for "auth," but on this route the code never even reads it.)

<!-- The worked example — this is today's local target (vulnerable_api.py), not crAPI's vehicle-location challenge (which uses GUID ids you can't just increment — don't reuse that worked example against this lab or the ids won't line up). Same root cause as W6 IDOR. Verify before teaching: `get_orders()` in vulnerable_api.py never calls current_user() — grep it live if you doubt this. Toggling X-User-Id (garbage value, wrong id, omitted) makes zero difference; only the URL's own id matters. Don't say "server trusts a client-set header" — that implies a check exists and is merely spoofable. It's simpler and worse than that: no check runs. The fix (solution_api.py) is what actually introduces the X-User-Id comparison — that's where "auth" first exists in this exercise, fake as it is. ~6 min. -->

---

## Mass assignment (API3)

```json
POST /api/users  { "username":"x", "password":"y", "is_admin":true, "balance":9999 }
```

- Client sets fields the server blindly binds (`user.update(body)` — no allow-list)
- Privilege/balance escalation, right at account creation

```sim
mass-assign
```

<!-- Walk it: the server takes the whole JSON body and binds it to the model, including fields the UI never exposes (is_admin, balance). The sim runs both create_user() implementations for real — edit the body, flip the toggle, watch which fields survive. This is today's local target's mass-assignment bug and the weekly quiz Q6. Fix = allow-list the bindable fields (ALLOWED_CREATE_FIELDS in solution_api.py). ~5 min. -->

---

## More of the Top 10

- API2 — broken authentication *(this week's `X-User-Id` header trick is a live example)*
- **API4 — unrestricted resource consumption:** no rate limit on `/api/login` → today's third graded bug (5 failed attempts, then 429)
- API6 — unrestricted access to sensitive business flows
- Under **2023's** taxonomy, "excessive data exposure" isn't its own number — it's folded into **API3 BOPLA** alongside mass assignment (you may see it listed separately elsewhere, incl. crAPI's own docs — that's the older 2019 split)

<!-- Round out the list. API4 = no rate limit → today's lab actually grades this one (Task 3, 401×5 then 429×2). Flag the API3/"excessive data exposure" taxonomy note pre-emptively — a student cross-checking crAPI's challenge list will see it as separate and think the slide is wrong; it's OWASP's own edition difference. ~4 min. -->

---

## Defenses

- **Object-level authorization** on every request (check ownership)
- **Allow-list** request schemas — bind only intended fields
- Rate limiting / quotas
- Return only needed fields (DTOs)
- Schema validation (OpenAPI / GraphQL types)

<!-- The payoff. #1: ownership check on every object access (kills BOLA). DTO/allow-list binding kills mass assignment AND excessive exposure in one move. Schema validation at the edge rejects junk early. ~5 min. -->

---

## Complementary: black-box recon cheat-sheet

When you only have an IP/URL (Kali):

```bash
netdiscover                 # find hosts
nmap -sV target             # ports/services (80/443?)
nikto -h http://target      # web server issues
dirb  http://target         # hidden paths
wpscan --url http://target  # if WordPress
hydra ... http-post-form    # password attack
```

*General awareness — no worksheet task uses these against today's target; useful for the CTF weeks later in the term.*

<!-- Practical recon, but be upfront it's not homework this week. Emphasize ethics + scope: only against provided sandbox targets. This is the "map the attack surface" muscle from W1, applied live. ~4 min. -->

---

## Real-world: feature abused as backdoor

WordPress 404-template RCE → bind shell:

```text
Appearance → Theme Editor → 404 Template → insert exec(...)
# trigger by visiting any non-existent page
nc -lvp 34567 -e /bin/bash   # attacker gets a shell
```

> Legitimate admin features become RCE without strict authz + integrity checks.

<!-- Shows that "a feature" + missing authz = RCE. A legit admin editor, abused once an attacker has access. Ties to least-privilege: even admins shouldn't be able to inject executable code. ~3 min. -->

---

## One API, three flaws

![One REST API with three separate flaws, each in a different handler. GET /api/users/{id}/orders never compares owner to caller — API1 BOLA. POST /api/users splats the whole JSON body into the model — API3 mass assignment. POST /api/login has no counter or lockout — API4 unrestricted resource consumption. All three are authorization and design flaws, not input-validation flaws — the JSON is well formed, so no amount of escaping, encoding, or a WAF rule blocks any of them.](img/api-flaws.svg)

<!-- Synthesis slide — today's three graded bugs, each traced to its exact line and exact fix. Land on the closing line: nothing here is a malformed-input problem, which is why "sanitize your inputs" doesn't apply this week — these are missing checks, not bad parsing. ~4 min. -->

---

## 🥷 Today's raid — the graded target

Local API, `docker compose up` → :8080 (vulnerable) / :8081 (fixed):

1. **BOLA:** `401 → 403 → 200` — probe, get denied, then read another user's orders as yourself
2. **Mass assignment:** smuggle `is_admin`/`balance` into account creation
3. **Resource consumption:** `401×5 → 429×2` on `/api/login`
4. **Defend:** switch to the pre-written `solution_api.py`, cite the exact fix line for each

> **Bonus (optional, ~20 min): crAPI** — OWASP's own intentionally-vulnerable API, real GUID-based BOLA, capture-only, no fix step, no separate grade

<!-- Explain before lab: the local app IS the graded lab — 65 of 100 points, all four tasks above. crAPI is a genuinely fun bonus with zero grading weight and no fix/patch step — don't imply "Round 2" fixes crAPI, nothing does. Defend (task 4) is read-and-cite against a pre-written solution, not student-authored code. The weekly quiz no longer asks for the mass-assignment field/fix/flag (dropped — quiz runs before the lab) — that's required in the worksheet instead. ~3 min. -->

---

## Deliverable

> 📋 **Worksheet 10** — `labs/week10-api-security/worksheet.md` (Part 3) · **kickoff:** `docker compose up` → :8080 (insecure) / :8081 (secure)

- Findings mapped to the API Top 10:2023 + your two personal flags (`FLAG_BOLA`, `FLAG_MASSASSIGN`)
- Fixes (authz checks, schemas, limits) — cited from `solution_api.py`
- Proof exploits now fail
- **+ Audit the AI / EiPE / Prompt Problem** (see worksheet)

<!-- Before/after + API-Top-10 mapping. AI-resilient tasks count. Also the NoteVault project API task. Both flags come from the local target — remind students crAPI capture isn't part of the deliverable. -->

---

## Key takeaways

- BOLA/IDOR is the dominant API bug — check ownership
- Bind only fields you intend
- Validate and throttle everything

<!-- Recap. Cold-call: "what one check stops BOLA?" (per-object ownership authorization). ~2 min. -->

---

# Questions?
Next week: Memory-safety & exploitation

<!-- Cliffhanger: "Next week we leave the web — crash a C binary with a fuzzer and hijack its execution, then rewrite it in Rust." Remind crAPI pulled before next session. -->
