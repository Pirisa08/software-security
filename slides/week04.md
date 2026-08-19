---
marp: true
theme: default
paginate: true
header: "Software Security · Week 4"
---

# Week 4
## Injection & Input Handling
Software Security · Nutthakorn Chalaemwongwan

<!-- Hook: type one quote mark into a login box and become admin — promise that demo. Injection is the oldest trick that still works. Today they exploit it, then fix it for real. ~2 min. -->

---

## Today

- Why injection is still #1-class of bug
- The general injection pattern
- SQL injection — hands-on
- Command injection
- Defenses: parameterized queries + validation
- 🎮 Game: **SQLi Warm-up**

<!-- Roadmap, 1 min. Tell them the one big idea (data becomes code) unifies SQLi, command injection, and even XSS next week. Lab = exploit DVWA/Juice Shop then patch it. -->

---

## Recap — Week 3

- Crypto failures: ECB, weak hashes, hardcoded keys
- Hashing ≠ encryption ≠ encoding
- Use vetted KDFs (bcrypt/argon2) + authenticated encryption

<!-- 1-min bridge. Last week we protected data at rest; today the attacker sends malicious data IN. Cold-call: "how should we store passwords?" to check W3 stuck. -->

---

## The injection pattern (one idea)

> Untrusted **data** gets interpreted as **code/commands**.

- Attacker input crosses a trust boundary into an interpreter
- SQL, OS shell, LDAP, XPath, template engines, NoSQL…
- Maps to **OWASP A05:2025 Injection**

<!-- This is THE mental model for the whole week — say it twice. Every injection is the same shape: an interpreter can't tell your data from its own instructions. Ask the class to name interpreters in a typical app (DB, shell, template). ~5 min. -->

---

## SQL injection — how it works

```sql
-- vulnerable (this week's app.py, SQLite)
"SELECT * FROM users WHERE username = '" + input + "'"
```

- Input `' OR '1'='1` → always true
- **UNION-based** → read other tables in one shot (today's lab)
- Stacked queries (`'; DROP TABLE users; --`) are the textbook example, but **don't assume they work everywhere** — Python's `sqlite3` refuses multiple statements in one `execute()` call; this week's target raises an error instead

<!-- Walk the string-concatenation on the board: show how the quote in the input lands inside the SQL string and breaks out. This app is SQLite via Python's sqlite3 module — no stacked queries, no blind SQLi task this week (that's UNION-based, direct-output only). Don't promise a DROP TABLE demo works here; it doesn't. ~7 min. -->

---

## Try it — watch the parse tree change

Type an input. See exactly where the quote breaks out of the string.

```sim
sqli-parse
```

<!-- Live payoff for "the quote lands inside the string and breaks out" — the sim renders the actual token boundaries shifting as they type, so the break-out is something they watch happen, not a claim on a slide. ~4 min. -->

---

## Auth bypass — anatomy of one payload

Inject into the **username** field:

```text
alice'--
```

```sql
SELECT * FROM users WHERE username = 'alice'--' AND password = '...';
```

- `'` closes the string literal you're injected into
- `--` comments out everything after it, including the password check
- No trailing space, no `LIMIT` trick needed — this app is SQLite via `fetchone()`, not a MySQL row-count gate; **don't carry over MySQL-specific folklore** ("needs a space after `--`") — that's a different engine's quirk

<!-- The worked example — slow down here. Decompose the payload token by token; this is exactly the SQLi Warm-up's auth-bypass hit. A common wrong instinct is to add `OR 1=1` and a `LIMIT` clause copied from a MySQL tutorial — walk through why neither is needed against this SQLite app, and why the bare `'--` is what the worksheet actually uses. ~8 min. -->

---

## Real-world impact

- **Equifax (2017):** unvalidated HTTP header → Struts RCE (CVE-2017-5638); 147M people, ~$700M settlement
- **Heartland (2008):** SQLi into payment systems → 130M+ cards
- Bulgaria: data on *almost all adults* leaked via SQLi
- Impact: data leak/modification, full DB control, DoS, reputation

<!-- Make it real — these are careers ended and companies fined. Equifax = a single unpatched input parser. Tie back: every breach here started as "untrusted data interpreted as code". ~4 min. -->

---

## Validate: allow-list, not block-list

- **Allow-list (preferred):** accept only known-good (e.g. `0–9` for a phone)
- **Block-list:** ban known-bad → bypassed by new payloads
- Validate **type · length · range · format**
- Client-side for UX, **server-side for security**

<!-- Key principle that recurs all term. Block-lists always lose (attackers invent new payloads); allow-lists define what's acceptable. Emphasize: validation is defense-in-depth, NOT the primary SQLi fix (that's parameterization — next). ~4 min. -->

---

## Demo / attack surface

- Login forms, search boxes, URL params, JSON fields, headers
- Error messages leak schema → enumeration
- Today's lab: raw payloads via browser/curl against `app.py` — no scanner needed to see the mechanism
- Burp Suite / `sqlmap` are real-world tools worth knowing (sandbox-only, ethically) — not required for this week's tasks

<!-- Point out injection isn't just login boxes — any input reaching an interpreter. Note verbose DB errors are a gift to attackers (schema leakage). Be clear Burp/sqlmap are industry-awareness, not something this week's worksheet has them install — every task here is a plain URL/curl payload. ~3 min. -->

---

## Command injection

```php
system("ping -c 1 " . $_GET['host']);   // vulnerable
// host = 8.8.8.8; cat /etc/passwd
```

- Shell metacharacters: `; | & $() \` >`
- Leads to RCE — full server compromise

<!-- Same pattern, deadlier outcome (RCE = own the server, not just the DB). Walk the metacharacters: `;` chains a second command. Ask: "what does `8.8.8.8; cat /etc/passwd` run?" ~5 min. -->

---

## Upload → RCE (a classic chain)

The classic *chain*, attacker uploads `shell.php`:

```php
<?php system($_GET['cmd']); ?>
```

- **If** the upload dir is web-served and PHP-executable: `.../uploads/shell.php?cmd=ls%20-l` → RCE
- **This week's lab stops one step earlier:** CWE-434 unrestricted upload — the app accepts any file type/extension, but the upload directory is **not** served or executed. Your task: explain *which missing control* would complete the chain (type check, extension allow-list, storage outside web root, no-exec) — not demonstrate a live shell
- **Fix:** validate file type via `mime_content_type()`, allow-list extensions, store uploads outside web root, no execute

<!-- Connects to W1's /upload threat model. Be precise: this app does NOT give you a working webshell today — Task 4 is a documentation exercise ("what's missing, and why does that stop RCE?"), not a live exploit. Don't imply students will pop a shell; they'll reason about the one control standing between this bug and that outcome. ~5 min. -->

---

## CWE mapping

- **CWE-89** — SQL injection
- **CWE-78** — OS command injection (CWE-77 is its general parent — cite CWE-78, the specific one)
- **CWE-434** — unrestricted upload of a dangerous file type

<!-- They map every lab finding to a CWE id — these three are what this week's worksheet actually grades. CWE-434 is a quarter of the exploitation score; don't drop it from this list. ~1 min. -->

---

## Defenses that actually work

- **Parameterized queries / prepared statements** (the fix for SQLi)
- ORM with bound parameters
- **Allow-list** input validation (type, length, format)
- Avoid shells: use exec APIs with arg arrays, not string concat
- Least-privilege DB accounts

<!-- The payoff. #1 message: parameterization makes data STAY data — the DB never parses it as SQL. For shells, pass an argv array, not a string. Least-privilege limits blast radius if they still get in. ~5 min. -->

---

## One value, three interpreters

![One untrusted request value reaches three different interpreters — SQL (CWE-89, fixed by a parameterized query), the OS shell (CWE-78, fixed by an argument vector with shell=False), and a filesystem write (CWE-434, fixed by an extension allow-list). One input filter cannot guard three grammars — the fix belongs at the sink that parses the value, not at the source.](img/injection-sinks.svg)

<!-- Synthesis slide — the SAME untrusted value from request.args/request.files is what feeds all three attacks just covered. Land on the closing line: escaping quotes does nothing to a semicolon in a shell, and a safe filename does nothing to SQL. Sets up "Defenses" as three separate fixes, not one. ~4 min. -->

---

## ⚔️ Game — SQLi Warm-up

Four hits against this week's own app — no filters to bypass, the app has none:

1. Auth bypass (`alice'--`)
2. UNION dump (steal all credentials)
3. Command injection
4. Unrestricted upload
5. **Warm-up cleared:** run `solution_app.py`, prove all four attacks now fail, cite the exact fix line for each

<!-- Explain before lab: this is NOT a tiered WAF-bypass ladder — it's 4 fixed attacks against app.py, then proving solution_app.py blocks all 4 ("warm-up cleared" = Task 5). No filter exists in the vulnerable app to bypass; don't set that expectation. DVWA/Juice Shop remain available as optional secondary targets, not the graded game. This is deliberately separate from the arena's own "SQLi Boss Fight" container challenge later in the session — same technique, different target, don't conflate the two names. ~3 min. -->

---

## Lab steps

> 📋 **Worksheet 4** — `labs/week04-injection/worksheet.md` (Part 3) · **kickoff:** `docker compose up` → http://localhost:8080

```bash
docker run --rm -p 80:80 vulnerables/web-dvwa   # optional extra target (or Juice Shop)
```

1. Find an injectable parameter, bypass auth
2. Extract data (UNION dump)
3. Achieve command injection
4. Probe the upload endpoint — document the missing control
5. Rewrite the endpoints safely & re-test

<!-- Logistics. Circulate with TAs. Remind: step 4 (rewrite + prove the payload now fails) is graded, not just the exploit. Also kick off the NoteVault project injection task (worksheet). -->

---

## Deliverable

- Findings: each injection point + payload + impact (CWE-mapped)
- The **fixed** code (prepared statements / validation)
- Proof the payload no longer works
- **+ Audit the AI / EiPE / Prompt Problem** (see worksheet)

<!-- Set expectations: before AND after code + proof. The AI-resilient tasks are part of the grade. The weekly quiz no longer asks for their payload/flag (that question was dropped — quiz runs before the lab, so it couldn't be answered) — the payload + flag are required in the worksheet's Task 1 and Evidence & Integrity section instead. -->

---

## Key takeaways

- Never build interpreter strings from untrusted input
- Parameterize first; validate as defense-in-depth
- Injection = data treated as code

<!-- Recap in 3 lines. Cold-call: "what's the ONE fix for SQLi?" (parameterized queries). ~2 min. -->

---

# Questions?
Next week: XSS & client-side risks

<!-- Cliffhanger: "Next week the same trick runs in the victim's browser — and skims credit cards." Remind DVWA/Juice Shop ready in their VM. -->
