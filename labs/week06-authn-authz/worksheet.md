# Worksheet 6 — Authentication, Sessions & Access Control (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 6**
> **Aligned:** OWASP 2025 **A01 Broken Access Control**, **A07 Authentication Failures** · **CWE-639** (IDOR), **CWE-347** (improper signature verification), **CWE-321** (weak hardcoded key)
> **Signature games:** 🗺️ **IDOR Treasure Hunt** — walk the `oid` numbers to loot orders that aren't yours · 🔏 **JWT Forgery** — mint a token you were never given.

> ⚠️ **Ethics note:** Forging tokens and accessing other users' objects is only legal in this sandbox (`vulnerable_app.py`) and your own Juice Shop. Doing it to a real service is unauthorized access. Keep all activity inside `http://localhost:8080`.

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|------|-----------|------|-------|
| Pirisa Kitichai | 6631503031 | 12/09 | - |

![Diagram of one request passing two gates: Gate 1 authentication accepts an alg:none forgery, a weak-secret forgery, and alice's real token, then Gate 2 authorization fails to check ownership so alice's valid token reads bob's /api/orders/2 as IDOR, with the solution_app.py fixes for both.](img/authn-vs-authz.svg)

## Part 2 — Lecture Questions

Answer in 2–4 sentences each.

1. Distinguish **authentication** from **authorization**. In `vulnerable_app.py`, `get_order` calls `current_user()` but ignores its result (L63) — which of the two is missing?
2. What is **IDOR** (CWE-639)? Why is `/api/orders/<oid>` exploitable, and what single check in `solution_app.py` (L64) closes it?
3. Explain the **`alg:none`** JWT attack. Why does listing `"none"` in `algorithms=[...]` (L55) let an attacker submit an *unsigned* token?
4. Why is the hardcoded HMAC secret `"secret"` (CWE-321) dangerous even if `alg:none` were disabled? How does a strong random secret + pinned algorithm defend the token?
5. What do the JWT claims **`exp`** and **`aud`** add, and why does the secure version reject tokens that lack them?

## Part 3 — Hands-on Lab (150 min)

**Learning goals:** exploit IDOR, forge JWTs two ways (`alg:none` and weak secret), then prove `solution_app.py` enforces ownership and rejects forged tokens. Steps mirror `attack.md`.

**Prerequisites:** Docker + Docker Compose, `curl`, `python3` with `pyjwt`, optionally Burp Suite. Working dir: `labs/week06-authn-authz/`.

### Environment setup

```bash
cd labs/week06-authn-authz
docker compose up            # python:3.12-slim + flask + pyjwt, runs vulnerable_app.py
# vulnerable app -> http://localhost:8080   (service name: authz-lab, port 8080)
```
Optional secondary target / proxy:
```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop       # -> http://localhost:3000
# Burp Suite: put the proxy listener AND the browser proxy on 127.0.0.1:8081.
# NOT 8080 — the lab app already owns host 8080 (docker-compose.yml, "8080:5000").
# Burp's own default listener is 8080, so you must change it: leave it there and
# either the listener refuses to start ("Address already in use") or, if it does
# bind, the browser's proxy address is the target's address and every request
# goes straight to the app instead of through Burp — you intercept nothing.
```

**What to submit per task:** the exact **command/token**, a **screenshot** of the JSON response, and a **2–3 sentence mitigation**.

---

**Task 0 — Onboarding (5 min).** Get alice's token (from `attack.md`):
```bash
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"alice","pw":"alicepw"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "$TOKEN"
```
Confirm `/api/orders/1` returns alice's Laptop order. *Deliverable: screenshot of the token + order 1.*

![Task 0 — alice's token issued and order 1 (Laptop) confirmed](img/week06_task0.png)

**Task 1 — IDOR Treasure Hunt (30 min) 🗺️.**
- *Goal:* read **bob's** order with **alice's** token.
- *Steps:*
  ```bash
  curl -s http://localhost:8080/api/orders/1 -H "Authorization: Bearer $TOKEN"   # yours
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $TOKEN"   # bob's — leaks!
  ```
- *Deliverable:* both responses + screenshot of bob's `Phone` order + why the missing ownership check (CWE-639) is the root cause.

```sim
jwt-forge
```
**Task 1 — IDOR Treasure Hunt (30 min) 🗺️.**

**ANS** **Result:** Using alice's own token, `/api/orders/1` correctly returned her Laptop order. Using the *same* alice token against `/api/orders/2` — bob's order — the server returned bob's full order data anyway: `{"item": "Phone", "note": "FLAG{idor_demo}", "owner": "bob", "total": 800}`, including a hidden flag value in the `note` field.

**Explanation:** The `get_order` handler calls `current_user()` to authenticate the request, but never compares the authenticated user's identity against the order's `owner` field before returning it. Any valid token — regardless of whose it is — is treated as sufficient to read *any* order by simply changing the numeric `oid` in the URL.

**Why the missing ownership check is the root cause (CWE-639):** Authentication only proves *who* is making the request; it says nothing about whether that user is *allowed* to access the specific object being requested. Without a server-side check like `if order["owner"] != current_user(): return 403`, the endpoint conflates "logged in" with "authorized for this resource," letting any authenticated user enumerate `oid` values and read every other user's data.

**Mitigation:** Add a deny-by-default ownership check on every object-access endpoint: after loading the record, verify `order["owner"] == current_user()` and return `403 Forbidden` if it doesn't match, before returning any data. (CWE-639)

![Task 1 — IDOR reveals bob's order and FLAG{idor_demo} using alice's token](img/week06_task1.png)

**Task 2 — JWT Forgery via alg:none (30 min) 🔏.**
- *Goal:* impersonate bob with an **unsigned** token (no secret needed).
- *Steps:*
  ```bash
  FORGED=$(python3 - <<'PY'
  import jwt
  print(jwt.encode({"sub": "bob"}, key="", algorithm="none"))
  PY
  )
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED"
  ```
- *Deliverable:* the forged token + screenshot of the accepted response + explanation of the `none` flaw (CWE-347).

**Task 2 — JWT Forgery via alg:none (30 min) 🔏.**

**ANS** **Forged token:** `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJib2IifQ.` (created with `jwt.encode({"sub": "bob"}, key="", algorithm="none")`)

**Result:** Submitting this completely unsigned token — note the empty final segment after the last dot — to `/api/orders/2` returned bob's full order data: `{"item": "Phone", "note": "FLAG{idor_demo}", "owner": "bob", "total": 800}`. No password, secret, or valid signature was ever needed to impersonate bob.

**Explanation:** The server's `current_user()` function checks the token's own `alg` header and, if it says `"none"`, decodes the payload with `verify_signature: False` — meaning it explicitly trusts an attacker-controlled claim about which algorithm to use, then trusts the resulting `sub` claim with zero cryptographic verification. Since JWTs are simply base64-encoded JSON, anyone can construct one client-side declaring `alg: none` and set `sub` to any username they want.

**Mitigation:** Never include `"none"` in the server's accepted `algorithms` list when decoding — pin verification to a single expected algorithm (e.g. `algorithms=["HS256"]`) so the `alg` header from the token itself can never control how it is verified. (CWE-347)

![Task 2 — alg:none forged token accepted, returns bob's order and FLAG{idor_demo}](img/week06_task2.png)

**Task 3 — JWT Forgery via weak secret (30 min) 🔏.**
- *Goal:* sign a *valid* HS256 token because the secret is the guessable string `secret` (CWE-321).
- *Steps:*
  ```bash
  FORGED2=$(python3 - <<'PY'
  import jwt
  print(jwt.encode({"sub": "bob"}, "secret", algorithm="HS256"))
  PY
  )
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED2"
  ```
- *Deliverable:* token + screenshot + 2–3 sentences on why secret strength + key management matter.

**Task 3 — JWT Forgery via weak secret (30 min) 🔏.**

**ANS** **Forged token:** `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJib2IifQ.-51G5JQmpJleARHp8rIljBczPFanWT93d_N_7LQGUXU` (created with `jwt.encode({"sub": "bob"}, "secret", algorithm="HS256")`)

**Result:** This token has a *cryptographically valid* HMAC-SHA256 signature — signing it triggered PyJWT's own `InsecureKeyLengthWarning` (the key is only 6 bytes vs. the recommended 32+), confirming the secret is far too weak. Submitting it to `/api/orders/2` returned bob's full order data: `{"item": "Phone", "note": "FLAG{idor_demo}", "owner": "bob", "total": 800}` — the server accepted it as fully legitimate.

**Explanation:** Unlike Task 2's `alg:none` attack, this token is *properly* signed and verified — the vulnerability isn't in the verification logic but in the secret itself. Because the HMAC key is the hardcoded, dictionary-guessable string `"secret"` (CWE-321), anyone who can guess or brute-force it can forge arbitrarily many valid tokens for any username, completely defeating the purpose of a signature.

**Why secret strength and key management matter:** A signature is only as trustworthy as the secret used to create it — a short, common, or hardcoded key can be brute-forced offline in seconds (tools like `hashcat` are built for exactly this), letting an attacker sign tokens for any user without ever touching the server. Strong secrets should be long (32+ random bytes), generated with a cryptographically secure random source, and stored outside the source code (e.g. in environment variables or a secrets manager) — never hardcoded as a literal string. (CWE-321)

![Task 3 — weak secret "secret" allows valid forged JWT, returns bob's order and FLAG{idor_demo}](img/week06_task3.png)

**Task 4 — Privilege/identity escalation reasoning (25 min).**
- *Goal:* combine the flaws. Using Task 2/3 you became `bob` *without his password*; using Task 1 you read objects you don't own.
- *Steps:* document the full attack chain (forge token → access any `oid`). Optionally replay the requests through **Burp Suite Repeater** and screenshot the intercepted request/response.
- *Deliverable:* a short chain diagram/paragraph + Burp (or curl) evidence.

![Task 4 — attack chain diagram: forged JWT (no credentials) + IDOR](img/week06_task4_diagram.png)
![Task 4 — actual evidence: forged token used to read bob's order via curl](img/week06_task2.png)

**Task 5 — Defend / fix it (30 min) 🛡️.**
- *Goal:* prove `solution_app.py` blocks Tasks 1–3.
- *Steps:* stop the vulnerable container (`Ctrl-C`), then:
  ```bash
  docker compose run --rm --service-ports authz-lab bash -c "pip install --no-cache-dir flask pyjwt && python solution_app.py"
  ```
  Re-run: get a fresh alice token, then re-fire each attack. Expected: `/api/orders/2` with alice's token → **403 forbidden** (ownership check, L64); the `alg:none` token → **401 invalid token** (algorithm pinned to HS256, L50); the `"secret"` token → **401** (strong random secret + required `aud`/`exp`, L10/40).
- *Deliverable:* screenshots of the 403 and both 401s + name the fix line for each.

**Task 5 — Defend / fix it (30 min) 🛡️.**

**ANS**

**Re-test 1 — IDOR (Task 1):**
Using alice's legitimate token against `/api/orders/2` (bob's order) now returns `{"error":"forbidden"}` with **HTTP 403** instead of leaking bob's data.
**Fix line (L64):** the ownership check `if order["owner"] != current_user(): return 403` now compares the authenticated identity against the record's actual owner before returning any data — the exact check `vulnerable_app.py` never performed.

**Re-test 2 — alg:none forgery (Task 2):**
Submitting the unsigned token (`alg:none`, empty signature) now returns `{"error":"invalid token"}` with **HTTP 401** instead of being accepted as bob.
**Fix line (L50):** `jwt.decode(token, SECRET, algorithms=["HS256"])` pins the accepted algorithm list to `HS256` only — the server never consults or trusts the token's own `alg` header to decide how to verify it, so an attacker-declared `alg: none` is rejected outright.

**Re-test 3 — weak-secret forgery (Task 3):**
Signing a token with the guessed secret `"secret"` and HS256 now also returns `{"error":"invalid token"}` with **HTTP 401**, even though the signature is cryptographically well-formed.
**Fix line (L10/L40):** the server's real secret is now a strong, randomly-generated key unrelated to the string `"secret"`, and the decode call additionally requires valid `aud`/`exp` claims — so even a properly-structured HS256 token fails verification unless it was signed with the server's actual (unguessable) key.

**Overall conclusion:** `solution_app.py` closes all three flaws by adding the ownership check IDOR was missing (CWE-639), pinning JWT algorithm verification so the token can never dictate its own verification method (CWE-347), and replacing the hardcoded weak secret with a strong managed key plus required claims (CWE-321). Each fix targets the specific broken assumption in the vulnerable version: "any authenticated user can read any object," "the token's own header can be trusted," and "the secret is safe because it's not shown in the API response," respectively.

![Task 5 — solution_app.py returns 403 for IDOR and 401 for both forged JWTs](img/week06_task5.png)

## Part 4 — Reflection

**1. CWE/OWASP mapping**

**ANS** IDOR (Task 1) maps to **CWE-639 / OWASP A01 Broken Access Control**, since the server never verifies the requester owns the object being accessed. The JWT forgeries (Task 2/3) map to **CWE-347 (improper signature verification) and CWE-321 (weak hardcoded key) / OWASP A07 Authentication Failures**, since both let an attacker mint a token the server wrongly trusts as authentic.

**2. Real breach — Optus (2022)**

**ANS** Attackers exploited an API endpoint (`/users/{userId}`) that returned full customer details based on a user ID with no proper access checks, simply by iterating over sequential ID values to systematically extract data from millions of accounts — exposing up to 10 million customers' personal records. This mirrors Task 1 exactly: an authenticated (or in Optus's case, even unauthenticated) request succeeds against *any* object ID because the server never checks whether the caller is authorized for that specific record, only that a request was made at all. It also mirrors Task 4's escalation lesson — a single missing ownership check, combined with predictable/enumerable identifiers, let a low-effort attack scale into a breach affecting a third of Australia's population with no advanced techniques required.

**3. Best mitigation**

**ANS** **Deny-by-default ownership checks** protect the most attack surface, because even with perfect JWT algorithm pinning and a strong secret, an attacker with a *legitimate* token for their own account could still IDOR their way into every other object if the server never checks ownership — as Task 1 showed independently of Task 2/3. Server-side authorization is non-negotiable because authentication only proves *who* is asking; only an explicit, server-enforced ownership/permission check can decide *what* that identity is allowed to see, and that decision can never be safely delegated to the client or inferred from "they have a valid token."

## Grading rubric (100)

| Criterion | Points |
|-----------|-------:|
| Part 2 — Lecture questions (conceptual accuracy) | 20 |
| Part 3 — Exploitation + evidence (payloads/tokens + screenshots, Tasks 1–4) | 40 |
| Part 3 — Defense (Task 5: fixes proven, lines cited) | 25 |
| Part 4 — Reflection (CWE/OWASP mapping, breach, mitigation) | 15 |
| **Total** | **100** |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** ____________________
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*

- **Explain in your own words** *(graded on your reasoning, not copied text):*

  1. **What did you do, and why did the vulnerability work?**

  **ANS:** I read bob's order using alice's own valid token (IDOR), then went further by forging two brand-new tokens with no real credentials at all — one with `alg:none` and an empty signature, and one properly signed with the guessable secret `"secret"` — and used both to read bob's order too. All of this worked because `vulnerable_app.py` never checked that the authenticated user actually owned the object being requested (`get_order` calls `current_user()` but ignores the result), and because JWT verification itself was broken: it trusted the token's own `alg` header enough to skip signature checking entirely, and its "real" verification path used a weak, hardcoded secret anyone could guess.

  2. **Why does your fix actually stop it — and what could still break it?**

  **ANS:** The fix stops IDOR because `solution_app.py` now compares `order["owner"]` against the authenticated identity and returns 403 if they don't match, closing the gap regardless of how the identity was obtained. It stops both JWT forgeries because the server pins verification to a single algorithm (`HS256` only, never trusting `alg:none`) and uses a strong, unguessable secret plus required `aud`/`exp` claims, so a token can no longer dictate its own verification rules or be signed with a brute-forceable key. It could still break if a developer added a new endpoint that forgot to include the same ownership check, or if the strong secret were ever accidentally hardcoded into a public repo or logged somewhere an attacker could find it — the fix is only as good as its weakest untested endpoint or its secret's actual secrecy.

---

## 🤖 Audit the AI (required)

**1. AI's full answer (asked: "fix the JWT verification in this Flask app: `jwt.decode(token, SECRET, algorithms=['HS256', 'none'])`"):**

> "You can fix this by removing 'none' from the algorithms list and just checking the signature:
> ```python
> data = jwt.decode(token, SECRET, algorithms=["HS256"])
> return data.get("sub")
> ```
> This ensures only properly signed HS256 tokens are accepted."

**2. Find what's wrong or risky:**

Removing `"none"` from the algorithms list is correct and necessary, but the AI's answer left `SECRET = "secret"` completely untouched — it never flagged that the hardcoded, dictionary-guessable secret (CWE-321) is just as exploitable as the `alg:none` bug. Even with the algorithm correctly pinned to HS256, an attacker who brute-forces or guesses `"secret"` can still forge perfectly valid signed tokens for any user, exactly as demonstrated in Task 3 — the AI treated this as a single-line "remove the bad algorithm" fix and missed that the *key itself* is the other half of the vulnerability. It also didn't add `exp`/`aud` claim validation, so a token — even a legitimately-issued one — never expires and isn't scoped to this specific application.

**3. Correct version:**

```python
import os
SECRET = os.environ["JWT_SECRET"]  # long, random, generated once, stored outside source code

data = jwt.decode(token, SECRET, algorithms=["HS256"], audience="week06-app",
                  options={"require": ["exp", "aud"]})
return data.get("sub")
```

This is safer because it addresses all three failure modes together: pinning the algorithm (stops `alg:none`), replacing the guessable literal with a strong secret pulled from environment/secrets storage (stops brute-forcing, CWE-321), and requiring `exp`/`aud` claims (stops indefinitely-valid tokens and tokens meant for a different service from being accepted here). The AI's fix addressed only one of these three risks and left the app just as forgeable via Task 3's weak-secret path.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.
---
## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).**

**ANS:** This week's app hands out a login token (a JWT) and then trusts whatever that token claims about who you are — but it checks the token so loosely that anyone can build their own fake one (either completely unsigned, or signed with the easily-guessed word "secret") and the server will still believe it. On top of that, once you're "logged in" as anyone, the order-lookup endpoint lets you view any customer's order just by changing a number in the URL, because it never checks whether the order actually belongs to you.

**B. Prompt Problem.**

**Prompt used:** *"Fix this Flask JWT verification function so it's safe from alg:none forgery and weak-secret brute-forcing: it currently does `jwt.decode(token, SECRET, algorithms=['HS256', 'none'])` where `SECRET = 'secret'`. Pin the algorithm list to HS256 only, replace the hardcoded secret with one loaded from an environment variable, and require the token to include valid `exp` and `aud` claims. Show the corrected code only."*

**Result:** Re-firing the `alg:none` forged token (`eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJib2IifQ.`) and the weak-secret-signed token (`jwt.encode({'sub':'bob'}, 'secret', algorithm='HS256')`) against the AI's corrected code both returned `401 invalid token` — the exploit failed in both cases, confirming the fix works. I also verified a genuinely valid token (signed with the new environment-variable secret, including `exp`/`aud`) was still accepted normally, confirming the fix didn't break legitimate logins.
