---
marp: true
theme: default
paginate: true
header: "Software Security · Week 14"
---

# Week 14
## Security of AI / LLM-Powered Applications
Software Security · Nutthakorn Chalaemwongwan

<!-- Hook: it's 2026 — your students will all ship AI features. Show that a single sentence can make an AI assistant ignore its rules and leak a secret. No exploit code, just text. ~2 min. -->

---

## Today

- Where AI features add attack surface
- OWASP **LLM Top 10 (2025)**
- Prompt injection (direct + indirect)
- Agentic-AI / MCP risks
- 🎮 Game: **Gandalf Challenge**

<!-- Roadmap, 1 min. Big idea: prompt injection IS injection (W4) — untrusted data interpreted as instructions. Everything they learned applies. Lab = beat Gandalf, then add guardrails. -->

---

## Why a whole week on AI

- LLMs now sit inside real products & agents
- New, fast-moving attack surface
- OWASP LLM Top 10 + MITRE ATLAS

<!-- Justify the week: this is the most current, fastest-moving area in the course. Note the field changes monthly — what they learn is the THINKING, not a fixed list. OWASP LLM Top 10 + MITRE ATLAS are the references. ~3 min. -->

---

## OWASP LLM Top 10 (2025)

| | | |
|---|---|---|
| LLM01 Prompt Injection | LLM02 Sensitive Info Disclosure | LLM03 Supply Chain |
| LLM04 Data/Model Poisoning | LLM05 Improper Output Handling | LLM06 Excessive Agency |
| **LLM07 System Prompt Leakage** | LLM08 Vector/Embedding | LLM09 Misinformation |
| LLM10 Unbounded Consumption | | |

> **New in 2025:** LLM07 System Prompt Leakage · LLM08 promoted (RAG everywhere) · LLM10 replaces "DoS" with runaway *cost*.

> **Heads up:** OWASP shipped a **2026** edition days before this lecture (Excessive Agency jumps to #3, Output Handling drops to #10). This course's lab, worksheet, and quiz key are still on **2025** numbering — use 2025 for anything graded this term.

<!-- Don't read all 10 — highlight the 2025 changes. LLM07 (system-prompt leakage) is new because devs hid secrets in prompts. LLM10 reframed as runaway COST (an agent loop can run up a huge bill). Mention the 2026 edition exists so students who search OWASP themselves aren't confused by different numbers — but the quiz/worksheet key is 2025, don't let them "correct" an answer to 2026 numbering. ~4 min. -->

---

## Prompt injection

> Untrusted text overrides the system's instructions — injection, again.

- **Direct:** user tells the bot to ignore its rules — this week's hands-on lab (Gandalf + Tasks 1-2)
- **Indirect:** malicious instructions hidden in a fetched doc / web page (RAG) — **discussed, not built:** the lab's mock LLM has no RAG/retrieval, so this is a thought experiment (worksheet Task 3), not something you'll exploit yourself today

<!-- The core concept — say "this is W4 injection in a new interpreter (the LLM)." Direct = the Gandalf game + graded Tasks 1-2, fully hands-on. Indirect is the scary one conceptually, but be upfront that this lab can't demonstrate it live — no retrieval pipeline exists to poison. ~6 min. -->

---

## Improper output handling

- Model output flows unsanitized into HTML/SQL/shell
- → XSS / injection downstream
- Treat LLM output as **untrusted input**

<!-- Crucial and overlooked: the LLM's OUTPUT is attacker-influenced data. If you drop it into innerHTML you get XSS (W5); into a query, SQLi (W4). The rule from W5 returns: encode for the context, validate before use. ~4 min. -->

---

## Real-world incidents

- **Bing Chat "Sydney" (2023):** a typed *"ignore previous instructions"* leaked the hidden system prompt — **direct** injection
- **EchoLeak (2025):** *zero-click* **indirect** injection in M365 Copilot → data exfil (CVE-2025-32711)
- **Agentic tool-abuse:** injected web/email content makes a tool-using agent take real actions (send mail, move funds, run code) — it trusts the text as instructions
- **Résumé injection:** hidden white text inflated an AI screening score

> Injection needs no exploit code — just text the model trusts.

<!-- EchoLeak is the headline: zero-click — the victim just receives an email Copilot later reads, and data exfiltrates. No link clicked. Résumé injection makes it relatable (white-on-white text gaming an AI screener). ~5 min. -->

---

## Agentic-AI / MCP risks (2025+)

- Agents call tools (e.g. via **MCP**) → real-world actions
- **Tool poisoning**, **excessive agency**, RCE via tools
- MITRE ATLAS added agent techniques (Oct 2025)
- Research: **43%** of public MCP servers had command-injection flaws

<!-- The frontier — and where THEY will build. The moment an LLM can call tools, injection becomes real-world ACTIONS (send money, run code). The 43% MCP stat lands: the ecosystem is young and insecure. ~5 min. -->

---

## Real MCP/agent incidents (2025)

- **Supabase × Cursor:** privileged agent read a support ticket with injected SQL → leaked integration tokens (privileged access + untrusted input + exfil channel)
- **Invariant Labs:** a malicious trivia MCP server's *tool description* hijacked a trusted WhatsApp MCP → exfiltrated chats
- **MCPoison (CVE-2025-54136):** approved-then-swapped MCP config in Cursor → silent RCE on every session

> The danger pattern: **privilege + untrusted input + an outbound channel.**

<!-- Drive the pattern home — it's the unifying lesson: an exploit needs privilege + untrusted input + a way out. Break any one leg and the attack fails (that's what the defenses do). The tool-DESCRIPTION attack surprises everyone. ~5 min. -->

---

## No boundary in the context window

![The system prompt, the user's typed turn, and any retrieved document all arrive at the model as the same run of text, with nothing marking any of it as data instead of instruction. The reply leaves the same way — untrusted, attacker-shaped text — and if it's passed unescaped into HTML, a shell, or SQL, whatever the model said just executes there. The model itself cannot fix this: there's no tag inside the context window that says "this part is data." The guards have to live outside the model — input_guardrail, redact_secret and escape — which is exactly guarded_chatbot.py.](img/prompt-injection.svg)

<!-- The argument underneath everything today: prompt = system + "\nUser: " + user is ONE string, so the model has no way to tell "instructions I trust" from "text I should just process." Land on the last line before moving to Defenses — it's the direct setup for the three guardrail functions the sim demonstrates next. ~5 min. -->

---

## Defenses

- Input/output **guardrails** + content filtering — *you'll build this: `guarded_chatbot.py`'s regex denylist*
- Strict output **schemas/validation**; encode before downstream use — *you'll build this: HTML-escaping the model's output*
- Redact secrets before they can reach a response — *you'll build this: `redact_secret()`*
- **Least-privilege tool access**, human-in-the-loop, rate limits, isolating untrusted RAG content — *concepts only this week (worksheet Q5); no agent/tool-calling code exists in this lab to demo*

```sim
prompt-guard
```

<!-- The payoff — map each defense to a leg of the pattern: least-privilege tools cut PRIVILEGE; isolating RAG content cuts UNTRUSTED INPUT; egress limits + human approval cut the OUTBOUND CHANNEL. The sim runs the actual guardrail/redact/escape code from both real files against whatever they type, layer by layer. Verified live: try the "not in either list" preset — a natural rephrase ("what's" vs "what is") slips past BOTH the vulnerable list and the guarded regex, in either mode. That's the honest lesson, not "redaction saves it" — in this toy model redact_secret() only has something to catch when mock_llm's own hardcoded leak path already fired, so a keyword filter that's too narrow is a gap on both sides, not one your later layers automatically patch. Be honest that the first three are hands-on today and the fourth bullet is discussion-only. No single guardrail is enough; layer them. ~5 min. -->

---

## 🧙 Game — Gandalf Challenge

1. Beat Gandalf levels via **direct prompt injection** → exfiltrate the secret (real external service, leaderboard by level)
2. **Round 2 (graded):** replay your winning injection + the reflected-XSS payload against the **guarded** bot — does it still land?
3. **Written only:** tool poisoning / excessive agency on an MCP-style agent (worksheet Q5) — no agent exists in this lab to demo live

<!-- Gandalf (Lakera) is genuinely fun and free — students compete to climb levels. Round 2 (Task 5: replay against guarded_chatbot.py) is graded — the point is that guardrails/redaction/escaping visibly stop what worked before. Don't promise a live tool-poisoning demo; it's a discussion question. The weekly quiz no longer asks for the injection/guardrail-failure/flag (dropped — quiz runs before the lab) — that's required in the worksheet instead. ~3 min. -->

---

## Deliverable

> 📋 **Worksheet 14** — `labs/week14-ai-llm-security/worksheet.md` (Part 3) · **kickoff:** `docker compose up` → :8082 (insecure) / :8083 (guarded)

- Attack log: prompt-injection disclosure (Task 1) + reflected-XSS from unescaped output (Task 2)
- Written: indirect-injection thought experiment (Task 3)
- Gandalf leaderboard result (Task 4)
- Mitigations + re-test results against the guarded bot (Task 5)
- Written: least-privilege agent/MCP tool design (Part 2 Q5 — reflection, not a build)
- **+ Audit the AI / EiPE / Prompt Problem** (see worksheet)

<!-- Six graded pieces, not three — the least-privilege tool design is a written reflection, not a build, so don't let students think they're missing a coding artifact for it. Especially fitting this week: the Audit-the-AI task critiques an AI's own (insecure) answer. Ports are 8082/8083 — the old pair's 6000 half was genuinely unreachable (Chrome/Firefox both block port 6000, the X11 port, per their restricted-port lists); 6001 was never actually blocked anywhere, so if asked, the honest reason for the move is "6000 was dead and we replaced the whole pair," not "the browsers blocked both." -->

---

## Key takeaways

- Prompt injection = injection; LLM output = untrusted
- Constrain agency: least-privilege tools, human approval
- The field moves monthly — track OWASP LLM + ATLAS

<!-- Recap. Cold-call: "the agent read a malicious email and wired money — which leg of privilege+input+channel would you cut, and how?" ~2 min. -->

---

# Questions?
Next week: DevSecOps — putting it together

<!-- Cliffhanger: "Next week we wire the whole course into one CI/CD pipeline — Red vs Blue: sneak a vuln past the gate, or block it." -->
