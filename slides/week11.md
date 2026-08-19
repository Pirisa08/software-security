---
marp: true
theme: default
paginate: true
header: "Software Security · Week 11"
---

# Week 11
## Memory-Safety & Exploitation
Software Security · Nutthakorn Chalaemwongwan

<!-- Hook: feed random bytes to a C program until it crashes, then turn that crash into "execute my code." This week is the closest to classic hacking — and to why the world is moving to Rust. ~2 min. -->

---

## Today

- The C/C++ memory model & the stack
- Finding bugs with **fuzzing**
- Stack overflow → control hijack
- Mitigations + the **memory-safe language** shift
- 🎮 Game: **Fuzzing Race → Pwn the Binary**

<!-- Roadmap, 1 min. Arc of the week: find (fuzz) → understand (debug) → exploit (pwn) → defend (mitigations) → cure (Rust). Lab follows the same arc. -->

---

## Why this still matters

- C/C++ runs the world's critical infrastructure
- Memory bugs = ~70% of severe CVEs historically
- Now a national-policy issue (CISA/ONCD roadmaps)

<!-- Motivate hard. ~70% of Microsoft/Chrome severe CVEs are memory-safety bugs — that stat lands. It's now government policy (CISA Secure by Design, White House ONCD memory-safety report). This isn't legacy trivia; it's current. ~4 min. -->

---

## The stack frame

- `gets`/`strcpy`/unchecked `memcpy` → overflow
- Overwrite return address → redirect execution

```sim
stack-frame
```

<!-- The worked example — the sim IS the board drawing, live. A local buffer sits BELOW the saved return address; writing past the buffer marches upward into the return address. Control the return address = control where the CPU jumps next. This is THE concept of the week. ~8 min. -->

---

## Bug classes

- **CWE-121** stack overflow · **CWE-787** OOB write
- **CWE-134** format string · **CWE-242** dangerous function (`gets()`)
- *(this week's binary: no UAF, no off-by-one — those are real bug classes but not in this lab's code)*

<!-- Map the family — these four are what's actually in vuln.c/fuzz_harness.c, verified against the source. UAF and off-by-one are legitimate classes worth mentioning exist, but don't cite them as "this week's bug classes" — nothing here demonstrates them. CWE-121 (this week's actual bug) ranks #14 in the 2025 CWE Top 25 — a stronger, on-topic stat than the old CWE-787-was-#1 line, which is now #5. ~3 min. -->

---

## Fuzzing — how bugs are found today

```bash
clang -g -fsanitize=address,fuzzer fuzz_harness.c -o fuzz && ./fuzz   # libFuzzer
afl-fuzz -i seeds -o out -- ./vuln @@                                  # AFL++
```

- Coverage-guided mutation finds crashes fast
- Pair with sanitizers (ASan) for root cause

<!-- Connect to W2 fuzzing (now hands-on). Coverage-guided = the fuzzer mutates inputs and keeps the ones that reach NEW code, so it "learns" its way to deep bugs. ASan turns a silent corruption into a precise crash report. This is round 1 of the game. ~6 min. -->

---

## Exploiting a stack overflow

1. Find offset to return address with a **cyclic pattern** — verify it, don't assume it: this build's offset is 72 bytes, but enabling the stack canary alone moves it to 80 (the canary word sits between buffer and return address)
2. Overwrite RA → jump to `win()`
3. Format string: `%x%x%x` leak, `%n` write

<!-- Walk the exploit method. Cyclic pattern (De Bruijn) tells you exactly how many bytes for THIS specific build — stress that 72 is a fact about the unhardened binary, not a fact about the bug; the sim/exploit-chain diagram shows this shift explicitly. Then overwrite it with the address of win(). Format string: %x leaks stack, %n writes — a primitive most students haven't seen. This is round 2 (pwn). ~6 min. -->

---

## Mitigations raise the bar

- **FORTIFY_SOURCE** — checks the copy itself, at call time (`__strcpy_chk`)
- **Stack canaries** — detect overwrite at function return, *after* the copy already happened
- **ASLR** / **PIE** — randomize addresses
- **NX/DEP** — blocks executing shellcode planted *on the stack* — irrelevant to this exploit, which returns into existing code (`win()`), never injects shellcode
- On **this lab's hardened build, FORTIFY fires first** — `*** buffer overflow detected ***: terminated`. The canary never gets a chance to speak. Verify the order yourself before teaching it as "canary catches it" — that's the wrong answer this lab's own materials were rewritten to correct.

<!-- THE key correction this slide needed: FORTIFY_SOURCE checks at the copy call, before the function even returns — so on the hardened build it always wins the race against the canary, which only checks at return time. This lab's own interactive sim literally calls "the canary detects it" the week's most reliable wrong answer — don't teach it. NX is a real mitigation but not for THIS exploit (ret2win, no injected shellcode) — say so explicitly rather than implying all four defenses equally harden the one attack just demonstrated. Worksheet Q4 grades naming all four (canary/PIE/NX/FORTIFY) + what each defeats — FORTIFY must be on this slide. ~5 min. -->

---

## From strcpy to shell — where each mitigation cuts the chain

![A vertical attack chain from fuzzing finding the crash, to the unchecked strcpy overflow, to the overwritten return address, to a ret2win shell. Three mitigations cut this chain at different links: FORTIFY_SOURCE aborts at copy time, before any overwrite — this hardened build traps here, which students often misread as the canary. The stack canary only detects the smash at return, after the copy already happened. ASLR/PIE randomizes addresses so the fixed win() address is wrong. NX/DEP stops the OTHER exploitation path (injected shellcode), not this one.](img/exploit-chain.svg)

<!-- Walk it top to bottom exactly once — this is the whole week's argument as one picture: which mitigation actually stops THIS exploit, and in what order they'd fire if more than one were present. Land on the same correction as the last slide: FORTIFY wins the race against the canary, every time, on this build. ~4 min. -->

---

## The real fix: memory-safe languages

- **Rust / Go** remove whole bug classes by design
- CISA "Secure by Design" + ONCD: move off C/C++ for new code
- Borrow checker / bounds checks = no overflow, no UAF

<!-- The thesis of the week. Mitigations are a treadmill; memory-safe languages END the bug class. Rust's borrow checker makes UAF a compile error, not a CVE. This is exactly where industry + government are steering. ~4 min. -->

---

## 💥 Game — Fuzzing Race → Pwn the Binary

1. **Round 1 (Fuzzing Race):** first team to crash the target wins
2. **Round 2 (Pwn):** exploit the overflow / format string
3. **Round 3 (Defend):** rebuild with canary+ASLR+PIE, then **rewrite in Rust**

<!-- Explain the 3 rounds before lab. Round 1 = instant feedback (it crashes or not). Round 3 (defend + Rust rewrite) is graded and the real lesson. The weekly quiz no longer asks for the crashing input/defense/flag (dropped — quiz runs before the lab) — that's required in the worksheet instead. ~3 min. -->

---

## Deliverable

> 📋 **Worksheet 11** — `labs/week11-memory-safety-exploitation/worksheet.md` (Part 3) · **kickoff:** in the **toolbox container** (`labs/toolbox` — Apple clang has no libFuzzer runtime): `clang -g -fsanitize=address,fuzzer fuzz_harness.c -o fuzz && ./fuzz`

- Fuzzing crash + exploit script
- Annotated Ghidra/gdb analysis
- Memory-safe (Rust) rewrite + why the bug is now impossible
- **+ Audit the AI / EiPE / Prompt Problem** (see worksheet)

<!-- The Rust rewrite + "why it's now impossible" is the key deliverable — it proves they understand the cure, not just the exploit. AI-resilient tasks count. -->

---

## Key takeaways

- Fuzz to find, debug to understand, mitigate to slow attackers
- Mitigations ≠ cure — memory-safe languages are the cure
- This is where the industry is moving

<!-- Recap. Cold-call: "why aren't stack canaries enough?" (they detect, don't prevent; bypassable via leaks — the cure is memory safety). ~2 min. -->

---

# Questions?
Next week: Software supply-chain security

<!-- Cliffhanger: "Next week — one poisoned dependency owns thousands of victims; we'll replay xz and SolarWinds-style attacks." -->
