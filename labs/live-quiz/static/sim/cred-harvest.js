// cred-harvest.js — Week 14 simulation (security-cryptography): plain-password
// login vs. challenge-response, and exactly what a log reader recovers from each.
//
// WHAT THIS IS FOR
// The whole lesson lives in one line of server.py: print(f"SERVER SAW PASSWORD:
// {password}") in vulnerable mode vs. print(f"SERVER SAW: nonce={nonce}
// proof={proof}") in fixed mode. What ends up in that line is entirely a
// function of what the client hands the server. This page reproduces exactly
// that choice, live, then asks the follow-up question the lab's README poses:
// once something IS in the log, what can a log reader (compromised server,
// over-eager logging SaaS, breached log store — never a wire eavesdropper)
// actually do with it?
//
// WHAT IS REAL AND WHAT IS MODELLED
//   real: SHA-256 and HMAC-SHA256, implemented from the FIPS 180-4 / RFC 2104
//         specs below (not a toy-sized stand-in like mac-extend.js's hash —
//         this week's lab genuinely runs hashlib.sha256 and hmac.new(...,
//         hashlib.sha256) in common.py, so the sim runs the real algorithms
//         too). Before shipping, this SHA-256/HMAC pair was checked message-
//         for-message against Node's crypto module (many lengths, including
//         the 55/56/64/65-byte padding-boundary cases) and against RFC 4231's
//         HMAC-SHA256 test vectors, including a key longer than the 64-byte
//         block size — every case matched exactly.
//   crypto.subtle is intentionally NOT used — same reasoning as
//         ecdsa-malleability.js and server-can-read.js: WebCrypto's subtle
//         API is only handed out on https/localhost, and a lecture laptop on
//         the room LAN over plain http is not a secure context. SHA-256/HMAC
//         are implemented in plain JS below so the page works either way.
//         crypto.getRandomValues() (not .subtle) IS used for the nonce — that
//         part of the Crypto interface has no secure-context restriction.
//   modelled, not faked: the "server" is a small state machine — one
//         function, serverVerify(), that mirrors server.py's login() pop-
//         then-check logic exactly (single-use nonce, nonce-then-proof
//         check order, generic "denied" on a proof mismatch). Every verdict
//         below — the original login, the immediate replay, the fresh-nonce
//         replay, and the offline guesses — calls this SAME function with
//         whatever bytes that scenario actually has. Nothing branches on
//         which button was clicked; the reuse/replay/guess checks either
//         match or they don't, by real hash comparison.
//   no network, no storage: this page never calls fetch(). "The server" is a
//         string this function builds and displays, in the exact log-line
//         format server.py prints.

(function () {
  "use strict";

  // ---- byte/hex helpers ---------------------------------------------------
  function bytesOf(str) { return Array.from(new TextEncoder().encode(str)); }
  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
  }
  function hexToBytes(hexStr) {
    const out = [];
    for (let i = 0; i < hexStr.length; i += 2) out.push(parseInt(hexStr.substr(i, 2), 16));
    return out;
  }
  function randomBytes(n) {
    const arr = new Uint8Array(n);
    if (window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(arr);
    } else {
      for (let i = 0; i < n; i++) arr[i] = Math.floor(Math.random() * 256);
    }
    return Array.from(arr);
  }

  // ---- real SHA-256 (FIPS 180-4), byte-array in, byte-array out -----------
  const K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
  ];

  function rotr(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }

  function sha256Bytes(msgBytes) {
    let H = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    const bitLen = msgBytes.length * 8;
    const padded = msgBytes.slice();
    padded.push(0x80);
    while (padded.length % 64 !== 56) padded.push(0x00);
    for (let i = 7; i >= 0; i--) {
      padded.push(i >= 4 ? 0 : (bitLen >>> (8 * i)) & 0xff);
    }

    const w = new Array(64);
    for (let chunkStart = 0; chunkStart < padded.length; chunkStart += 64) {
      for (let t = 0; t < 16; t++) {
        const o = chunkStart + t * 4;
        w[t] = ((padded[o] << 24) | (padded[o + 1] << 16) | (padded[o + 2] << 8) | padded[o + 3]) >>> 0;
      }
      for (let t = 16; t < 64; t++) {
        const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
        const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
      }

      let [a, b, c, d, e, f, g, h] = H;
      for (let t = 0; t < 64; t++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const temp1 = (h + S1 + ch + K[t] + w[t]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + temp1) >>> 0;
        d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      H = [
        (H[0] + a) >>> 0, (H[1] + b) >>> 0, (H[2] + c) >>> 0, (H[3] + d) >>> 0,
        (H[4] + e) >>> 0, (H[5] + f) >>> 0, (H[6] + g) >>> 0, (H[7] + h) >>> 0,
      ];
    }
    const out = [];
    for (const word of H) out.push((word >>> 24) & 0xff, (word >>> 16) & 0xff, (word >>> 8) & 0xff, word & 0xff);
    return out;
  }

  // ---- real HMAC-SHA256 (RFC 2104) -----------------------------------------
  function hmacSha256Bytes(keyBytes, msgBytes) {
    const blockSize = 64;
    let key = keyBytes.slice();
    if (key.length > blockSize) key = sha256Bytes(key);
    while (key.length < blockSize) key.push(0x00);
    const ipad = key.map(b => b ^ 0x36);
    const opad = key.map(b => b ^ 0x5c);
    const inner = sha256Bytes(ipad.concat(msgBytes));
    return sha256Bytes(opad.concat(inner));
  }

  // ---- server-side helpers, mirroring common.py exactly --------------------
  function deriveVerifier(saltBytes, passwordBytes) { return sha256Bytes(saltBytes.concat(passwordBytes)); }
  function computeProof(verifierBytes, nonceBytes) { return hmacSha256Bytes(verifierBytes, nonceBytes); }

  // Mirrors server.py's login() pop-then-check state machine exactly:
  //   outstandingNonceBytes === null  -> "no outstanding challenge" (already used)
  //   nonce mismatch                  -> "stale or wrong nonce"
  //   proof mismatch                  -> generic "denied"
  //   match                           -> ok
  // Every caller below (the real login, both replay attempts, every offline
  // guess) goes through this one function with whatever bytes it actually has.
  function serverVerifyChallenge(verifierBytes, outstandingNonceBytes, submittedNonceBytes, submittedProofHex) {
    if (outstandingNonceBytes === null) return { ok: false, reason: "no outstanding challenge" };
    if (bytesToHex(submittedNonceBytes) !== bytesToHex(outstandingNonceBytes)) {
      return { ok: false, reason: "stale or wrong nonce" };
    }
    const expectedProofHex = bytesToHex(computeProof(verifierBytes, submittedNonceBytes));
    return expectedProofHex === submittedProofHex
      ? { ok: true, reason: "proof matched", expectedProofHex }
      : { ok: false, reason: "denied (proof mismatch)", expectedProofHex };
  }

  function serverVerifyPlain(verifierBytes, saltBytes, submittedPasswordBytes) {
    const check = deriveVerifier(saltBytes, submittedPasswordBytes);
    return { ok: bytesToHex(check) === bytesToHex(verifierBytes) };
  }

  // ---- scenarios ------------------------------------------------------------
  // Three login surfaces, one shared bug: whatever the client sends, server.py
  // prints. Preset 0 uses the LAB'S OWN demo account and salt verbatim
  // (server.py's DEMO_USERNAME/DEMO_PASSWORD/DEMO_SALT), so it matches the
  // exact SERVER SAW line students capture themselves in Part 2a.
  const PRESETS = [
    {
      label: "Webmail login", username: "alice", password: "correct-horse-battery",
      salt: "week14-demo-salt",
      reuseService: "the same person's fitness-tracker app (same password, reused)",
      reuseSalt: "fitness-app-salt",
    },
    {
      label: "Support console", username: "helpdesk_tom", password: "Sn0wman#2024",
      salt: "support-console-salt",
      reuseService: "the same person's ticketing-system admin login (same password, reused)",
      reuseSalt: "ticketing-admin-salt",
    },
    {
      label: "Delivery-driver app", username: "driver_lin", password: "PurpleTruck88!",
      salt: "driver-app-salt",
      reuseService: "the same driver's personal email account (same password, reused)",
      reuseSalt: "personal-email-salt",
    },
  ];

  // A tiny illustrative guess list for the offline-dictionary demonstration —
  // deliberately does NOT contain any preset's real password, so every run
  // shows "no match", same as it would against any reasonably-chosen password.
  function guessListFor(preset) {
    return ["password123", "qwerty2024", preset.username + "2024"];
  }

  let PRESET = PRESETS[0];
  let MODE = "plain";

  // Fixed-mode session state: what the legit login actually produced, and
  // what the server still has outstanding for this username afterwards.
  let FIXED = null; // { verifier, nonceBytes, nonceHex, proofBytes, proofHex, outstandingAfterLogin }

  const el = {
    log: document.getElementById("server-log"),
    work: document.getElementById("work"),
    verdictAttacker: document.getElementById("verdict-attacker"),
    verdictReplay: document.getElementById("verdict-replay"),
    summary: document.getElementById("summary"),
    replayBtn: document.getElementById("replay-btn"),
  };

  function loadScenario(preset) {
    PRESET = preset;
    document.querySelectorAll("#presets .preset-btn").forEach((btn, i) => {
      btn.setAttribute("aria-pressed", PRESETS[i] === preset ? "true" : "false");
    });
    el.verdictReplay.textContent = "";
    el.verdictReplay.className = "verdict";
    compute();
  }

  function setMode(mode) {
    MODE = mode;
    document.querySelectorAll("#modes .preset-btn").forEach(btn => {
      btn.setAttribute("aria-pressed", btn.dataset.mode === mode ? "true" : "false");
    });
    el.verdictReplay.textContent = "";
    el.verdictReplay.className = "verdict";
    compute();
  }

  function compute() {
    const saltBytes = bytesOf(PRESET.salt);
    const passwordBytes = bytesOf(PRESET.password);
    const verifier = deriveVerifier(saltBytes, passwordBytes); // stored at signup, in BOTH modes

    if (MODE === "plain") {
      FIXED = null;

      el.log.textContent =
        `POST /login {"username": "${PRESET.username}", "password": "${PRESET.password}"}\n\n` +
        `SERVER SAW PASSWORD: ${PRESET.password}`;

      el.work.textContent =
        "(no crypto ran — the vulnerable path hands the server the raw password, exactly like " +
        "server.py's `password = body.get(\"password\")` branch. There is nothing to compute; " +
        "the password IS the log line.)";

      // What a log reader gets: the password, verbatim. Show the (real,
      // computed) consequence: does it also unlock a second, unrelated
      // account where this person reused it?
      const reuseVerifier = deriveVerifier(bytesOf(PRESET.reuseSalt), passwordBytes);
      const reuseCheck = serverVerifyPlain(reuseVerifier, bytesOf(PRESET.reuseSalt), passwordBytes);

      el.verdictAttacker.className = "verdict bad";
      el.verdictAttacker.textContent =
        `captured from the log: password = "${PRESET.password}"\n\n` +
        `offline guessing: not needed — the real password was captured verbatim.\n\n` +
        `credential-reuse check against ${PRESET.reuseService}:\n` +
        `  sha256(reuse_salt || "${PRESET.password}") == that account's stored verifier -> ` +
        `${reuseCheck.ok ? "MATCH" : "no match"}\n` +
        (reuseCheck.ok
          ? "  -> ACCEPTED there too. One over-logging server just handed the attacker a second account."
          : "  -> unexpected: reuse check should always match here (same password, by construction).");

      el.summary.textContent =
        "CWE-522 / CWE-319 in one direction, CWE-532 in the other: TLS protected this password on " +
        "the wire, and it still ended up sitting in plaintext in a log file the moment it reached " +
        "the endpoint. Nothing about this required breaking any cryptography — the server was simply " +
        "handed the secret and wrote down what it was handed.";
      return;
    }

    // ---- Fixed mode: real challenge-response, computed live ---------------
    const nonceBytes = randomBytes(16);
    const nonceHex = bytesToHex(nonceBytes);
    const proofBytes = computeProof(verifier, nonceBytes);
    const proofHex = bytesToHex(proofBytes);

    // The legit login itself: server had just issued this exact nonce, so it
    // verifies — through the SAME serverVerifyChallenge() used for replays below.
    const legit = serverVerifyChallenge(verifier, nonceBytes, nonceBytes, proofHex);

    // server.py pops the username's outstanding nonce on EVERY /login POST for
    // that user, success or not — so immediately after this legit login, there
    // is nothing outstanding to replay against.
    FIXED = { verifier, saltBytes, nonceBytes, nonceHex, proofBytes, proofHex };

    el.log.textContent =
      `GET /challenge?username=${PRESET.username} -> {"nonce": "${nonceHex}", "salt": "${bytesToHex(saltBytes)}"}\n` +
      `POST /login {"username": "${PRESET.username}", "nonce": "${nonceHex}", "proof": "${proofHex}"}\n\n` +
      `SERVER SAW: nonce=${nonceHex} proof=${proofHex}` +
      (legit.ok ? "" : "  (unexpected: legit login failed to verify)");

    el.work.textContent =
      `verifier = SHA-256(salt || password)        [derived once, locally — never sent]\n` +
      `verifier = ${bytesToHex(verifier)}\n` +
      `nonce (server-issued, single-use, 16 bytes) = ${nonceHex}\n` +
      `proof = HMAC-SHA256(verifier, nonce)        = ${proofHex}`;

    // Offline-guess demonstration: everything a log reader has here (salt,
    // nonce, proof) is PUBLIC/log-visible, so an offline check against a
    // candidate password IS possible from log access alone — the same
    // real hash math, run against three guesses instead of the real password.
    const guesses = guessListFor(PRESET);
    const guessLines = guesses.map(g => {
      const guessVerifier = deriveVerifier(saltBytes, bytesOf(g));
      const guessProofHex = bytesToHex(computeProof(guessVerifier, nonceBytes));
      const match = guessProofHex === proofHex;
      return `  "${g}" -> proof ${guessProofHex}  ${match ? "MATCH" : "no match"}`;
    }).join("\n");

    el.verdictAttacker.className = "verdict ok";
    el.verdictAttacker.textContent =
      `captured from the log: nonce=${nonceHex} proof=${proofHex}\n` +
      `no password anywhere in this line.\n\n` +
      `offline guesses against the intercepted (salt, nonce, proof) — all three are log-visible:\n` +
      `${guessLines}\n\n` +
      `none of these 3 match — but if the real password HAD been on this list, this exact offline ` +
      `check would have found it (Worksheet Q4's "offline-dictionary resistance" gap). What makes ` +
      `that loop expensive at internet scale is a SLOW verifier KDF (bcrypt/argon2, Week 2) — this ` +
      `demo's plain salted SHA-256 is fast on purpose, to keep the lesson readable, not to be safe.`;

    el.summary.textContent =
      "Same server, same print() call — but the bytes it's handed are structurally different: a " +
      "single-use nonce and an HMAC output, not a password. A log reader here recovers nothing that " +
      "logs in anywhere else, and nothing that answers 'what did they type', because HMAC has no " +
      "inverse. That's the ONE property this demo proves — see the Honest Scope box for the two it doesn't.";
  }

  function runReplay() {
    if (MODE === "plain") {
      const passwordBytes = bytesOf(PRESET.password);
      const verifier = deriveVerifier(bytesOf(PRESET.salt), passwordBytes);
      const result = serverVerifyPlain(verifier, bytesOf(PRESET.salt), passwordBytes);
      el.verdictReplay.className = "verdict bad";
      el.verdictReplay.textContent =
        `Attacker logs in again with the exact same captured password:\n` +
        `sha256(salt || "${PRESET.password}") == stored verifier -> ${result.ok ? "MATCH" : "no match"}\n\n` +
        (result.ok
          ? "✓ ACCEPTED — a captured plaintext password is a standing credential. There's no nonce, " +
            "no expiry, nothing single-use about it: the attacker can walk back in tomorrow, or next " +
            "month, from anywhere, as many times as they like, until the password is changed."
          : "unexpected: this check should always match (same password, by construction).");
      return;
    }

    if (!FIXED) return;
    const { verifier, nonceBytes, nonceHex, proofHex } = FIXED;

    // Attempt 1: replay the EXACT captured request. server.py already popped
    // this username's nonce the moment the legit login above used it, so
    // there is nothing outstanding — REJECTED before the proof is even checked.
    const attempt1 = serverVerifyChallenge(verifier, /* outstanding */ null, nonceBytes, proofHex);

    // Attempt 2: attacker fetches a genuinely fresh nonce themselves (that
    // endpoint isn't secret — anyone can call GET /challenge), so the nonce
    // check passes this time. But all they have is the OLD proof, which was
    // computed by HMAC over the OLD nonce — cryptographically bound to it.
    const freshNonceBytes = randomBytes(16);
    const freshNonceHex = bytesToHex(freshNonceBytes);
    const attempt2 = serverVerifyChallenge(verifier, /* outstanding */ freshNonceBytes, freshNonceBytes, proofHex);

    el.verdictReplay.className = "verdict ok";
    el.verdictReplay.textContent =
      `Attempt 1 — resend the exact captured (nonce, proof):\n` +
      `  nonce=${nonceHex} proof=${proofHex}\n` +
      `  -> ${attempt1.ok ? "accepted (unexpected)" : `✗ REJECTED — ${attempt1.reason}`}\n` +
      `  (server.py pops each username's nonce on every /login attempt, success or not — this ` +
      `exact request can never be presented again.)\n\n` +
      `Attempt 2 — fetch a genuinely fresh nonce, but reuse the OLD captured proof:\n` +
      `  new nonce=${freshNonceHex}  (nonce check passes — it's the real current one)\n` +
      `  submitted proof=${proofHex}  (the only one the attacker has)\n` +
      `  expected proof=${attempt2.expectedProofHex}  (HMAC-SHA256(verifier, new nonce), recomputed)\n` +
      `  -> ${attempt2.ok ? "accepted (unexpected)" : `✗ REJECTED — ${attempt2.reason}`}\n` +
      `  (the proof is HMAC-bound to the nonce it was made for — a different nonce genuinely ` +
      `produces a different proof, not a different check on the same one.)`;
  }

  // ---- wiring: STATIC buttons already in the HTML, listeners only ----------
  document.querySelectorAll("#presets .preset-btn").forEach(btn => {
    btn.addEventListener("click", () => loadScenario(PRESETS[Number(btn.dataset.preset)]));
  });
  document.querySelectorAll("#modes .preset-btn").forEach(btn => {
    btn.addEventListener("click", () => setMode(btn.dataset.mode));
  });
  el.replayBtn.addEventListener("click", runReplay);

  document.querySelectorAll("#modes .preset-btn").forEach(btn => {
    btn.setAttribute("aria-pressed", btn.dataset.mode === MODE ? "true" : "false");
  });
  loadScenario(PRESETS[0]);
})();
