// server-can-read.js — Week 13 simulation (security-cryptography): TLS-only vs.
// hybrid E2EE, and the root-of-trust gap the lab explicitly does not close.
//
// WHAT THIS IS FOR
// The lab's whole lesson is one line in server.py: `print(f"SERVER SAW: {payload}")`
// runs byte-for-byte identically in both modes (vulnerable and fixed). What
// differs is only what alice.py hands it — the raw secret, or a hybrid-encrypted
// envelope. This page reproduces exactly that choice, live, then adds one toggle
// the two containers never demonstrate: what happens if the "server" also
// controls which public key Alice trusts (Worksheet Q2's root-of-trust problem).
//
// WHAT IS REAL AND WHAT IS MODELLED
//   real: RSA key generation (real prime search by trial division, real modular
//         exponentiation over BigInt), the RSA key-wrap (session_key^e mod n to
//         wrap, wrapped^d mod n to unwrap), and the authenticated-encryption tag
//         check — decrypt with any key other than the one actually used and the
//         recomputed tag genuinely fails to match, the same property AES-GCM
//         gives common.py's hybrid_encrypt/hybrid_decrypt. No branch below fakes
//         a pass/fail based on which button was clicked; every verdict comes
//         from calling the SAME decrypt function with whatever key that role
//         actually holds.
//   toy-sized: the RSA modulus here is ~48 bits (two 24-bit primes), not the
//         2048-bit modulus common.py uses — large enough that the math is
//         genuine RSA, small enough that keygen is instant and every
//         intermediate value fits on screen. The symmetric cipher is a keyed
//         keystream (seeded from BOTH the session key and the nonce, so two
//         messages never reuse a keystream even if a key ever repeated) plus a
//         keyed-hash tag: structurally AEAD-shaped (confidentiality +
//         integrity, real tag verification) but not literally AES-GCM — the
//         same "same shape, smaller numbers" trade this course's mac-extend.js
//         makes with its toy Merkle–Damgard hash. One difference from
//         common.py's envelope: real AESGCM.encrypt appends its tag onto `ct`,
//         so common.py's JSON only ever has three keys (enc_key/nonce/ct); this
//         toy cipher breaks the tag out as its own fourth field so the
//         authentication check is easy to point at on screen.
//   crypto.subtle is intentionally not used — same reasoning as
//         ecdsa-malleability.js: WebCrypto is only handed out on https/localhost,
//         and a lecture laptop on the room LAN over plain http is not a secure
//         context. Everything below is synchronous plain JS so it works either way.
//   no network, no storage: this page never calls fetch(). "The server" is a
//         string this function builds and displays, in the exact log-line format
//         server.py prints.

(function () {
  "use strict";

  // ---- byte/hex helpers ---------------------------------------------------
  function bytesOf(str) { return Array.from(new TextEncoder().encode(str)); }
  function strOf(bytes) { return new TextDecoder().decode(new Uint8Array(bytes)); }
  function hex8(n) { return (n >>> 0).toString(16).padStart(8, "0"); }
  function bytesToHex(bytes) { return bytes.map(b => b.toString(16).padStart(2, "0")).join(""); }
  function hexToBytes(hexStr) {
    const out = [];
    for (let i = 0; i < hexStr.length; i += 2) out.push(parseInt(hexStr.substr(i, 2), 16));
    return out;
  }
  function envelopeB64(envelope) { return btoa(JSON.stringify(envelope)); }

  // ---- toy RSA: real prime search + real modular exponentiation -----------
  function isProbablePrime(n) {
    if (n < 2n) return false;
    if (n % 2n === 0n) return n === 2n;
    if (n % 3n === 0n) return n === 3n;
    let i = 5n;
    while (i * i <= n) {
      if (n % i === 0n || n % (i + 2n) === 0n) return false;
      i += 6n;
    }
    return true;
  }

  function randPrimeBits(bits) {
    const lo = 1 << (bits - 1);          // force the top bit set
    const span = (1 << bits) - lo;       // range width so we stay within `bits` bits
    for (;;) {
      let cand = (lo + Math.floor(Math.random() * span)) | 1; // force odd
      const c = BigInt(cand >>> 0);
      if (isProbablePrime(c)) return c;
    }
  }

  function egcd(a, b) {
    let [old_r, r] = [a, b];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
      const q = old_r / r;
      [old_r, r] = [r, old_r - q * r];
      [old_s, s] = [s, old_s - q * s];
    }
    return [old_r, old_s]; // gcd, and Bezout coefficient for a
  }

  function modinv(a, m) {
    const [g, x] = egcd(((a % m) + m) % m, m);
    if (g !== 1n) return null;
    return ((x % m) + m) % m;
  }

  function modpow(base, exp, mod) {
    base = ((base % mod) + mod) % mod;
    let result = 1n;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % mod;
      exp >>= 1n;
      base = (base * base) % mod;
    }
    return result;
  }

  function generateRSA(bits) {
    const E_CANDIDATES = [65537n, 257n, 17n, 5n, 3n];
    for (;;) {
      const p = randPrimeBits(bits);
      const q = randPrimeBits(bits);
      if (p === q) continue;
      const n = p * q;
      const phi = (p - 1n) * (q - 1n);
      let e = null;
      for (const cand of E_CANDIDATES) {
        if (cand < phi && egcd(cand, phi)[0] === 1n) { e = cand; break; }
      }
      if (e === null) continue;
      const d = modinv(e, phi);
      if (d === null) continue;
      return { p, q, n, phi, e, d };
    }
  }

  // ---- toy AEAD: keyed keystream (confidentiality) + keyed tag (integrity) -
  // Structurally identical shape to mac-extend.js's `compress`, but seeded from
  // a secret key rather than a fixed IV -- that's what turns it into a keyed
  // MAC over the ciphertext, i.e. the "authenticated" half of AEAD.
  function keyedMix(seed, bytes) {
    let s = seed >>> 0;
    for (const b of bytes) {
      s = Math.imul(s ^ b, 0x01000193) >>> 0;
      s = ((s << 13) | (s >>> 19)) >>> 0;
    }
    return s >>> 0;
  }

  function keystreamBytes(seed, length) {
    let s = (seed ^ 0x9e3779b9) >>> 0;
    if (s === 0) s = 0xdeadbeef;
    const out = [];
    for (let i = 0; i < length; i++) {
      s ^= s << 13; s >>>= 0;
      s ^= s >>> 17;
      s = (s ^ (s << 5)) >>> 0;
      out.push(s & 0xff);
    }
    return out;
  }

  function seedFromKey(sessionKeyBig) {
    const M = 4294967291n; // largest prime below 2^32 -- any large modulus works here
    return Number(((sessionKeyBig % M) + M) % M) >>> 0;
  }

  // Bind BOTH the session key and the nonce into the working seed -- real
  // AES-GCM's keystream depends on both too. Without the nonce folded in here,
  // the nonce field in the envelope would be decorative (two messages under
  // the same session key would produce an identical keystream); this way it
  // does the job its own field name claims.
  function derivedSeed(sessionKeyBig, nonceStr) {
    return (seedFromKey(sessionKeyBig) ^ keyedMix(0x9e3779b9, bytesOf(nonceStr))) >>> 0;
  }

  function aeadEncrypt(sessionKeyBig, nonceStr, plaintextBytes) {
    const seed = derivedSeed(sessionKeyBig, nonceStr);
    const ks = keystreamBytes(seed, plaintextBytes.length);
    const ct = plaintextBytes.map((b, i) => b ^ ks[i]);
    const tag = hex8(keyedMix(seed, bytesOf(nonceStr).concat(ct)));
    return { ct, tag };
  }

  function aeadDecrypt(sessionKeyBig, nonceStr, ctBytes, tagHex) {
    const seed = derivedSeed(sessionKeyBig, nonceStr);
    const recomputed = hex8(keyedMix(seed, bytesOf(nonceStr).concat(ctBytes)));
    if (recomputed !== tagHex) return { ok: false, recomputedTag: recomputed };
    const ks = keystreamBytes(seed, ctBytes.length);
    const pt = ctBytes.map((b, i) => b ^ ks[i]);
    return { ok: true, plaintext: strOf(pt) };
  }

  // ---- hybrid encryption: mirrors common.py's hybrid_encrypt/hybrid_decrypt -
  function hybridEncrypt(pub, plaintextStr) {
    const plaintextBytes = bytesOf(plaintextStr);
    const nonce = Math.random().toString(36).slice(2, 10);
    let sessionKey;
    do {
      sessionKey = BigInt(Math.floor(Math.random() * 16777216)) + 1n;
    } while (sessionKey >= pub.n);
    const wrapped = modpow(sessionKey, pub.e, pub.n);
    const { ct, tag } = aeadEncrypt(sessionKey, nonce, plaintextBytes);
    const envelope = { enc_key: wrapped.toString(16), nonce, ct: bytesToHex(ct), tag };
    return { envelope, sessionKey, wrapped };
  }

  function hybridDecryptWithPriv(priv, envelope) {
    const wrapped = BigInt("0x" + envelope.enc_key);
    const sessionKey = modpow(wrapped, priv.d, priv.n);
    const ctBytes = hexToBytes(envelope.ct);
    const result = aeadDecrypt(sessionKey, envelope.nonce, ctBytes, envelope.tag);
    return Object.assign({ sessionKey }, result);
  }

  // A real attacker holding only the envelope plus the PUBLIC n and e (both
  // openly published) has no d and cannot invert modpow -- that is RSA's
  // trapdoor. The most a passive interceptor can try is treating the
  // intercepted wrapped integer as if it already WERE the session key -- a
  // real novice mistake, not a strawman -- and the tag check below genuinely
  // rejects it.
  function operatorNaiveAttempt(envelope) {
    const guessKey = BigInt("0x" + envelope.enc_key);
    const ctBytes = hexToBytes(envelope.ct);
    return aeadDecrypt(guessKey, envelope.nonce, ctBytes, envelope.tag);
  }

  // ---- scenarios ------------------------------------------------------------
  // Three messaging use cases, one shared bug: server.py logs exactly what
  // alice.py hands it. "Direct message" uses the lab's own SECRET_MESSAGE
  // constant verbatim, so it matches the SERVER SAW line students captured
  // themselves in Part 2a.
  const PRESETS = [
    { label: "Direct message", data: "meet at pier 39 at midnight" },
    { label: "Password reset code", data: "reset code 482913, valid 10 minutes" },
    { label: "Prescription refill", data: "refill request: sertraline 50mg, patient #4471" },
  ];

  const RSA_BITS = 24; // two ~24-bit primes -> ~48-bit n: instant keygen, real math

  let SECRET, BOB, ATTACKER;
  let MODE = "vulnerable";

  const el = {
    substituteCheck: document.getElementById("substitute-key"),
    substituteHint: document.getElementById("substitute-hint"),
    log: document.getElementById("server-log"),
    work: document.getElementById("work"),
    verdictOperator: document.getElementById("verdict-operator"),
    verdictBob: document.getElementById("verdict-bob"),
    summary: document.getElementById("summary"),
  };

  function loadScenario(preset) {
    SECRET = preset.data;
    BOB = generateRSA(RSA_BITS);
    ATTACKER = generateRSA(RSA_BITS);

    document.querySelectorAll("#presets .preset-btn").forEach((btn, i) => {
      btn.setAttribute("aria-pressed", PRESETS[i] === preset ? "true" : "false");
    });

    compute();
  }

  function setMode(mode) {
    MODE = mode;
    document.querySelectorAll("#modes .preset-btn").forEach(btn => {
      btn.setAttribute("aria-pressed", btn.dataset.mode === mode ? "true" : "false");
    });
    el.substituteCheck.disabled = (mode === "vulnerable");
    compute();
  }

  function compute() {
    // Vulnerable mode has no key exchange at all, so the substitution toggle
    // has nothing to act on regardless of its checked state -- MODE gates it,
    // not the checkbox alone.
    const substituteActive = MODE === "fixed" && el.substituteCheck.checked;
    el.substituteHint.textContent = MODE === "vulnerable"
      ? "No public key is ever exchanged in vulnerable mode, so this toggle has nothing to " +
        "substitute — it's disabled, and checking it (if you could) would change nothing below."
      : (substituteActive
          ? "Active: the /pubkey step below hands Alice the ATTACKER's public key instead of Bob's."
          : "Off: Alice fetches Bob's real public key, exactly as bob.py publishes it.");

    if (MODE === "vulnerable") {
      // Mirrors alice.py's vulnerable branch exactly: payload = SECRET_MESSAGE, no crypto.
      el.log.textContent = `alice sends the payload straight to POST /send:\n"${SECRET}"\n\n` +
        `SERVER SAW: ${SECRET}`;
      el.work.textContent = "(no crypto ran — vulnerable mode hands the server the raw string, " +
        "exactly like alice.py's `payload = SECRET_MESSAGE` branch. There is no key to compute.)";

      el.verdictOperator.textContent = `✓ readable — "${SECRET}"`;
      el.verdictOperator.className = "verdict bad";
      el.verdictBob.textContent =
        `✓ readable — "${SECRET}" (the exact same string the server already logged)`;
      el.verdictBob.className = "verdict ok";

      el.summary.textContent = "The server is a trusted third party by construction: whatever " +
        "Alice hands it, it can log, store, and hand to anyone who asks. TLS, if it were layered " +
        "on here, would only have protected this string on the wire between hops — it says " +
        "nothing about what happens once the server holds it in the clear.";
      return;
    }

    // Fixed mode: real hybrid encryption, toy-sized so every step is readable.
    const recipientPub = substituteActive ? ATTACKER : BOB;
    const { envelope, sessionKey, wrapped } = hybridEncrypt(recipientPub, SECRET);
    const b64 = envelopeB64(envelope);

    el.log.textContent =
      `alice fetches "bob's" public key from GET /pubkey (n=0x${recipientPub.n.toString(16)}` +
      `${substituteActive ? " — this is the ATTACKER's n, not bob's" : ""})\n` +
      `alice encrypts client-side and POSTs the envelope, never the plaintext\n\n` +
      `SERVER SAW: ${b64}`;

    el.work.textContent =
      `session key for this one message: 0x${sessionKey.toString(16)}\n` +
      `RSA key-wrap  session_key^e mod n = 0x${wrapped.toString(16)}\n` +
      `  (e = 0x${recipientPub.e.toString(16)}, n = 0x${recipientPub.n.toString(16)})\n` +
      `AES-style ciphertext: ${envelope.ct}\n` +
      `authentication tag:   ${envelope.tag}`;

    if (substituteActive) {
      // The "operator" here has swapped its own key in, so it holds the
      // matching private key for whatever Alice actually encrypted to.
      const opResult = hybridDecryptWithPriv(ATTACKER, envelope);
      if (opResult.ok) {
        el.verdictOperator.textContent =
          `✓ READABLE — the operator (who swapped in its own key at the pubkey step) ` +
          `recovers "${opResult.plaintext}" with its own real private key. This is exactly what ` +
          `a malicious server can do at step ①  — the root-of-trust gap.`;
        el.verdictOperator.className = "verdict bad";

        // The attacker relays a working copy on to bob so nothing looks
        // broken -- re-encrypted for real, to bob's REAL public key this time.
        // This is a SECOND, DIFFERENT envelope under a different session key --
        // shown explicitly below so "bob still decrypts fine" doesn't read as
        // "E2EE worked here." It didn't; it worked AGAIN, for a message the
        // operator had already read once in between.
        const relay = hybridEncrypt(BOB, opResult.plaintext);
        const bobResult = hybridDecryptWithPriv(BOB, relay.envelope);
        el.log.textContent += `\n\nSERVER SAW (re-wrapped by the operator before forwarding ` +
          `to bob): ${envelopeB64(relay.envelope)}`;
        el.work.textContent += `\n\nrelay session key (a DIFFERENT one bob unwraps — not the ` +
          `one alice originally sent): 0x${relay.sessionKey.toString(16)}`;
        el.verdictBob.textContent = bobResult.ok
          ? `✓ delivered — bob decrypts "${bobResult.plaintext}" with his own real key and ` +
            `sees nothing wrong. He has no way to tell this copy was re-encrypted by an impostor ` +
            `after being read in the clear in between.`
          : "unexpected: the relay envelope failed to verify (should not happen with matched keys)";
        el.verdictBob.className = "verdict ok";
      } else {
        el.verdictOperator.textContent = "unexpected: the attacker's own key failed to unwrap " +
          "its own envelope (should not happen)";
        el.verdictOperator.className = "verdict bad";
        el.verdictBob.textContent = "";
        el.verdictBob.className = "verdict";
      }
    } else {
      const opResult = operatorNaiveAttempt(envelope);
      el.verdictOperator.textContent = opResult.ok
        ? "unexpected: a naive guess actually verified (should not happen)"
        : `✗ REJECTED — the operator has no private key, only the public n and e. The most ` +
          `a passive interceptor can try is treating the intercepted wrapped integer as if it ` +
          `already were the session key; the recomputed tag (${opResult.recomputedTag}) doesn't ` +
          `match the real one (${envelope.tag}), so the authenticated cipher refuses to release ` +
          `anything.`;
      el.verdictOperator.className = "verdict ok";

      const bobResult = hybridDecryptWithPriv(BOB, envelope);
      el.verdictBob.textContent = bobResult.ok
        ? `✓ readable — bob's real private key unwraps the session key, the tag verifies, ` +
          `and he recovers "${bobResult.plaintext}"`
        : "unexpected: bob's own key failed to decrypt his own envelope (should not happen)";
      el.verdictBob.className = "verdict ok";
    }

    el.summary.textContent = substituteActive
      ? "Hybrid encryption alone didn't save this message — Alice encrypted to a key she never " +
        "verified belonged to Bob. The math is flawless on both sides; the failure is entirely in " +
        "trusting whichever key the server handed over. That's Worksheet Q2, and it's exactly why " +
        "Signal adds TOFU and safety numbers instead of trusting the server's word for it."
      : "The server stores and logs the exact same bytes it always does — only now those bytes " +
        "are an opaque envelope it structurally cannot open. No key that opens it ever touches " +
        "the server, which is the entire difference between this mode and the vulnerable one above.";
  }

  // ---- wiring: STATIC buttons already in the HTML, listeners only ----------
  document.querySelectorAll("#presets .preset-btn").forEach(btn => {
    btn.addEventListener("click", () => loadScenario(PRESETS[Number(btn.dataset.preset)]));
  });
  document.querySelectorAll("#modes .preset-btn").forEach(btn => {
    btn.addEventListener("click", () => setMode(btn.dataset.mode));
  });
  el.substituteCheck.addEventListener("change", compute);

  document.querySelectorAll("#modes .preset-btn").forEach(btn => {
    btn.setAttribute("aria-pressed", btn.dataset.mode === MODE ? "true" : "false");
  });
  loadScenario(PRESETS[0]);
})();
