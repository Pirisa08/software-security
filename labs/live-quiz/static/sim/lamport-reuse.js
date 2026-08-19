/* lamport-reuse.js — Week 15 simulation (security-cryptography, PQC).
 *
 * WHAT THIS IS FOR
 * vulnerable_app.py generates ONE Lamport one-time keypair at startup and
 * reuses it on every /sign call. A Lamport signature over an N-bit message
 * reveals exactly one of the two secret preimages per bit position — the one
 * selected by that bit's value — so ONE signature only ever gives away half
 * the key. But sign the message's bitwise complement too and every bit
 * differs, so together the two signatures reveal BOTH preimages at EVERY
 * position: the entire private key, recovered with zero brute force. This
 * page runs exactly that attack against a real (if toy-sized) Lamport
 * instance, live, and then runs the identical attack against a SECOND
 * instance that enforces one-time use — fixed_app.py's actual fix — so the
 * two verdicts below are two different real computations, not one narrated
 * result and one assumed one.
 *
 * WHAT IS REAL
 * Every preimage is 32 genuinely random bytes (crypto.getRandomValues, with a
 * Math.random fallback — see randomBytes below). Every hash is a real
 * SHA-256, implemented in this file byte-identical to Python's
 * hashlib.sha256 (same construction and the same verification method as
 * jwt-forge.js / ecdsa-malleability.js in this same directory: checked
 * against a reference implementation, not stubbed out). sign(), verify() and
 * the bit ordering below match vulnerable_app.py / fixed_app.py / exploit.py
 * line for line: sign(message) reveals sk[i][bit_i] for i = 0..31,
 * most-significant-bit first; verify(message, sig) checks
 * SHA256(sig[i]) == pk[i][bit_i] for every i; Verifier B refuses any SECOND
 * /sign, exactly as fixed_app.py's one-time guard does. Nothing branches on
 * which preset or button was clicked — every ACCEPTED/REJECTED verdict below
 * is the actual result of running verify() against the actual recovered (or
 * incomplete) key.
 *
 * crypto.subtle is avoided on purpose: it needs a secure context, and a
 * lecture laptop served over plain http on the room LAN is not one.
 *
 * N = 32 here, same as vulnerable_app.py's N (it signs the message directly,
 * no pre-hash, so every message bit is attacker-controllable — the whole
 * reason the key-reuse forgery is clean and demonstrable).
 */
(function () {
  "use strict";

  var N = 32;

  /* ---- SHA-256 in plain JS (same construction as jwt-forge.js / ecdsa-malleability.js) ---- */
  var K256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  function sha256Bytes(bytes) {
    var len = bytes.length;
    var total = ((len + 9 + 63) >> 6) << 6;
    var m = new Uint8Array(total);
    m.set(bytes);
    m[len] = 0x80;
    var hi = Math.floor(len / 536870912);      // high 32 bits of len*8
    var lo = (len * 8) >>> 0;
    m[total - 8] = (hi >>> 24) & 255; m[total - 7] = (hi >>> 16) & 255;
    m[total - 6] = (hi >>> 8) & 255;  m[total - 5] = hi & 255;
    m[total - 4] = (lo >>> 24) & 255; m[total - 3] = (lo >>> 16) & 255;
    m[total - 2] = (lo >>> 8) & 255;  m[total - 1] = lo & 255;

    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var w = new Array(64), i, t, a, b, c, d, e, f, g, h, s0, s1, ch, maj, t1, t2;

    for (t = 0; t < total; t += 64) {
      for (i = 0; i < 16; i++) {
        w[i] = (m[t + i * 4] << 24) | (m[t + i * 4 + 1] << 16)
             | (m[t + i * 4 + 2] << 8) | m[t + i * 4 + 3];
      }
      for (i = 16; i < 64; i++) {
        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      a = H[0]; b = H[1]; c = H[2]; d = H[3];
      e = H[4]; f = H[5]; g = H[6]; h = H[7];
      for (i = 0; i < 64; i++) {
        s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        ch = (e & f) ^ (~e & g);
        t1 = (h + s1 + ch + K256[i] + w[i]) | 0;
        s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = (s0 + maj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0;
        d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0;
      H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0;
      H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    var out = new Uint8Array(32);
    for (i = 0; i < 8; i++) {
      out[i * 4] = (H[i] >>> 24) & 255; out[i * 4 + 1] = (H[i] >>> 16) & 255;
      out[i * 4 + 2] = (H[i] >>> 8) & 255; out[i * 4 + 3] = H[i] & 255;
    }
    return out;
  }

  function bytesToHex(bytes) {
    var out = "", i, h;
    for (i = 0; i < bytes.length; i++) {
      h = bytes[i].toString(16);
      out += h.length < 2 ? "0" + h : h;
    }
    return out;
  }

  function hex32(n) { return (n >>> 0).toString(16).padStart(8, "0"); }

  function randomBytes(n) {
    var a = new Uint8Array(n);
    if (typeof crypto !== "undefined" && crypto && crypto.getRandomValues) {
      crypto.getRandomValues(a);
    } else {
      for (var i = 0; i < n; i++) a[i] = Math.floor(Math.random() * 256);
    }
    return a;
  }

  /* Most-significant-bit-first, matching vulnerable_app.py's int_to_bits exactly. */
  function intToBits(value, n) {
    var bits = [];
    for (var i = 0; i < n; i++) bits.push((value >>> (n - 1 - i)) & 1);
    return bits;
  }

  /* ---- Lamport primitives (match sign()/verify() in both Flask apps) ---- */
  function genKeypair() {
    var sk = [], pk = [], i, a, b;
    for (i = 0; i < N; i++) {
      a = randomBytes(32); b = randomBytes(32);
      sk.push([a, b]);
      pk.push([sha256Bytes(a), sha256Bytes(b)]);
    }
    return { sk: sk, pk: pk };
  }

  function signWith(sk, message) {
    var bits = intToBits(message, N), sig = [];
    for (var i = 0; i < N; i++) sig.push(sk[i][bits[i]]);
    return sig;
  }

  /* Checks every position (no early exit), so a caller can report exactly
   * which and how many bits failed — the same shape as exploit.py's
   * "mismatches" count against the fixed app. */
  function verifyDetailed(pk, message, sig) {
    var bits = intToBits(message, N), mismatches = [], i;
    for (i = 0; i < N; i++) {
      if (bytesToHex(sha256Bytes(sig[i])) !== bytesToHex(pk[i][bits[i]])) mismatches.push(i);
    }
    return { ok: mismatches.length === 0, mismatches: mismatches };
  }

  /* ---- scenarios: same mechanic, different privileged action ----------- */
  var PRESETS = [
    { label: "Admin access", targetLabel: "grant_admin", target: 0xA5A5C3C3,
      note: "This target is literally vulnerable_app.py's ADMIN_MESSAGE (0xA5A5C3C3) — the exact " +
            "value the lab's /admin endpoint checks a signature against." },
    { label: "File-share control", targetLabel: "full_control (read+write+delete+share)",
      target: 0xC3C3A5A5,
      note: "Same reused key, same SHA-256, a different privileged action guarded the same way — " +
            "the bits don't know or care what they mean." },
    { label: "Payment approval", targetLabel: "approve_unlimited_transfer", target: 0x5A5A3C3C,
      note: "A payments API built on the identical one-time-signature scheme has the identical hole." }
  ];

  var M = 0x00000000, NOT_M = 0xFFFFFFFF;
  var state = {};

  /* ---- DOM helpers ------------------------------------------------------ */
  var el = {};
  ["presets", "scenario-note", "target", "sign-m-btn", "sign-notm-btn", "forge-btn",
   "run-all-btn", "action-status", "grid", "cell-detail", "verdict-a", "verdict-b", "summary"
  ].forEach(function (id) { el[id] = document.getElementById(id); });

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function txt(tag, cls, s) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (s !== undefined) n.textContent = s;
    return n;
  }

  /* ---- scenario setup ---------------------------------------------------- */
  function loadScenario(preset) {
    state.preset = preset;
    state.A = genKeypair();          // vulnerable_app.py's keypair — reused
    state.B = genKeypair();          // fixed_app.py's keypair — independent, one-time
    state.sigA_M = null; state.sigA_notM = null;
    state.sigB_M = null;             // Verifier B's 2nd /sign never succeeds, so no sigB_notM
    state.selected = null;

    el.target.textContent =
      "target_message = 0x" + hex32(preset.target) + "   (\"" + preset.targetLabel + "\")\n" +
      "POST /sign {\"message_hex\":\"" + preset.target.toString(16).padStart(8, "0") + "\"} " +
      "-> 403 \"refusing to sign the reserved message\"  (both servers enforce this baseline —\n" +
      "without it the flag would be a one-line curl and the lesson would be moot)";

    el["scenario-note"].textContent = preset.note;

    el["sign-m-btn"].disabled = false;
    el["sign-notm-btn"].disabled = true;
    el["forge-btn"].disabled = true;
    el["action-status"].textContent = "Nothing requested yet.";
    el["cell-detail"].textContent = "Click a bit position after step ① to see the real SHA-256 check.";

    ["verdict-a", "verdict-b"].forEach(function (id) {
      el[id].textContent = ""; el[id].className = "verdict";
    });
    el.summary.textContent = "";

    document.querySelectorAll(".preset-btn").forEach(function (btn) {
      var mine = PRESETS[Number(btn.dataset.preset)] === preset;
      btn.setAttribute("aria-pressed", mine ? "true" : "false");
    });

    renderGrid();
  }

  /* ---- the bit-recovery grid --------------------------------------------- */
  function renderGrid() {
    clear(el.grid);
    var bitsTarget = intToBits(state.preset.target, N);
    var phase = state.sigA_notM ? "full" : (state.sigA_M ? "half" : "unknown");
    for (var i = 0; i < N; i++) {
      var need = bitsTarget[i];
      var cell = document.createElement("button");
      cell.type = "button";
      cell.className = "lamport-cell is-" + phase + (need === 1 ? " is-b-needed" : "")
        + (state.selected === i ? " is-selected" : "");
      cell.setAttribute("aria-label",
        "bit " + i + ", target needs " + need + ", " +
        (phase === "unknown" ? "nothing known yet"
          : phase === "half" ? "only the bit=0 preimage known"
          : "both preimages known"));
      cell.appendChild(txt("span", "lamport-idx", "i=" + i));
      cell.appendChild(txt("span", "lamport-glyph",
        phase === "unknown" ? "? ?" : phase === "half" ? "0 ·" : "0 1"));
      (function (idx) { cell.addEventListener("click", function () { selectCell(idx); }); })(i);
      el.grid.appendChild(cell);
    }
  }

  function selectCell(i) {
    state.selected = i;
    renderGrid();

    var target = state.preset.target;
    var need = intToBits(target, N)[i];
    var lines = [];
    lines.push("Verifier A's keypair (:8100) — bit i=" + i + ". Target needs bit=" + need + ".");
    lines.push("");

    if (state.sigA_M) {
      var pre0 = state.sigA_M[i];
      var h0 = bytesToHex(sha256Bytes(pre0));
      var pk0 = bytesToHex(state.A.pk[i][0]);
      var pk1 = bytesToHex(state.A.pk[i][1]);
      lines.push("from POST /sign M=0x00000000:");
      lines.push("  sk[" + i + "][0] = " + bytesToHex(pre0));
      lines.push("  SHA256(sk[" + i + "][0]) = " + h0);
      lines.push("    == pk[" + i + "][0]?  " + (h0 === pk0 ? "YES ✓" : "NO ✗ (bug!)"));
      lines.push("    == pk[" + i + "][1]?  " + (h0 === pk1 ? "YES (bug!)" : "NO ✗") +
        "  — the OTHER preimage stays secret from this signature alone");
    } else {
      lines.push("sk[" + i + "][0] not requested yet — click step ①.");
    }

    lines.push("");
    if (state.sigA_notM) {
      var pre1 = state.sigA_notM[i];
      var h1 = bytesToHex(sha256Bytes(pre1));
      var pkb1 = bytesToHex(state.A.pk[i][1]);
      lines.push("from POST /sign ~M=0xFFFFFFFF (Verifier A only — key reused, so this succeeded):");
      lines.push("  sk[" + i + "][1] = " + bytesToHex(pre1));
      lines.push("  SHA256(sk[" + i + "][1]) = " + h1);
      lines.push("    == pk[" + i + "][1]?  " + (h1 === pkb1 ? "YES ✓" : "NO ✗ (bug!)") +
        "  — BOTH preimages at this position are now known");
    } else {
      lines.push("sk[" + i + "][1] not known yet. Verifier A would happily sign it (key reused) — " +
        "click step ②. Verifier B would refuse it outright.");
    }
    el["cell-detail"].textContent = lines.join("\n");
  }

  /* ---- the three attack steps -------------------------------------------- */
  function doSignM() {
    if (state.sigA_M) return;
    state.sigA_M = signWith(state.A.sk, M);
    state.sigB_M = signWith(state.B.sk, M);
    el["sign-m-btn"].disabled = true;
    el["sign-notm-btn"].disabled = false;
    el["action-status"].textContent =
      "① Verifier A: 200 OK. Verifier B: 200 OK — both reveal sk[i][0] for all 32 positions " +
      "(the message is all-zero bits, so bit_i = 0 everywhere).";
    if (state.selected !== null) selectCell(state.selected); else renderGrid();
  }

  function doSignNotM() {
    if (!state.sigA_M || state.sigA_notM) return;
    state.sigA_notM = signWith(state.A.sk, NOT_M);
    // Verifier B refuses: fixed_app.py's one-time guard. No sigB_notM is ever set.
    el["sign-notm-btn"].disabled = true;
    el["forge-btn"].disabled = false;
    el["action-status"].textContent =
      "② Verifier A (key reused): 200 OK — sk[i][1] revealed too; the full key is now known. " +
      "Verifier B (one-time enforced): 403 \"one-time key already used\" — refused, even though this " +
      "is a different message from the first. The rule is one signature, period — not one distinct " +
      "message: a repeat of 0x00000000 would get the identical 403.";
    if (state.selected !== null) selectCell(state.selected); else renderGrid();
  }

  function doForge() {
    if (!state.sigA_M || !state.sigA_notM) return;
    var target = state.preset.target;
    var bitsTarget = intToBits(target, N);
    var bitsM = intToBits(M, N), bitsNotM = intToBits(NOT_M, N);

    /* Reconstruct Verifier A's private key from the two collected signatures,
     * then self-check every recovered preimage against the PUBLISHED pk —
     * the same assertion loop exploit.py runs before it trusts the recovery. */
    var skA = [], selfCheckFails = 0, i;
    for (i = 0; i < N; i++) skA.push([null, null]);
    for (i = 0; i < N; i++) skA[i][bitsM[i]] = state.sigA_M[i];
    for (i = 0; i < N; i++) skA[i][bitsNotM[i]] = state.sigA_notM[i];
    for (i = 0; i < N; i++) {
      if (bytesToHex(sha256Bytes(skA[i][0])) !== bytesToHex(state.A.pk[i][0])) selfCheckFails++;
      if (bytesToHex(sha256Bytes(skA[i][1])) !== bytesToHex(state.A.pk[i][1])) selfCheckFails++;
    }

    var forgedA = [];
    for (i = 0; i < N; i++) forgedA.push(skA[i][bitsTarget[i]]);
    var resA = verifyDetailed(state.A.pk, target, forgedA);

    // Verifier B: the attacker only ever held sk[i][0] (from the one signature
    // that succeeded), so the best possible forgery reuses that signature
    // as-is at every position — exactly exploit.py's "bogus" construction.
    var forgedB = state.sigB_M;
    var resB = verifyDetailed(state.B.pk, target, forgedB);

    var vA = el["verdict-a"];
    if (selfCheckFails > 0) {
      vA.className = "verdict ok";
      vA.textContent = "self-check failed at " + selfCheckFails + " preimage(s) before forging — " +
        "the recovered key did not match the published pk, so no forgery was attempted. (This should " +
        "never happen; it would indicate a bug in this page, not in the lab.)";
    } else if (resA.ok) {
      vA.className = "verdict bad";
      vA.textContent = "✓ ACCEPTED — self-check passed (recovered key matched pk at all 32 " +
        "positions), and the forged signature on \"" + state.preset.targetLabel + "\" verifies. The " +
        "server never signed this message for you — it never had to.";
    } else {
      vA.className = "verdict ok";
      vA.textContent = "✗ rejected — the forged signature failed verification at " +
        resA.mismatches.length + " position(s), first at i=" + resA.mismatches[0] + ". With both " +
        "signatures genuinely collected this should not happen; check the two collection steps ran.";
    }

    var vB = el["verdict-b"];
    if (resB.ok) {
      vB.className = "verdict bad";
      vB.textContent = "unexpected: this forgery verified with only one signature collected — " +
        "re-check the target message's bit pattern for this preset.";
    } else {
      vB.className = "verdict ok";
      vB.textContent = "✗ REJECTED — the best forgery possible from ONE signature fails at " +
        resB.mismatches.length + " of 32 bit positions (first at i=" + resB.mismatches[0] + "): " +
        "wherever \"" + state.preset.targetLabel + "\" needs bit=1, you only ever held the bit=0 " +
        "preimage, because the 2nd /sign was refused. One-time enforcement is the entire fix — no " +
        "new cryptography.";
    }

    el.summary.textContent = "The vulnerability is operational, not mathematical: Lamport's security " +
      "proof assumes exactly one signature per key. Reuse it once and hash preimage-resistance can't " +
      "save you — the SECOND signature is what hands over the rest of the key. CWE-323 (reusing a " +
      "key pair), not a broken hash.";
  }

  function runAll() {
    doSignM();
    doSignNotM();
    doForge();
  }

  /* ---- wiring ------------------------------------------------------------ */
  document.querySelectorAll(".preset-btn").forEach(function (btn) {
    btn.addEventListener("click", function () { loadScenario(PRESETS[Number(btn.dataset.preset)]); });
  });

  el["sign-m-btn"].addEventListener("click", doSignM);
  el["sign-notm-btn"].addEventListener("click", doSignNotM);
  el["forge-btn"].addEventListener("click", doForge);
  el["run-all-btn"].addEventListener("click", runAll);

  loadScenario(PRESETS[0]);
})();
