// CBC bit-flipping: unauthenticated AES-CBC is malleable, and AEAD (GCM) is not.
//
// A toy 16-byte block cipher (NOT real AES — real AES-256 has the same exploitable shape,
// just a bigger key schedule and a real S-box). What matters for the attack is structural,
// not the specific round math: CBC decrypts block i as P_i = D(C_i) XOR C_{i-1}, so XOR-ing a
// delta into C_{i-1} XORs that exact same delta into P_i — no key needed, because XOR is its
// own inverse and the decrypt function is never touched.
//
// Plaintext layout mirrors the real lab's vulnerable_app.py exactly:
//   Block 0 (bytes  0..15): "comment=FILLER!!"   <- expendable filler, the app never reads it
//   Block 1 (bytes 16..31): "<field>=<value>;<pad>"  <- 4-char field + "=" + 5-char value +
//                            ";" + 5-char pad = 16 bytes, value sits at block-1 offset 5..9
// Token bytes: IV (16) || C0 (16) || C1 (16), i.e. token[16:32] is C0, token[32:48] is C1.

const ROUNDS = 3; // toy cipher rounds — real AES-256 runs 14, same substitution-permutation shape

// Fixed diffusion permutation of the 16 byte positions inside a block: P(i) = 7*i + 3 (mod 16).
// gcd(7, 16) = 1, so this is a genuine bijection on 0..15 (every position moves, none collide).
const PERM = Array.from({ length: 16 }, (_, i) => (7 * i + 3) % 16);
const INV_PERM = new Array(16);
PERM.forEach((p, i) => { INV_PERM[p] = i; });

function bytesOf(str) {
  const out = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 0xff;
  return out;
}

function asciiOf(bytes) {
  let s = "";
  for (const b of bytes) s += (b >= 32 && b < 127) ? String.fromCharCode(b) : ".";
  return s;
}

function hexOf(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join(" ");
}

function hexTight(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function xorBlocks(a, b) {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
  return out;
}

function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

function bytesToBase64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// --- Toy keyed permutation cipher --------------------------------------------------------
// A keyed 256-entry S-box (a real bijection: every value 0..255 appears exactly once, so it
// has a genuine inverse) built by shuffling with a key-seeded xorshift PRNG.
function seedFromKey(keyBytes) {
  let s = 0x9e3779b9;
  for (const b of keyBytes) {
    s = Math.imul(s ^ b, 0x85ebca6b) >>> 0;
    s = ((s << 13) | (s >>> 19)) >>> 0;
  }
  return (s >>> 0) || 1;
}

function xorshift32(state) {
  let x = state >>> 0;
  x ^= x << 13; x >>>= 0;
  x ^= x >>> 17;
  x ^= x << 5; x >>>= 0;
  return x >>> 0;
}

function buildSbox(keyBytes) {
  let state = seedFromKey(keyBytes);
  const sbox = Array.from({ length: 256 }, (_, i) => i);
  for (let i = 255; i > 0; i--) {
    state = xorshift32(state);
    const j = state % (i + 1);
    const tmp = sbox[i]; sbox[i] = sbox[j]; sbox[j] = tmp;
  }
  const inv = new Array(256);
  for (let i = 0; i < 256; i++) inv[sbox[i]] = i;
  return { sbox, inv };
}

function expandRoundKey(keyBytes, roundIndex) {
  const rk = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    rk[i] = keyBytes[(i + roundIndex * 7) % keyBytes.length] ^ ((roundIndex * 0x9f + i * 0x2f) & 0xff);
  }
  return rk;
}

function encryptRound(block, rk, sbox) {
  const t = new Uint8Array(16);
  for (let i = 0; i < 16; i++) t[i] = sbox[block[i] ^ rk[i]];
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[PERM[i]] = t[i];
  return out;
}

function decryptRound(block, rk, inv) {
  const t = new Uint8Array(16);
  for (let i = 0; i < 16; i++) t[i] = block[PERM[i]];
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = inv[t[i]] ^ rk[i];
  return out;
}

function toyEncryptBlock(block, keyBytes, sboxObj) {
  let state = block;
  for (let r = 0; r < ROUNDS; r++) state = encryptRound(state, expandRoundKey(keyBytes, r), sboxObj.sbox);
  return state;
}

function toyDecryptBlock(block, keyBytes, sboxObj) {
  let state = block;
  for (let r = ROUNDS - 1; r >= 0; r--) state = decryptRound(state, expandRoundKey(keyBytes, r), sboxObj.inv);
  return state;
}

function cbcEncrypt(p0, p1, iv, keyBytes, sboxObj) {
  const c0 = toyEncryptBlock(xorBlocks(p0, iv), keyBytes, sboxObj);
  const c1 = toyEncryptBlock(xorBlocks(p1, c0), keyBytes, sboxObj);
  return { c0, c1 };
}

function cbcDecrypt(c0, c1, iv, keyBytes, sboxObj) {
  const p0 = xorBlocks(toyDecryptBlock(c0, keyBytes, sboxObj), iv);
  const p1 = xorBlocks(toyDecryptBlock(c1, keyBytes, sboxObj), c0);
  return { p0, p1 };
}

// A keyed tag over the whole token — a stand-in for ANY real integrity check bolted onto this
// scheme (encrypt-then-MAC, or AES-GCM's GHASH computed over its own CTR-mode ciphertext, which
// is a different cipher mode entirely, not CBC-plus-a-checksum). The tag math differs by
// construction; the property that matters here is the same across all of them: an attacker who
// edits ciphertext without the key cannot produce a new tag that matches, so the OLD tag (still
// attached) no longer verifies.
function toyTag(keyBytes, dataBytes) {
  let state = seedFromKey(keyBytes);
  for (const b of dataBytes) {
    state = Math.imul(state ^ b, 0x01000193) >>> 0;
    state = ((state << 13) | (state >>> 19)) >>> 0;
  }
  return state >>> 0;
}

function tagHex(n) {
  return (n >>> 0).toString(16).padStart(8, "0");
}

// --- Scenarios --------------------------------------------------------------
// Three systems, one bug: a fixed-format value sits at a known byte offset inside an
// unauthenticated CBC block. Preset 0 is the literal layout from vulnerable_app.py.
const PRESETS = [
  { label: "Session role cookie", fieldName: "role", benign: "guest", target: "admin" },
  { label: "Storage tier flag", fieldName: "tier", benign: "basic", target: "super" },
  { label: "Approval stage", fieldName: "step", benign: "draft", target: "final" },
];
const COMMENT_FILLER = "comment=FILLER!!"; // block 0 — the app never reads this, any scenario
const PAD = "xpad0";

function block1For(scenario, value) {
  const v = value.length === 5 ? value : (value + "     ").slice(0, 5);
  return scenario.fieldName + "=" + v + ";" + PAD;
}

let KEY, IV, sboxObj, C0, C1, ORIGINAL_TAG, SCENARIO;

function loadScenario(scenario) {
  SCENARIO = scenario;
  KEY = bytesOf("k" + Math.random().toString(36).slice(2, 10)); // fresh toy key, hidden from the attacker's own math below
  IV = bytesOf(Math.random().toString(36).slice(2, 10).padEnd(16, "0").slice(0, 16));
  sboxObj = buildSbox(KEY);

  const p0 = bytesOf(COMMENT_FILLER);
  const p1 = bytesOf(block1For(scenario, scenario.benign));
  const enc = cbcEncrypt(p0, p1, IV, KEY, sboxObj);
  C0 = enc.c0; C1 = enc.c1;
  ORIGINAL_TAG = toyTag(KEY, concatBytes(IV, C0, C1));

  const token = bytesToBase64(concatBytes(IV, C0, C1));
  document.getElementById("intercepted").textContent =
    `token = ${token}\n` +
    `  IV = ${hexOf(IV)}\n` +
    `  C0 = ${hexOf(C0)}   (block 0 ciphertext — flip THIS to edit block 1's plaintext)\n` +
    `  C1 = ${hexOf(C1)}   (block 1 ciphertext — holds the role field once decrypted)\n` +
    `tag = ${tagHex(ORIGINAL_TAG)}   (stands in for a real integrity check an AEAD version of ` +
    `this app would attach — GCM computes it differently, but no key means no valid new tag, either way)`;

  document.getElementById("target-value").value = scenario.target;

  document.querySelectorAll(".preset-btn").forEach((el, i) => {
    el.setAttribute("aria-pressed", PRESETS[i] === scenario ? "true" : "false");
  });
  ["work", "forged", "verdict-a", "verdict-b", "summary"].forEach(id => {
    const el = document.getElementById(id);
    el.textContent = "";
    if (el.classList.contains("verdict")) el.className = "verdict";
  });
  renderLengthHint();
  renderOffset();
}

document.querySelectorAll(".preset-btn").forEach(btn => {
  btn.addEventListener("click", () => loadScenario(PRESETS[Number(btn.dataset.preset)]));
});

const targetInput = document.getElementById("target-value");
function renderLengthHint() {
  const target = targetInput.value;
  const benign = SCENARIO.benign;
  const hint = document.getElementById("length-hint");
  if (target.length === benign.length) {
    hint.textContent = `Same length as "${benign}" (${benign.length} bytes) — a clean, ` +
      `length-preserving flip: every byte of "${benign}" gets replaced by the matching byte of "${target}".`;
  } else if (target.length < benign.length) {
    hint.textContent = `"${target}" is ${target.length} bytes but "${benign}" is ${benign.length} ` +
      `bytes — CBC only flips bytes it has a byte to flip FROM, so the last ` +
      `${benign.length - target.length} byte(s) of the field stay as their original "${benign}" characters.`;
  } else {
    hint.textContent = `"${target}" is ${target.length} bytes but "${benign}" is only ${benign.length} ` +
      `bytes — only the first ${benign.length} bytes of "${target}" can be used; there's no ciphertext ` +
      `byte to base the rest of the flip on.`;
  }
}
targetInput.addEventListener("input", renderLengthHint);

const offsetSlider = document.getElementById("offset");
const offsetVal = document.getElementById("offset-val");

// Single-byte label, used only for the compact "(zone: ...)" annotation in the work panel —
// a description of the START byte, not a prediction of the outcome (see spanEnd below for that).
function zoneOf(offset) {
  if (offset <= 3) return "the field name";
  if (offset === 4) return "the '=' separator";
  if (offset >= 5 && offset <= 9) return "the value";
  if (offset === 10) return "the ';' delimiter";
  return "trailing padding";
}

// The last byte a flip of length n starting at `offset` actually touches, clamped to the
// 16-byte block boundary the same way the real forge loop clamps it (bytes past index 15
// are simply never written).
function spanEnd(offset, n) {
  return Math.min(offset + n - 1, 15);
}

function renderOffset() {
  const offset = Number(offsetSlider.value);
  offsetVal.textContent = `byte ${offset}`;
  const n = Math.min(SCENARIO.benign.length, targetInput.value.length);
  const hint = document.getElementById("offset-hint");

  if (n < 1) {
    hint.textContent = "Type a target value above to see what this offset would actually flip.";
    return;
  }

  const end = spanEnd(offset, n);
  const span = end > offset ? `bytes ${offset}..${end}` : `byte ${offset}`;
  const fullyInValue = offset >= 5 && end <= 9;
  const fullyInPad = offset >= 11 && end <= 15;
  // Any byte in 0..4 (field name + "=") or exactly byte 10 (the ";") is a byte the app's
  // parser actually inspects — touching it, even alongside the real value bytes, corrupts
  // something checked. This is a span test, not a start-byte test: offset=6 with a 5-byte
  // flip starts inside the value but its LAST byte lands on the ';' at offset 10, so it
  // still corrupts a checked byte even though it "starts" in the right place.
  const touchesChecked = offset <= 4 || (offset <= 10 && end >= 10);

  if (fullyInValue) {
    hint.textContent = `Correct — ${span} sit entirely inside where "${SCENARIO.benign}" lives ` +
      `inside block 1.`;
  } else if (touchesChecked) {
    hint.textContent = `This flip covers ${span}, reaching into the field name, "=", or the ";" ` +
      `delimiter — the app's fixed-format parser will see a corrupted field and reject this ` +
      `token, even though the CBC math still "worked".`;
  } else if (fullyInPad) {
    hint.textContent = `${span[0].toUpperCase()}${span.slice(1)} land on trailing padding — nobody ` +
      `reads those bytes, so the field and value decrypt totally unchanged ("${SCENARIO.benign}" ` +
      `stays "${SCENARIO.benign}"). You corrupted ciphertext and nothing detected it — it just ` +
      `didn't land anywhere that mattered.`;
  } else {
    // Unreachable in practice (any span starting at offset<=9 that reaches the pad has
    // already crossed byte 10, caught above) — kept as a safe fallback, not a dead branch
    // we're asserting away.
    hint.textContent = `${span[0].toUpperCase()}${span.slice(1)} span more than one field — click ` +
      `"Compute" to see exactly what this does.`;
  }
}
offsetSlider.addEventListener("input", renderOffset);

document.getElementById("forge-btn").addEventListener("click", () => {
  const offset = Number(offsetSlider.value);
  const target = targetInput.value;
  const benignBytes = bytesOf(SCENARIO.benign);
  const targetBytes = bytesOf(target);
  const n = Math.min(benignBytes.length, targetBytes.length);

  const forgedC0 = new Uint8Array(C0);
  const deltas = [];
  for (let i = 0; i < n; i++) {
    const idx = offset + i;
    if (idx >= 0 && idx < 16) {
      const delta = benignBytes[i] ^ targetBytes[i];
      forgedC0[idx] ^= delta;
      deltas.push(delta);
    }
  }

  document.getElementById("work").textContent =
    `C0 (from the intercepted token): ${hexOf(C0)}\n` +
    `byte offset chosen: ${offset}  (zone: ${zoneOf(offset)})\n` +
    `"${SCENARIO.benign}" (benign) vs "${target}" (your target) -> XOR delta per byte: ` +
    `${deltas.map(d => d.toString(16).padStart(2, "0")).join(" ") || "(none — target is empty)"}\n` +
    `C0[${offset}..${offset + n - 1}] before: ${hexOf(C0.slice(offset, offset + n))}\n` +
    `C0[${offset}..${offset + n - 1}] after:  ${hexOf(forgedC0.slice(offset, offset + n))}\n` +
    `-> forged C0: ${hexOf(forgedC0)}`;

  const forgedToken = bytesToBase64(concatBytes(IV, forgedC0, C1));

  // What the REAL server decrypts (uses KEY, which the forging math above never touched).
  const { p0: forgedP0, p1: forgedP1 } = cbcDecrypt(forgedC0, C1, IV, KEY, sboxObj);

  document.getElementById("forged").textContent =
    `forged token = ${forgedToken}\n\n` +
    `the server decrypts this to:\n` +
    `  block 0 (never read by the app): ${asciiOf(forgedP0)}  (${hexTight(forgedP0)})\n` +
    `  block 1: "${asciiOf(forgedP1)}"`;

  // --- Verifier A: AES-CBC, no MAC — replays the app's own fixed-offset parser ---
  const prefix = bytesOf(SCENARIO.fieldName + "=");
  let wellFormed = true;
  for (let i = 0; i < prefix.length; i++) if (forgedP1[i] !== prefix[i]) wellFormed = false;
  if (forgedP1[10] !== 0x3b) wellFormed = false; // ';'
  const verdictA = document.getElementById("verdict-a");
  if (!wellFormed) {
    verdictA.textContent = "✗ malformed — the fixed-format parser can't even find the field/delimiter " +
      "in this block. Rejected, but NOT because tampering was detected — there's no check for that.";
    verdictA.className = "verdict ok";
  } else {
    const value = asciiOf(forgedP1.slice(5, 10));
    if (value === SCENARIO.target) {
      verdictA.textContent = `✓ ACCEPTED — the token still parses, and the value now reads ` +
        `"${value}". Access granted, and the key was never touched.`;
      verdictA.className = "verdict bad";
    } else {
      verdictA.textContent = `✗ rejected — parses fine (the format is intact) but the value reads ` +
        `"${value}", not "${SCENARIO.target}". CBC has no way to tell "garbled" from "legitimate" — ` +
        `this only failed because the value doesn't match, not because anything caught the tamper.`;
      verdictA.className = "verdict ok";
    }
  }

  // --- Verifier B: AES-GCM / AEAD — the tag is checked BEFORE the plaintext is ever read ---
  const unchanged = forgedC0.every((b, i) => b === C0[i]);
  const newTag = toyTag(KEY, concatBytes(IV, forgedC0, C1));
  const verdictB = document.getElementById("verdict-b");
  if (unchanged) {
    verdictB.textContent = "— no bytes were changed, so of course the original tag still matches. " +
      "Pick an offset/value that actually differs from the benign token to test the tag check.";
    verdictB.className = "verdict";
  } else if (newTag === ORIGINAL_TAG) {
    verdictB.textContent = "✓ accepted (this shouldn't happen — check the construction)";
    verdictB.className = "verdict bad";
  } else {
    verdictB.textContent = `✗ REJECTED — the auth tag over this ciphertext should be ${tagHex(newTag)}, ` +
      `but the token still carries the OLD tag ${tagHex(ORIGINAL_TAG)}. You can't recompute a matching ` +
      "tag without the key, so any edit — even one clean byte — gets caught before decryption even runs.";
    verdictB.className = "verdict ok";
  }

  document.getElementById("summary").textContent =
    "The vulnerability is structural, not about which cipher you pick: any unauthenticated block-" +
    "cipher mode (CBC, CTR, OFB — all of them) decrypts whatever ciphertext it's handed and trusts " +
    "the result. Encryption alone answers \"can you read this?\", never \"did this change?\" (CWE-353 / " +
    "CWE-649). AEAD closes the gap by adding a tag the attacker can't forge without the key — the same " +
    "idea as HMAC, just protecting ciphertext instead of a plain message.";
});

loadScenario(PRESETS[0]);
