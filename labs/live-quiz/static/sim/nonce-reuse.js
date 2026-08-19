// nonce-reuse.js — AES-GCM nonce reuse, and why "it round-trips" proves nothing.
//
// broken_hybrid_encrypt.py wraps a fresh AES-256 session key with RSA-OAEP (once,
// correctly), then encrypts every message in the session with AES-GCM under a
// MODULE-LEVEL CONSTANT nonce (_FIXED_GCM_NONCE = b"\x00" * 12). RSA/OAEP are never
// touched by this bug and never touched by this sim either — the whole break lives
// in one line, and it's a confidentiality break a PASSIVE eavesdropper gets for free.
//
// AES-GCM's confidentiality step is CTR mode: ciphertext = plaintext XOR keystream,
// where keystream = f(key, nonce, block counter) — never a function of the plaintext.
// Reuse (key, nonce) and the keystream repeats bit-for-bit, so for two messages in the
// same session: ciphertext1 XOR ciphertext2 = (msg1 XOR KS) XOR (msg2 XOR KS) = msg1 XOR msg2.
// No key needed. That's genuinely computed below with a toy keyed stream generator —
// NOT real AES (implementing AES's S-box/MixColumns + GHASH here would bury the lesson
// in machinery that isn't the point), but the exact structural property that makes the
// attack work: same (key, nonce) in -> bit-identical keystream out, plaintext-independent.
// crypto.subtle is deliberately not used, same reasoning as ecdsa-malleability.js: this
// page can be framed sandboxed (opaque origin) and the lab host may be plain HTTP, both
// of which make the real Web Crypto API unavailable.
//
// One honest simplification: real AESGCM.encrypt() returns ciphertext with a 16-byte
// auth tag appended. This sim's "ciphertext" is the body only, so the XOR below stays
// clean across the whole overlap. Your Part 3 proof script against the real file needs
// to slice that tag off (or only XOR up to the shorter plaintext's length) before this
// trick works on genuine AESGCM output — the panel above says so too.

const NONCE_BYTES = 12; // matches GCM_NONCE_BYTES in broken_hybrid_encrypt.py

function bytesOf(str) { return Array.from(new TextEncoder().encode(str)); }
function hexByte(b) { return b.toString(16).padStart(2, "0"); }
function hexOf(bytes) { return bytes.map(hexByte).join(""); }

function mix(state, b) {
  const s = Math.imul(state ^ b, 0x01000193) >>> 0; // FNV-prime-ish mix
  return ((s << 13) | (s >>> 19)) >>> 0;             // rotate, so position matters
}

// Toy keyed block: E(key, nonce, counter) -> 4 bytes. NOT real AES. What has to be
// true for the lesson: this depends ONLY on (key, nonce, counter) — never on the
// plaintext — exactly like AES-CTR/GCM's real keystream generator.
function toyBlock(keyBytes, nonceBytes, counter) {
  let s = 0x6a09e667;
  for (const b of keyBytes) s = mix(s, b);
  for (const b of nonceBytes) s = mix(s, b);
  s = mix(s, counter & 0xff);
  s = mix(s, (counter >>> 8) & 0xff);
  return [(s >>> 24) & 0xff, (s >>> 16) & 0xff, (s >>> 8) & 0xff, s & 0xff];
}

function keystream(keyBytes, nonceBytes, length) {
  const out = [];
  let counter = 0;
  while (out.length < length) {
    out.push(...toyBlock(keyBytes, nonceBytes, counter));
    counter++;
  }
  return out.slice(0, length);
}

function xorBytes(a, b) {
  const n = Math.min(a.length, b.length);
  const out = new Array(n);
  for (let i = 0; i < n; i++) out[i] = a[i] ^ b[i];
  return out;
}

// AES-GCM's confidentiality mechanism, structurally: ciphertext = plaintext XOR KS(key, nonce).
function encrypt(keyBytes, nonceBytes, ptBytes) {
  return xorBytes(ptBytes, keystream(keyBytes, nonceBytes, ptBytes.length));
}

function printable(byte) {
  return (byte >= 0x20 && byte < 0x7f) ? String.fromCharCode(byte) : "�";
}
function bytesToDisplay(bytes) { return bytes.map(printable).join(""); }

// --- Scenarios ---------------------------------------------------------------
// Three sessions, same underlying bug. Preset 0 is the lab file's own demo() pair.
const PRESETS = [
  {
    label: "Session chat",
    msg1: "Meet me at the usual place, 9pm.",
    msg2: "Bring the documents we discussed.",
    cribOffset: 0,
    crib: "Meet me at the ",
  },
  {
    label: "Wire transfer memo",
    msg1: "TRANSFER 500 USD TO ACCT-4471",
    msg2: "TRANSFER 50000 USD TO ACCT-9932",
    cribOffset: 0,
    crib: "TRANSFER ",
  },
  {
    label: "Password reset token",
    msg1: "RESET-TOKEN: 8f31c2 FOR alice@example.com",
    msg2: "RESET-TOKEN: 5590aa FOR admin@example.com",
    cribOffset: 0,
    crib: "RESET-TOKEN: ",
  },
];

let KEY, NONCE_FIXED, NONCE_B1, NONCE_B2;
let msg1Bytes, msg2Bytes, minLen;
let ctA1, ctA2, ctB1, ctB2;

function randBytes(n) {
  const out = new Array(n);
  for (let i = 0; i < n; i++) out[i] = Math.floor(Math.random() * 256);
  return out;
}

const cribOffsetSlider = document.getElementById("crib-offset");
const cribOffsetVal = document.getElementById("crib-offset-val");

function renderOffset() {
  cribOffsetVal.textContent = `byte ${cribOffsetSlider.value}`;
  document.getElementById("crib-offset-hint").textContent =
    `The two messages this session overlap for their first ${minLen} bytes — drag past ` +
    `that and there's nothing on the other side to XOR against.`;
}
cribOffsetSlider.addEventListener("input", renderOffset);

function loadScenario(preset) {
  KEY = randBytes(16); // fresh session key -- never shown, never used by the code below
  NONCE_FIXED = new Array(NONCE_BYTES).fill(0);            // _FIXED_GCM_NONCE, reused
  NONCE_B1 = new Array(NONCE_BYTES).fill(0); NONCE_B1[NONCE_BYTES - 1] = 1; // counter nonce, msg #1
  NONCE_B2 = new Array(NONCE_BYTES).fill(0); NONCE_B2[NONCE_BYTES - 1] = 2; // counter nonce, msg #2

  msg1Bytes = bytesOf(preset.msg1);
  msg2Bytes = bytesOf(preset.msg2);
  minLen = Math.min(msg1Bytes.length, msg2Bytes.length);

  ctA1 = encrypt(KEY, NONCE_FIXED, msg1Bytes);
  ctA2 = encrypt(KEY, NONCE_FIXED, msg2Bytes); // SAME nonce both times -- the bug

  ctB1 = encrypt(KEY, NONCE_B1, msg1Bytes);
  ctB2 = encrypt(KEY, NONCE_B2, msg2Bytes);    // different nonce each time -- the fix

  document.getElementById("intercepted").textContent =
    `nonce = ${hexOf(NONCE_FIXED)}  (same value, every message this session)\n` +
    `ct1   = ${hexOf(ctA1)}\n` +
    `ct2   = ${hexOf(ctA2)}`;

  document.getElementById("crib").value = preset.crib;
  cribOffsetSlider.max = String(Math.max(0, minLen - 1));
  cribOffsetSlider.value = String(preset.cribOffset);

  document.querySelectorAll(".preset-btn").forEach((el, i) => {
    el.setAttribute("aria-pressed", PRESETS[i] === preset ? "true" : "false");
  });
  ["work", "forged", "verdict-a", "verdict-b", "summary"].forEach(id => {
    const el = document.getElementById(id);
    el.textContent = "";
    if (el.classList.contains("verdict")) el.className = "verdict";
  });
  renderOffset();
}

document.querySelectorAll(".preset-btn").forEach(btn => {
  btn.addEventListener("click", () => loadScenario(PRESETS[Number(btn.dataset.preset)]));
});

document.getElementById("recover-btn").addEventListener("click", () => {
  const offset = Number(cribOffsetSlider.value);
  const cribText = document.getElementById("crib").value;
  const cribBytes = bytesOf(cribText);
  const usedLen = Math.max(0, Math.min(cribBytes.length, minLen - offset));

  const workEl = document.getElementById("work");
  const forgedEl = document.getElementById("forged");
  const verdictA = document.getElementById("verdict-a");
  const verdictB = document.getElementById("verdict-b");

  if (usedLen <= 0) {
    workEl.textContent = "Crib runs past the shorter message at this offset -- nothing left to XOR.";
    forgedEl.textContent = "";
    verdictA.textContent = ""; verdictA.className = "verdict";
    verdictB.textContent = ""; verdictB.className = "verdict";
    document.getElementById("summary").textContent = "";
    return;
  }

  const slice = arr => arr.slice(offset, offset + usedLen);
  const cribSlice = cribBytes.slice(0, usedLen);

  const diffA = xorBytes(slice(ctA1), slice(ctA2));
  const candA = xorBytes(diffA, cribSlice);

  const diffB = xorBytes(slice(ctB1), slice(ctB2));
  const candB = xorBytes(diffB, cribSlice);

  const realSlice = slice(msg2Bytes);
  const matchesA = candA.length === realSlice.length && candA.every((b, i) => b === realSlice[i]);
  const matchesB = candB.length === realSlice.length && candB.every((b, i) => b === realSlice[i]);

  const candADisplay = bytesToDisplay(candA);
  const candBDisplay = bytesToDisplay(candB);

  workEl.textContent =
    `broken_hybrid_encrypt.py: ciphertext1 XOR ciphertext2, bytes ${offset}..${offset + usedLen - 1}\n` +
    `  = ${hexOf(diffA)}\n` +
    `  XOR your crib "${cribText.slice(0, usedLen)}"\n` +
    `  -> candidate fragment of message 2: "${candADisplay}"\n\n` +
    `fixed_hybrid_encrypt.py: same computation, that session's ciphertexts\n` +
    `  -> candidate fragment: "${candBDisplay}"\n` +
    `(the session key is never read -- only public ciphertext bytes and your guessed crib)`;

  forgedEl.textContent =
    `broken_hybrid_encrypt.py recovered: "${candADisplay}"\n` +
    `fixed_hybrid_encrypt.py recovered:  "${candBDisplay}"\n` +
    `real message 2 at this offset:      "${bytesToDisplay(realSlice)}"`;

  if (matchesA) {
    verdictA.textContent = "recovered -- this fragment of message 2 is genuine plaintext, and the " +
      "session key was never touched.";
    verdictA.className = "verdict bad";
  } else {
    verdictA.textContent = "garbage -- wrong crib or offset, not because the reused nonce protected " +
      "anything. Try the real prefix at byte 0.";
    verdictA.className = "verdict ok";
  }

  if (matchesB) {
    verdictB.textContent = "recovered (this should not happen -- check the two nonce values above)";
    verdictB.className = "verdict bad";
  } else {
    verdictB.textContent = "garbage -- this session's two messages used different nonces, so " +
      "ciphertext1 XOR ciphertext2 is not message1 XOR message2 here. A correct crib buys you nothing.";
    verdictB.className = "verdict ok";
  }

  document.getElementById("summary").textContent =
    "The vulnerability is structural, not about which cipher you pick: any stream cipher or CTR-mode " +
    "block cipher (AES-GCM, AES-CTR, ChaCha20-Poly1305, even RC4/WEP) produces a keystream that depends " +
    "only on (key, nonce) -- reuse the pair and the keystream repeats, so ciphertext1 XOR ciphertext2 " +
    "collapses straight to message1 XOR message2, no key required. The fix never touches RSA-OAEP or the " +
    "AES-256 session key -- only how the nonce is chosen. And the discipline has to guarantee uniqueness, " +
    "not just look non-constant: a per-message counter (what fixed_hybrid_encrypt.py uses here) or a fresh " +
    "CSPRNG value both work; a nonce taken from wall-clock seconds does not -- two messages in the same " +
    "second would collide right back into this exact bug.";
});

loadScenario(PRESETS[0]);
