// CBC padding-oracle attack, and why AES-GCM (an AEAD) gives it no signal to work with.
//
// A toy block cipher (NOT real AES — real AES has 14 rounds of SubBytes/ShiftRows/MixColumns;
// this has two rounds of substitute-then-reverse-then-substitute, just enough that no output byte
// depends only on the input byte at the same position). What matters for the attack is structural,
// not the specific mixing math: CBC decryption is P_i = D(C_i) XOR C_{i-1}, where D is the raw
// block-decrypt (no chaining). That holds for ANY block cipher, toy or real. If a server tells you
// whether the result has valid PKCS#7 padding, you can choose C_{i-1} yourself and read that one
// bit back — which is exactly the attack `exploit.py` runs against `vulnerable_app.py` on :8098.

const BLOCK = 16;

function bytesOf(str) {
  return Array.from(new TextEncoder().encode(str));
}

function randomBytes(n) {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return Array.from(out);
}

function xorBytes(a, b) {
  return a.map((v, i) => v ^ b[i]);
}

function chunkBytes(bytes, size) {
  const out = [];
  for (let i = 0; i < bytes.length; i += size) out.push(bytes.slice(i, i + size));
  return out;
}

function hex2(n) {
  return (n & 0xff).toString(16).padStart(2, "0");
}

function hex8(n) {
  return (n >>> 0).toString(16).padStart(8, "0");
}

function bytesToHex(bytes) {
  return bytes.map(hex2).join(" ");
}

function bytesToBase64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function toPrintable(bytes) {
  return bytes.map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : "\\x" + hex2(b)).join("");
}

// --- Toy block cipher (a stand-in for AES) ----------------------------------
// A fixed pseudorandom byte permutation, generated once (deterministic, not hand-typed) so it's
// guaranteed to be a genuine bijection — standing in for AES's S-box, same ROLE (nonlinear
// substitution), not the real Rijndael table.
function buildSbox(seed) {
  let s = seed >>> 0;
  const rnd = () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s; };
  const arr = Array.from({ length: 256 }, (_, i) => i);
  for (let i = 255; i > 0; i--) {
    const j = rnd() % (i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}
const SBOX = buildSbox(0x5a17e35);
const INV_SBOX = new Array(256);
SBOX.forEach((v, i) => { INV_SBOX[v] = i; });

const KEYROT = 7; // second round's key is the first round's key rotated by this many bytes

// Two rounds: substitute, reverse the 16 byte positions (self-inverse — real AES uses
// ShiftRows+MixColumns for the same "no byte stands alone" purpose), substitute again with a
// different round key. This is enough that D(C)[i] does NOT depend only on C[i], which is the
// property a skeptical reader would otherwise (correctly) object is doing real work for us.
function toyBlockEncrypt(P, key) {
  const s0 = P.map((b, i) => SBOX[b ^ key[i]]);
  const s1 = s0.slice().reverse();
  return s1.map((b, i) => SBOX[b ^ key[(i + KEYROT) % BLOCK]]);
}
function toyBlockDecrypt(C, key) {
  const u0 = C.map((b, i) => INV_SBOX[b] ^ key[(i + KEYROT) % BLOCK]);
  const u1 = u0.slice().reverse();
  return u1.map((b, i) => INV_SBOX[b] ^ key[i]);
}

// --- PKCS#7 --------------------------------------------------------------------
function pkcs7Pad(bytes) {
  const n = BLOCK - (bytes.length % BLOCK);
  return bytes.concat(Array(n).fill(n));
}
function pkcs7Valid(bytes) {
  if (!bytes.length || bytes.length % BLOCK !== 0) return false;
  const n = bytes[bytes.length - 1];
  if (n < 1 || n > BLOCK) return false;
  for (let i = bytes.length - n; i < bytes.length; i++) if (bytes[i] !== n) return false;
  return true;
}

// --- Oracle A: AES-CBC, unauthenticated (mirrors vulnerable_app.py) ------------
function cbcEncrypt(plainBytes, key) {
  const iv = randomBytes(BLOCK);
  const padded = pkcs7Pad(plainBytes);
  let prev = iv;
  const ctBlocks = [];
  for (let i = 0; i < padded.length; i += BLOCK) {
    const xored = xorBytes(padded.slice(i, i + BLOCK), prev);
    const c = toyBlockEncrypt(xored, key);
    ctBlocks.push(c);
    prev = c;
  }
  return { iv, ctBlocks };
}

// --- Oracle B: a toy AEAD, tag checked before anything else (mirrors fixed_app.py) --
// A keyed mix (real computation, not a lookup) standing in for the 128-bit GCM tag.
function toyTag(bytes, tagKey) {
  let acc = 0x811c9dc5 ^ ((tagKey[0] << 24) | (tagKey[1] << 16) | (tagKey[2] << 8) | tagKey[3]);
  for (const b of bytes) {
    acc = Math.imul(acc ^ b, 0x01000193) >>> 0;
    acc = ((acc << 13) | (acc >>> 19)) >>> 0;
  }
  for (let i = 4; i < tagKey.length; i++) acc = Math.imul(acc ^ tagKey[i], 0x01000193) >>> 0;
  return acc >>> 0;
}
function streamKeystreamBlock(nonce, blockIndex, key) {
  const counter = nonce.slice();
  counter[15] = counter[15] ^ blockIndex; // toy CTR: vary the last nonce byte per block
  return toyBlockEncrypt(counter, key);
}
function aeadEncrypt(plainBytes, key, tagKey) {
  const nonce = randomBytes(BLOCK);
  // Real AES-GCM needs no padding at all (stream mode) — padded here only so the block count
  // lines up 1:1 with Oracle A, for a fair side-by-side comparison.
  const padded = pkcs7Pad(plainBytes);
  const ctBlocks = [];
  for (let i = 0; i < padded.length; i += BLOCK) {
    ctBlocks.push(xorBytes(padded.slice(i, i + BLOCK), streamKeystreamBlock(nonce, i / BLOCK, key)));
  }
  const flatCt = [].concat(...ctBlocks);
  const tag = toyTag(nonce.concat(flatCt), tagKey); // ONE tag over the WHOLE message, like real GCM
  return { nonce, ctBlocks, tag };
}

// --- The attack itself: recover D(target) one byte at a time, then recover the plaintext -----
// One routine drives BOTH oracles below — the algorithm never knows or cares which one it's
// talking to, only what it gets back. That's the whole point: same attack, different outcome.
function recoverIntermediate(oracleFn) {
  const inter = new Array(BLOCK).fill(0);
  let queries = 0;
  for (let padVal = 1; padVal <= BLOCK; padVal++) {
    const pos = BLOCK - padVal;
    const forged = new Array(BLOCK).fill(0);
    for (let j = pos + 1; j < BLOCK; j++) forged[j] = inter[j] ^ padVal;
    let found = false;
    for (let guess = 0; guess < 256; guess++) {
      forged[pos] = guess;
      queries++;
      if (!oracleFn(forged.slice())) continue;
      if (padVal === 1) {
        // Classic false positive: P might genuinely end 0x01, or might end ...0x02 0x02 (or
        // longer) by accident. Perturb the neighbour byte and re-query to disambiguate.
        const probe = forged.slice();
        probe[pos - 1] ^= 0xff;
        queries++;
        if (!oracleFn(probe)) continue;
      }
      inter[pos] = guess ^ padVal;
      found = true;
      break;
    }
    if (!found) return { inter: null, queries, stoppedAtPos: pos };
  }
  return { inter, queries, stoppedAtPos: -1 };
}

function recoverPlaintext(oracleFnForIdx, prevBlocks, targetBlocks) {
  let recovered = [];
  let totalQueries = 0;
  const blockLog = [];
  for (let idx = 0; idx < targetBlocks.length; idx++) {
    const { inter, queries, stoppedAtPos } = recoverIntermediate(forged => oracleFnForIdx(idx, forged));
    totalQueries += queries;
    if (!inter) {
      blockLog.push(`block ${idx}: no usable signal (first byte tried, position ${stoppedAtPos}) — giving up`);
      return { recovered: null, totalQueries, blockLog };
    }
    const pblock = xorBytes(inter, prevBlocks[idx]);
    recovered.push(...pblock);
    blockLog.push(`block ${idx} recovered: "${toPrintable(pblock)}"`);
  }
  let stripped = recovered.slice();
  const n = recovered[recovered.length - 1];
  if (n >= 1 && n <= BLOCK) {
    const tail = recovered.slice(recovered.length - n);
    if (tail.every(b => b === n)) stripped = recovered.slice(0, recovered.length - n);
  }
  return { recovered: stripped, totalQueries, blockLog };
}

// --- Scenarios --------------------------------------------------------------
// Three different systems, same underlying bug. Each key is real to the simulation (both oracles
// really check against it) but is never read by the attack code below — only probed, byte by byte.
const PRESETS = [
  { label: "Session cookie", data: "sid=88f2c1;role=guest;exp=1800" },
  { label: "Password-reset link", data: "reset:uid=4471;token=90ee2c" },
  { label: "Payment authorization", data: "pay:acct=4410-2291;amt=250.00" },
];

let KEY_A, KEY_B, TAG_KEY_B, dataBytes;
let ivA, ctBlocksA, prevBlocksA;
let nonceB, ctBlocksB, prevBlocksB, expectedTagB;

function oracleFor(which, idx, forged) {
  if (which === "A") return pkcs7Valid(xorBytes(toyBlockDecrypt(ctBlocksA[idx], KEY_A), forged));
  return toyTag(forged.concat(ctBlocksB[idx]), TAG_KEY_B) === expectedTagB;
}

function loadScenario(preset) {
  KEY_A = randomBytes(BLOCK);
  KEY_B = randomBytes(BLOCK);
  TAG_KEY_B = randomBytes(BLOCK);
  dataBytes = bytesOf(preset.data);

  const encA = cbcEncrypt(dataBytes, KEY_A);
  ivA = encA.iv;
  ctBlocksA = encA.ctBlocks;
  prevBlocksA = [ivA, ...ctBlocksA.slice(0, -1)];

  const encB = aeadEncrypt(dataBytes, KEY_B, TAG_KEY_B);
  nonceB = encB.nonce;
  ctBlocksB = encB.ctBlocks;
  expectedTagB = encB.tag;
  prevBlocksB = [nonceB, ...ctBlocksB.slice(0, -1)];

  document.getElementById("intercepted").textContent =
    `Oracle A  GET /secret -> base64(IV||ct)\n  ${bytesToBase64(ivA.concat(...ctBlocksA))}\n` +
    `  ${ctBlocksA.length} ciphertext block(s), ${ctBlocksA.length * BLOCK} bytes\n\n` +
    `Oracle B  GET /secret -> base64(nonce||ct)  [tag verified separately, never shown]\n` +
    `  ${bytesToBase64(nonceB.concat(...ctBlocksB))}\n` +
    `  ${ctBlocksB.length} ciphertext block(s), ${ctBlocksB.length * BLOCK} bytes`;

  document.querySelectorAll(".preset-btn").forEach((el, i) => {
    el.setAttribute("aria-pressed", PRESETS[i] === preset ? "true" : "false");
  });

  ["work-a", "work-b", "recover-work-a", "recover-work-b", "summary"].forEach(id => {
    document.getElementById(id).textContent = "";
  });
  ["verdict-a", "verdict-b", "recover-verdict-a", "recover-verdict-b"].forEach(id => {
    const el = document.getElementById(id);
    el.textContent = "";
    el.className = "verdict";
  });

  renderGuess();
}

document.querySelectorAll(".preset-btn").forEach(btn => {
  btn.addEventListener("click", () => loadScenario(PRESETS[Number(btn.dataset.preset)]));
});

// --- Manual single-guess exploration -----------------------------------------
const guessSlider = document.getElementById("guess-byte");
const guessVal = document.getElementById("guess-byte-val");

function renderGuess() {
  const guess = Number(guessSlider.value);
  guessVal.textContent = `${guess}  (0x${hex2(guess)})`;

  const forged = new Array(BLOCK).fill(0);
  forged[15] = guess;

  // Oracle A
  const dA = toyBlockDecrypt(ctBlocksA[0], KEY_A);
  const pA = xorBytes(dA, forged);
  const validA = pkcs7Valid(pA);
  const n = pA[15];

  document.getElementById("work-a").textContent =
    `forged_prev = ${bytesToHex(forged)}\n` +
    `candidate P = D(C_t) XOR forged_prev  (only the server can compute D(C_t) — it holds the key)\n` +
    `P's last byte = 0x${hex2(n)}`;

  const verdictA = document.getElementById("verdict-a");
  if (validA && n === 1) {
    verdictA.textContent = `✓ 200 — valid padding (the clean case). D(C_t)[15] = ${guess} ⊕ 0x01 ` +
      `= 0x${hex2(guess ^ 1)} — one real byte of the server's internal state, key never touched.`;
    verdictA.className = "verdict bad";
  } else if (validA) {
    verdictA.textContent = `✓ 200 — valid padding, but this is the classic FALSE POSITIVE: P happens to ` +
      `end ...0x${hex2(n)} 0x${hex2(n)} by chance, not a real 0x01. The automated run below catches this by ` +
      `perturbing the neighbour byte before trusting a guess.`;
    verdictA.className = "verdict bad";
  } else {
    verdictA.textContent = `✗ 403 — invalid padding. This guess reveals nothing; try another.`;
    verdictA.className = "verdict ok";
  }

  // Oracle B — same forged_prev, tried against Oracle B's own real ciphertext block.
  // This demo's tag is computed over the WHOLE message (nonce||full ciphertext), like real GCM's
  // is — never per-block — so a 32-byte guess (forged_prev||one block) is hashing something
  // structurally different from what produced the real tag, on top of needing the exact bytes.
  const realMessageLen = BLOCK + ctBlocksB.length * BLOCK; // nonce + the FULL ciphertext
  const candidateTag = toyTag(forged.concat(ctBlocksB[0]), TAG_KEY_B);
  const validB = candidateTag === expectedTagB;

  document.getElementById("work-b").textContent =
    `no padding step exists in this construction — fixed_app.py checks the tag first, full stop:\n` +
    ` candidate tag = toyTag(forged_prev || C_t)       = 0x${hex8(candidateTag)}\n` +
    ` real tag      = toyTag(nonce || ${realMessageLen}-byte ciphertext) = 0x${hex8(expectedTagB)}\n` +
    ` ${validB ? "MATCH (this shouldn't happen)" : "MISMATCH — rejected"}`;

  const verdictB = document.getElementById("verdict-b");
  verdictB.textContent = validB
    ? `✓ 200 (this shouldn't happen — check the construction)`
    : `✗ 403 — uniform, for every failure. Stream mode means there was never a padding step to probe.`;
  verdictB.className = validB ? "verdict bad" : "verdict ok";
}
guessSlider.addEventListener("input", renderGuess);

// --- Automated full recovery --------------------------------------------------
document.getElementById("recover-btn").addEventListener("click", () => {
  const resA = recoverPlaintext((idx, forged) => oracleFor("A", idx, forged), prevBlocksA, ctBlocksA);
  const resB = recoverPlaintext((idx, forged) => oracleFor("B", idx, forged), prevBlocksB, ctBlocksB);

  const workA = document.getElementById("recover-work-a");
  const verdictA = document.getElementById("recover-verdict-a");
  if (resA.recovered) {
    const text = toPrintable(resA.recovered);
    workA.textContent = resA.blockLog.join("\n") + `\n\nfull plaintext = "${text}"`;
    const matches = text === preset_data_of_current();
    verdictA.textContent = `✓ FULLY RECOVERED in ${resA.totalQueries} oracle queries` +
      (matches ? " — matches this scenario's real secret exactly." : ".") +
      ` The AES key was never read, only guessed padding-oracle responses.`;
    verdictA.className = "verdict bad";
  } else {
    workA.textContent = resA.blockLog.join("\n");
    verdictA.textContent = `✗ stalled after ${resA.totalQueries} queries — no usable signal (shouldn't happen for Oracle A).`;
    verdictA.className = "verdict ok";
  }

  const workB = document.getElementById("recover-work-b");
  const verdictB = document.getElementById("recover-verdict-b");
  if (resB.recovered) {
    workB.textContent = resB.blockLog.join("\n") + `\n\nfull plaintext = "${toPrintable(resB.recovered)}"`;
    verdictB.textContent = `✓ leaked (this shouldn't happen — check the construction).`;
    verdictB.className = "verdict bad";
  } else {
    workB.textContent = resB.blockLog.join("\n");
    verdictB.textContent = `✗ NO SIGNAL — ${resB.totalQueries} queries, every single one rejected. ` +
      `Zero bytes recovered.`;
    verdictB.className = "verdict ok";
  }

  document.getElementById("summary").textContent =
    "The vulnerability is structural, not about which cipher you pick: any block cipher run in CBC " +
    "mode gives an attacker P = D(ciphertext) XOR previous-block, and a server that distinguishes " +
    "valid from invalid padding in its response lets the attacker choose that previous block and " +
    "read the distinction straight back — one real byte per ~256 queries, key never touched. " +
    "AES-GCM removes both ingredients at once: it's a stream mode, so there is no padding step to " +
    "probe in the first place, and its tag is verified before any plaintext logic runs at all — so " +
    "every failure, for any reason, looks identical from the outside.";
});

function preset_data_of_current() {
  const pressed = document.querySelector('.preset-btn[aria-pressed="true"]');
  const idx = pressed ? Number(pressed.dataset.preset) : 0;
  return PRESETS[idx].data;
}

loadScenario(PRESETS[0]);
