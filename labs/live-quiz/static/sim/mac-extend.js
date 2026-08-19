// Length-extension attack on a prefix-MAC, and why H(secret || H(data)) resists it.
//
// A toy Merkle-Damgard hash (NOT a real algorithm — real MD5/SHA-1 have the same
// exploitable shape, just a bigger state and a real compression function). What
// matters for the attack is structural, not the specific mixing math: the final
// digest IS the internal chaining value, so anyone holding a digest can resume
// hashing from it — with no need to have seen the bytes that produced it.

const BLOCK = 8; // bytes per compression step

function bytesOf(str) {
  return Array.from(new TextEncoder().encode(str));
}

function hex(n) {
  return (n >>> 0).toString(16).padStart(8, "0");
}

// One compression step: mix 8 message bytes into the running state.
function compress(state, block) {
  let s = state >>> 0;
  for (const b of block) {
    s = Math.imul(s ^ b, 0x01000193) >>> 0; // FNV-prime-ish mix
    s = ((s << 13) | (s >>> 19)) >>> 0;      // rotate, so byte order matters
  }
  return s >>> 0;
}

// Standard MD-style padding: 0x80, zeros, then the TOTAL message length in
// bits as a 4-byte big-endian tail, padded to a block boundary.
function pad(totalLenBytes) {
  const out = [0x80];
  while ((totalLenBytes + out.length) % BLOCK !== BLOCK - 4) out.push(0x00);
  const bits = totalLenBytes * 8;
  out.push((bits >>> 24) & 0xff, (bits >>> 16) & 0xff, (bits >>> 8) & 0xff, bits & 0xff);
  return out;
}

// Hash a full byte array from a fresh (or given) starting state.
function toyhash(bytes, initState = 0x6a09e667) {
  const padded = bytes.concat(pad(bytes.length));
  let state = initState;
  for (let i = 0; i < padded.length; i += BLOCK) {
    state = compress(state, padded.slice(i, i + BLOCK));
  }
  return state >>> 0;
}

// Attacker's move: given only a digest (= the internal state after the
// original message's own padding) and a length guess for what came before it,
// resume compression with the extension bytes, padded for the length the
// SERVER will see once it re-hashes secret+data+glue+extension.
function extendFromDigest(digest, knownPrefixLen, extensionBytes) {
  const glue = pad(knownPrefixLen);
  const totalLen = knownPrefixLen + glue.length + extensionBytes.length;
  const tail = extensionBytes.concat(pad(totalLen));
  let state = digest >>> 0;
  for (let i = 0; i < tail.length; i += BLOCK) {
    state = compress(state, tail.slice(i, i + BLOCK));
  }
  return { forgedDigest: state >>> 0, glue };
}

function glueToDisplay(glueBytes) {
  return glueBytes.map(b => "\\x" + b.toString(16).padStart(2, "0")).join("");
}

// --- Scenarios --------------------------------------------------------------
// Three different systems with the exact same underlying bug. Each secret is
// real to the simulation (so Verifier A/B can check the real server-side MAC)
// but is never shown or used by the attacker's own computation below — only
// its LENGTH is guessed, same as a real attacker would have to.
const PRESETS = [
  { label: "Admin cookie", data: "user=alice&admin=false", extension: "&admin=true" },
  { label: "File-share permission", data: "file=report.pdf&role=viewer", extension: "&role=editor" },
  { label: "Order total", data: "item=widget&qty=1&price=999", extension: "&price=1" },
];

let SECRET, DATA, dataBytes, macA, macB;

function loadScenario(preset) {
  SECRET = bytesOf("k3y_" + Math.random().toString(36).slice(2, 6)); // 8 bytes, hidden
  DATA = preset.data;
  dataBytes = bytesOf(DATA);
  macA = toyhash(SECRET.concat(dataBytes));                              // prefix-MAC: vulnerable
  macB = toyhash(SECRET.concat(bytesOf(hex(toyhash(dataBytes)))));       // H(secret||H(data)): resists

  document.getElementById("intercepted").textContent =
    `data = "${DATA}"\nmac  = ${hex(macA)}   (this is Verifier A's MAC — the one you're attacking)`;
  document.getElementById("extension").value = preset.extension;

  for (const el of document.querySelectorAll(".preset-btn")) {
    el.setAttribute("aria-pressed", el === document.activeElement ? "true" : el.getAttribute("aria-pressed"));
  }
  document.querySelectorAll(".preset-btn").forEach((el, i) => {
    el.setAttribute("aria-pressed", PRESETS[i] === preset ? "true" : "false");
  });
  ["work", "forged", "verdict-a", "verdict-b", "summary"].forEach(id => {
    const el = document.getElementById(id);
    el.textContent = "";
    if (el.classList.contains("verdict")) el.className = "verdict";
  });
  renderLen();
}

document.querySelectorAll(".preset-btn").forEach(btn => {
  btn.addEventListener("click", () => loadScenario(PRESETS[Number(btn.dataset.preset)]));
});

const lenSlider = document.getElementById("guess-len");
const lenVal = document.getElementById("guess-len-val");
function renderLen() {
  lenVal.textContent = `${lenSlider.value} bytes`;
  const correct = Number(lenSlider.value) === SECRET.length;
  document.getElementById("guess-hint").textContent = correct
    ? "This happens to be the real secret length — the forgery below will verify."
    : "Wrong guess means wrong padding, which means the server re-hashes something " +
      "different from what you computed — the forgery will fail Verifier A too.";
}
lenSlider.addEventListener("input", renderLen);

document.getElementById("forge-btn").addEventListener("click", () => {
  const guessLen = Number(lenSlider.value);
  const extensionText = document.getElementById("extension").value;
  const extensionBytes = bytesOf(extensionText);

  const { forgedDigest, glue } = extendFromDigest(macA, guessLen + dataBytes.length, extensionBytes);

  document.getElementById("work").textContent =
    `resume toyhash from digest ${hex(macA)}\n` +
    `(no secret bytes touched — only its guessed length: ${guessLen})\n` +
    `glue padding inserted by the hash construction: "${glueToDisplay(glue)}"\n` +
    `+ your bytes: "${extensionText}"\n` +
    `-> forged digest: ${hex(forgedDigest)}`;

  const forgedData = DATA + glueToDisplay(glue) + extensionText;
  document.getElementById("forged").textContent =
    `data = "${forgedData}"\nmac  = ${hex(forgedDigest)}`;

  // What the REAL server would compute for this forged data, secret length as guessed.
  const forgedBytesAsServerSeesIt = SECRET.concat(dataBytes, glue, extensionBytes);
  const realCheckA = toyhash(forgedBytesAsServerSeesIt);
  const verdictA = document.getElementById("verdict-a");
  if (realCheckA === forgedDigest) {
    verdictA.textContent = "✓ ACCEPTED — the forged message is valid for this MAC, and the " +
      "secret was never read.";
    verdictA.className = "verdict bad";
  } else {
    verdictA.textContent = "✗ rejected — length guess was wrong, so the padding (and therefore " +
      "the hash) the server computes doesn't match yours.";
    verdictA.className = "verdict ok";
  }

  // Verifier B: attacker would need macB = toyhash(secret || toyhash(forgedData)),
  // and extending macB the same way does NOT produce that — the outer hash's
  // state after processing secret is never exposed by macB alone.
  const wouldNeedInnerHash = toyhash(bytesOf(forgedData));
  const realCheckB = toyhash(SECRET.concat(bytesOf(hex(wouldNeedInnerHash))));
  // The attacker's only lever against Verifier B is the SAME extension trick applied to macB —
  // which extends the OUTER hash's state, not the inner H(data) it's actually keyed over.
  const bogusExtendB = extendFromDigest(macB, guessLen + 8, extensionBytes).forgedDigest;
  const verdictB = document.getElementById("verdict-b");
  if (bogusExtendB === realCheckB) {
    verdictB.textContent = "✓ accepted (this shouldn't happen — check the construction)";
    verdictB.className = "verdict bad";
  } else {
    verdictB.textContent = "✗ REJECTED — extending macB gets you the outer hash's next state, " +
      "not H(forged data). The server recomputes H(secret || H(forged data)) from scratch and " +
      "it doesn't match. Nesting the hash breaks the trick.";
    verdictB.className = "verdict ok";
  }

  document.getElementById("summary").textContent =
    "The vulnerability is structural, not about which hash you pick: any Merkle–Damgard " +
    "hash (MD5, SHA-1, SHA-256 — all of them) leaks its exact internal state as its output. " +
    "H(secret || data) lets that leaked state become the attacker's own starting point. " +
    "The fix nests the hash so the secret gates a step the attacker can never resume from " +
    "the outside — which is the same idea HMAC is built on, just with more structure.";
});

loadScenario(PRESETS[0]);
