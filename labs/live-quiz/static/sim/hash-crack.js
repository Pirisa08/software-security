// Dictionary attack on an unsalted MD5 password store, and why a per-user salt +
// an iterated KDF change the price of the same attack instead of just hiding it.
//
// The MD5 here is a REAL, standards-conformant MD5 (RFC 1321) — not a toy. It is
// byte-identical to Python's hashlib.md5: md5hex("sunshine2021") below produces
// f364b087df0401706d6b1c8f68a50bf7, the exact "admin" row this week's
// users_vulnerable.csv ships. The salted store's KDF is NOT bcrypt (bcrypt is a
// Blowfish-keyed construction with its own internal state machine, out of scope
// for a browser demo) — it is a small, real, iterated-hashing construction with
// the two properties that matter for this week: a per-user random salt mixed in
// before hashing, and a tunable number of real hash operations per guess. Both
// stores are hashed for real, live, for whatever preset is selected.

const WORDLIST = [
  "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
  "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
  "monkey", "letmein", "shadow", "master", "666666", "qwertyuiop", "123321",
  "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx",
  "7777777", "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1",
  "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer",
  "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000",
  "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars",
  "klaster", "112233", "george", "computer", "michelle", "jessica", "pepper",
  "1111", "zxcvbn", "555555", "11111111", "131313", "freedom", "777777",
  "pass", "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua",
  "cheese", "amanda", "summer", "love", "ashley", "nicole", "chelsea",
  "biteme", "matthew", "access", "yankees", "987654321", "dallas", "austin",
  "thunder", "taylor", "matrix", "mobilemail", "sunshine2021", "welcome",
  "admin", "flower", "banana", "hello123", "loveme",
];

// --- Real MD5 (RFC 1321) ------------------------------------------------------
// K[i] = floor(abs(sin(i+1)) * 2**32) — the spec defines the constants this way,
// so generating them from sin() *is* implementing the spec, not a shortcut.
const MD5_K = [];
for (let i = 0; i < 64; i++) MD5_K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;
const MD5_S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

function rotl32(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }

function md5Bytes(bytes) {
  const len = bytes.length;
  const msg = bytes.slice();
  msg.push(0x80);
  while (msg.length % 64 !== 56) msg.push(0);
  const bitLen = BigInt(len) * 8n;
  for (let i = 0; i < 8; i++) msg.push(Number((bitLen >> BigInt(8 * i)) & 0xffn));

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let off = 0; off < msg.length; off += 64) {
    const M = new Array(16);
    for (let j = 0; j < 16; j++) {
      const p = off + j * 4;
      M[j] = (msg[p] | (msg[p + 1] << 8) | (msg[p + 2] << 16) | (msg[p + 3] << 24)) >>> 0;
    }
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + MD5_K[i] + M[g]) >>> 0;
      A = D; D = C; C = B;
      B = (B + rotl32(F, MD5_S[i])) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = [];
  for (const w of [a0, b0, c0, d0]) for (let i = 0; i < 4; i++) out.push((w >>> (8 * i)) & 0xff);
  return out.map(b => b.toString(16).padStart(2, "0")).join("");
}

function md5hex(str) { return md5Bytes(Array.from(new TextEncoder().encode(str))); }

// --- Toy salted KDF: real per-user salt, real repeated MD5, tunable cost -----
// NOT bcrypt. Same SHAPE bcrypt has (salt || password) run through a real
// primitive `cost` times) so the two properties this week cares about — salting
// and work factor — are both genuinely computed, not simulated.
function kdfHex(password, saltHex, cost) {
  let state = saltHex;
  for (let i = 0; i < cost; i++) state = md5hex(state + ":" + password);
  return state;
}

function randomSaltHex() {
  const bytes = new Uint8Array(4);
  if (window.crypto && window.crypto.getRandomValues) window.crypto.getRandomValues(bytes);
  else for (let i = 0; i < 4; i++) bytes[i] = Math.floor(Math.random() * 256);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

// --- Scenarios -----------------------------------------------------------------
// Three leaked-DB flavors, identical mechanic: an unsalted MD5 store where one
// dictionary pass cracks the target AND, for free, anyone who reused the same
// password; a salted+iterated store where the identical technique matches
// nothing, and an attacker who adapts still pays real, measured, extra cost.
const PRESETS = [
  {
    label: "University portal",
    org: "State University student portal (this week's own lab)",
    target: "admin",
    users: [
      { username: "admin", password: "sunshine2021" },
      { username: "registrar", password: "sunshine2021" },
      { username: "alice", password: "password" },
      { username: "ta1", password: "letmein" },
    ],
  },
  {
    label: "Campus camera fleet",
    org: "Building security camera dashboard logins",
    target: "cam-north",
    users: [
      { username: "cam-north", password: "dragon" },
      { username: "cam-south", password: "dragon" },
      { username: "cam-east", password: "master" },
      { username: "installer", password: "qwerty" },
    ],
  },
  {
    label: "Helpdesk mailbox",
    org: "IT helpdesk shared-account logins",
    target: "support1",
    users: [
      { username: "support1", password: "iloveyou" },
      { username: "support-backup", password: "iloveyou" },
      { username: "support2", password: "michael" },
      { username: "intern", password: "monkey" },
    ],
  },
];

let PRESET, STORE_A, STORE_B, TARGET_USER, TWIN_USER, COST;

function fmtMs(ms) { return ms < 0.1 ? "<0.1 ms" : `${ms.toFixed(1)} ms`; }

function buildStores() {
  STORE_A = PRESET.users.map(u => ({ username: u.username, password: u.password, digest: md5hex(u.password) }));
  STORE_B = PRESET.users.map(u => {
    const salt = randomSaltHex();
    return {
      username: u.username, password: u.password, salt,
      // Both getters re-derive from `password` + `salt` + the current COST on every
      // access — real recomputation, so moving the cost slider genuinely re-hashes.
      get digest() { return kdfHex(this.password, this.salt, COST); },
      get stored() { return `$tkdf$${COST}$${this.salt}$${this.digest}`; },
    };
  });
  TARGET_USER = PRESET.target;
  TWIN_USER = null;
  const targetDigest = STORE_A.find(u => u.username === TARGET_USER).digest;
  for (const u of STORE_A) {
    if (u.username !== TARGET_USER && u.digest === targetDigest) TWIN_USER = u.username;
  }
}

// The two .q blocks stay pure, evenly-columned "username  value" data — no
// inline annotation. A wrapped span mid-line in a half-width grid column (or
// the worksheet's 4:3 iframe) has nowhere sane to go once it breaks, so the
// target/twin story is told once, underneath, as its own short caption line.
function renderStores() {
  const linesA = STORE_A.map(u => `${u.username.padEnd(16)} ${u.digest}`).join("\n");
  document.getElementById("store-a").textContent = linesA;

  const linesB = STORE_B.map(u => `${u.username.padEnd(16)} ${u.stored}`).join("\n");
  document.getElementById("store-b").textContent = linesB;

  const capA = document.getElementById("store-a-cap");
  const capB = document.getElementById("store-b-cap");
  if (TWIN_USER) {
    capA.innerHTML = `Target: <strong>${TARGET_USER}</strong>. <span class="hash-crack-flag same">` +
      `${TWIN_USER} shares this exact hash</span> — crack ${TARGET_USER} and you've read ` +
      `${TWIN_USER}'s password too, for free.`;
    capB.innerHTML = `Target: <strong>${TARGET_USER}</strong>. <span class="hash-crack-flag diff">` +
      `${TWIN_USER}'s entry looks nothing alike</span>, despite the identical password.`;
  } else {
    capA.textContent = `Target: ${TARGET_USER}. No other row here happens to share its hash.`;
    capB.textContent = `Target: ${TARGET_USER}.`;
  }
}

function renderCostHint() {
  document.getElementById("cost-val").textContent = `${COST} real hash operations per guess`;
}

function clearResults() {
  ["work", "recovered", "verdict-a", "verdict-b-naive", "verdict-b-adapted"].forEach(id => {
    const el = document.getElementById(id);
    el.textContent = "";
    if (el.classList.contains("verdict")) el.className = "verdict";
  });
  document.getElementById("summary").textContent = "";
  updateGuessLive();
}

function loadScenario(preset) {
  PRESET = preset;
  COST = Number(document.getElementById("cost").value);
  buildStores();
  renderStores();
  renderCostHint();
  document.getElementById("org-label").textContent = preset.org;

  document.querySelectorAll(".preset-btn").forEach((el, i) => {
    el.setAttribute("aria-pressed", PRESETS[i] === preset ? "true" : "false");
  });
  document.getElementById("guess").value = "";
  clearResults();
}

document.querySelectorAll(".preset-btn").forEach(btn => {
  btn.addEventListener("click", () => loadScenario(PRESETS[Number(btn.dataset.preset)]));
});

const costSlider = document.getElementById("cost");
costSlider.addEventListener("input", () => {
  COST = Number(costSlider.value);
  renderStores();
  renderCostHint();
  updateGuessLive();
});

function updateGuessLive() {
  const guess = document.getElementById("guess").value;
  const liveEl = document.getElementById("guess-live");
  if (!guess) { liveEl.textContent = ""; return; }
  const targetA = STORE_A.find(u => u.username === TARGET_USER);
  const targetB = STORE_B.find(u => u.username === TARGET_USER);
  const hitA = md5hex(guess) === targetA.digest;
  const hitB = kdfHex(guess, targetB.salt, COST) === targetB.digest;
  liveEl.innerHTML =
    `Store A (${TARGET_USER}): ${hitA ? '<span class="hash-crack-flag same">✓ MATCH</span>' : "no match"} · ` +
    `Store B (${TARGET_USER}): ${hitB ? '<span class="hash-crack-flag diff">✓ match (found it, the slow way)</span>' : "no match"}`;
}
document.getElementById("guess").addEventListener("input", updateGuessLive);

document.getElementById("attack-btn").addEventListener("click", () => {
  const targetA = STORE_A.find(u => u.username === TARGET_USER);
  const targetB = STORE_B.find(u => u.username === TARGET_USER);

  // Store A: real MD5 of every candidate, stop at the first real match.
  let t0 = performance.now();
  let attemptsA = 0, foundA = null;
  for (const w of WORDLIST) {
    attemptsA++;
    if (md5hex(w) === targetA.digest) { foundA = w; break; }
  }
  const msA = performance.now() - t0;

  // Store B, naive: the SAME technique (raw md5(word)) against Store B's stored
  // string. Real comparisons, every one of them — they just never match, because
  // "$tkdf$..." isn't the shape a raw md5 hex digest can ever take.
  let naiveMatches = 0;
  for (const w of WORDLIST) if (md5hex(w) === targetB.stored) naiveMatches++;

  // Store B, adapted: attacker now uses the public salt + cost (both sit in the
  // open, right next to the hash — same as real bcrypt) and redoes the real KDF
  // for every candidate, stopping at the first real match.
  t0 = performance.now();
  let attemptsB = 0, foundB = null;
  for (const w of WORDLIST) {
    attemptsB++;
    if (kdfHex(w, targetB.salt, COST) === targetB.digest) { foundB = w; break; }
  }
  const msB = performance.now() - t0;

  const opsA = attemptsA;               // 1 real MD5 call per guess
  const opsB = attemptsB * COST;        // `cost` real MD5 calls per guess
  const ratio = Math.round(opsB / opsA);

  document.getElementById("work").textContent =
    `Store A: tried ${attemptsA}/${WORDLIST.length} candidates, 1 real md5() call each\n` +
    `  -> stopped at "${foundA}" in ${fmtMs(msA)} (${opsA} total md5 calls)\n\n` +
    `Store B, same technique (raw md5(word) vs. "$tkdf$..."): ${naiveMatches}/${WORDLIST.length} matched\n\n` +
    `Store B, adapted (kdfHex(word, salt, ${COST}) vs. stored digest):\n` +
    `  -> stopped at "${foundB}" in ${fmtMs(msB)} (${opsB} total md5 calls, ${COST} per guess)`;

  document.getElementById("recovered").textContent =
    `${TARGET_USER}'s password: ${foundA}\n` +
    (TWIN_USER ? `${TWIN_USER}'s password: ${foundA}  (never guessed — read straight off the matching hash)` : "no other row shares this hash");

  const verdictA = document.getElementById("verdict-a");
  verdictA.textContent = `✓ CRACKED — ${foundA} recovered in ${fmtMs(msA)}, ` +
    `${opsA} real md5() calls total across ${STORE_A.length} accounts.`;
  verdictA.className = "verdict bad";

  const verdictBNaive = document.getElementById("verdict-b-naive");
  verdictBNaive.textContent = `✗ same technique: 0/${WORDLIST.length} matches — ` +
    `"$tkdf$..." isn't a shape raw md5(word) can ever produce.`;
  verdictBNaive.className = "verdict ok";

  // Every preset's password is deliberately drawn from WORDLIST, so this attack
  // always eventually finds it — cost changes the PRICE of that success, never
  // whether it happens. No "still not found" branch: that outcome is never true
  // here, and printing it anyway would misstate what the cost slider controls.
  const verdictBAdapted = document.getElementById("verdict-b-adapted");
  verdictBAdapted.textContent = `✓ adapted technique still finds it — ${foundB} recovered in ` +
    `${fmtMs(msB)}. Store A: ${opsA} total md5() calls. Store B, adapted: ${opsB} total md5() ` +
    `calls — ${ratio}× as many, for the identical password.`;
  verdictBAdapted.className = "verdict bad";

  document.getElementById("summary").textContent =
    "Nothing about MD5 itself changed between the two stores — the same real MD5 ran both times. " +
    "What changed is the price of a guess: no salt means one precomputed pass clears every row that " +
    `shares a password (${TWIN_USER || "a row"} came free here); a salt means the attacker needs a ` +
    "fresh run per row; and the iteration count multiplies the cost of every single one of those runs. " +
    `"${foundA}" was in the wordlist either way — a slow, salted KDF didn't make it unguessable, it made ` +
    "guessing it (and everything else in the wordlist) cost dramatically more. That's the work-factor " +
    "argument: raise the price, don't assume the vault. Real security still needs a password policy that " +
    "keeps weak, in-wordlist passwords out in the first place.";
});

loadScenario(PRESETS[0]);
