// Entropy collapse: a "textbook-secure" key/token derivation fed a seed that
// was never actually random. expand() and commit() below are toy mixers, NOT
// real HKDF/SHA-256 — but the shape is the real bug: CVE-2008-0166 (Debian's
// OpenSSL packaging patch deleted the entropy-gathering code, leaving only a
// process ID — about 32,768 values, system-wide — to seed every key). Swap
// expand()/commit() for a real KDF and a real hash and nothing about the
// lesson changes: the primitive was never broken, the seed was never random.
//
// Every number below is computed for real: the brute-force loop actually
// runs candidate-by-candidate in this tab, and Verifier B's "years needed"
// figure is derived with BigInt from the exact candidates/sec that loop just
// measured — never a scripted or hardcoded outcome.

function u32(n) {
  return n >>> 0;
}

// expand(): stands in for "derive key material from a seed" (a CSPRNG or a
// KDF in a real system). The mixing itself is not the bug — a real system's
// KDF is at least this strong. What breaks the scheme is what gets fed in.
function expand(seed) {
  let s = u32(seed);
  s = Math.imul(s ^ 0x9e3779b9, 0x85ebca6b) >>> 0;
  s = ((s << 13) | (s >>> 19)) >>> 0;
  s = Math.imul(s ^ 0xc2b2ae35, 0x27d4eb2f) >>> 0;
  s = ((s << 17) | (s >>> 15)) >>> 0;
  return s >>> 0;
}

// commit(): the one-way "publish" step — a host-key fingerprint, a stored
// token hash, a reset-link hash. Whatever this scenario calls it, it's the
// only value that ever actually leaves the server.
function commit(key) {
  let s = 0x6a09e667;
  const bytes = [(key >>> 24) & 0xff, (key >>> 16) & 0xff, (key >>> 8) & 0xff, key & 0xff];
  for (const b of bytes) {
    s = Math.imul(s ^ b, 0x01000193) >>> 0;
    s = ((s << 13) | (s >>> 19)) >>> 0;
  }
  return s >>> 0;
}

function hex(n) {
  return u32(n).toString(16).padStart(8, "0");
}

// --- Scenarios ---------------------------------------------------------
// Three different systems, same underlying bug: the seed's real range is
// tiny next to the 2^128 the design assumes. realRange is the ACTUAL number
// of possible seeds in the real deployment — small enough that the sim's
// own brute-force loop finishes in well under a second in a plain browser
// tab, same as it would for a real attacker against the real bug.
const PRESETS = [
  {
    label: "TLS host key",
    asset: "SSH/TLS host key",
    sourceLabel: "process ID (PID)",
    realRange: 32768, // 2^15 — the actual magnitude of CVE-2008-0166
    incident:
      "Debian's OpenSSL packaging patch (CVE-2008-0166, 2006–2008) accidentally deleted the " +
      "entropy-gathering code. Every key generated on an affected system came from a PID and " +
      "nothing else — about 32,768 possible values per key type, system-wide, for two years.",
  },
  {
    label: "Session token",
    asset: "login session token",
    sourceLabel: "server clock (Unix seconds)",
    realRange: 300,
    incident:
      "The token generator seeds its “random” value from the current timestamp instead of a " +
      "CSPRNG — Snake Oil squares #4 and #9. Anyone who can bracket a five-minute login window " +
      "already has the entire real search space.",
  },
  {
    label: "Password-reset link",
    asset: "password-reset token",
    sourceLabel: "request counter",
    realRange: 10000,
    incident:
      "The reset-link generator seeds from an incrementing request counter instead of real " +
      "randomness. An attacker who can learn the counter's approximate position (e.g. by " +
      "requesting their own reset first) narrows the search hugely.",
  },
];

let SCENARIO, TRUE_SEED, PRIVATE_KEY, PUBLISHED_COMMIT, LAST_RATE;

function loadScenario(preset) {
  SCENARIO = preset;
  TRUE_SEED = Math.floor(Math.random() * preset.realRange);
  PRIVATE_KEY = expand(TRUE_SEED);
  PUBLISHED_COMMIT = commit(PRIVATE_KEY);
  LAST_RATE = null;

  document.getElementById("scenario-context").textContent = preset.incident;
  document.getElementById("intercepted").textContent =
    `asset = "${preset.asset}"\n` +
    `seed source = ${preset.sourceLabel}  (real range: ${preset.realRange.toLocaleString()} possible values)\n` +
    `published commitment = ${hex(PUBLISHED_COMMIT)}   (this is ALL that ever left the server)`;

  document.querySelectorAll(".preset-btn").forEach((el, i) => {
    el.setAttribute("aria-pressed", PRESETS[i] === preset ? "true" : "false");
  });

  const slider = document.getElementById("search-range");
  slider.min = "1";
  slider.max = String(Math.min(preset.realRange * 3, 150000));
  // step stays 1: a range input snaps its value to min + n*step, and
  // realRange is not on that lattice for a coarser step (e.g. 32768 with
  // step 164 snaps to 32801) -- the default click would still succeed, but
  // the readout would then contradict the "real range: N" text above it.
  slider.step = "1";
  slider.value = String(preset.realRange);

  ["work", "recovered", "verdict-a", "verdict-b", "summary"].forEach((id) => {
    const el = document.getElementById(id);
    el.textContent = "";
    if (el.classList.contains("verdict")) el.className = "verdict";
  });

  renderRange();
}

document.querySelectorAll(".preset-btn").forEach((btn) => {
  btn.addEventListener("click", () => loadScenario(PRESETS[Number(btn.dataset.preset)]));
});

const rangeSlider = document.getElementById("search-range");
const rangeVal = document.getElementById("search-range-val");
function renderRange() {
  const v = Number(rangeSlider.value);
  rangeVal.textContent = `${v.toLocaleString()} candidates (seed 0 to ${(v - 1).toLocaleString()})`;
  const covers = v >= SCENARIO.realRange;
  document.getElementById("range-hint").textContent = covers
    ? `This covers the real system's entire ${SCENARIO.realRange.toLocaleString()}-candidate space — ` +
      `a real attacker only ever needs to search that far, once.`
    : `This covers only part of the real ${SCENARIO.realRange.toLocaleString()}-candidate space — ` +
      `you might miss the true seed. A real attacker would just widen the search to the full range, ` +
      `which is still nothing to brute-force.`;
}
rangeSlider.addEventListener("input", renderRange);

document.getElementById("crack-btn").addEventListener("click", () => {
  const searchRange = Math.min(Number(rangeSlider.value), 500000); // safety cap only — no preset gets near it
  const t0 = performance.now();
  let found = -1;
  let candidateKey = null;
  for (let seed = 0; seed < searchRange; seed++) {
    const key = expand(seed);
    if (commit(key) === PUBLISHED_COMMIT) {
      found = seed;
      candidateKey = key;
      break;
    }
  }
  const t1 = performance.now();
  const elapsedMs = t1 - t0;
  const tried = found >= 0 ? found + 1 : searchRange;
  LAST_RATE = tried / Math.max(elapsedMs / 1000, 0.001); // candidates/sec, guarded against a 0ms run

  document.getElementById("work").textContent =
    `for seed = 0 .. ${searchRange - 1}:\n` +
    `  key = expand(seed)                 // same function the server uses\n` +
    `  if commit(key) == ${hex(PUBLISHED_COMMIT)}: STOP\n` +
    `tried ${tried.toLocaleString()} candidates in ${elapsedMs.toFixed(1)} ms ` +
    `(~${Math.round(LAST_RATE).toLocaleString()} candidates/sec, this browser tab, no special hardware)`;

  const verdictA = document.getElementById("verdict-a");
  const recovered = document.getElementById("recovered");
  if (found >= 0) {
    recovered.textContent =
      `seed  = ${found}\n` +
      `key   = ${hex(candidateKey)}\n` +
      `commit(key) = ${hex(commit(candidateKey))}  — matches the published commitment`;
    verdictA.textContent =
      `✓ KEY RECOVERED — seed ${found} reproduces the exact published commitment. The secret ` +
      `key was never transmitted; only its narrow source ever had to be guessed.`;
    verdictA.className = "verdict bad";
  } else {
    recovered.textContent =
      `no match in seeds 0..${searchRange - 1} — widen the search range above the real system's ` +
      `${SCENARIO.realRange.toLocaleString()}-candidate space and try again.`;
    verdictA.textContent =
      `✗ not found in this range — that doesn't mean the system is safe, only that this ` +
      `particular search missed it. The real range is still only ` +
      `${SCENARIO.realRange.toLocaleString()} candidates.`;
    verdictA.className = "verdict ok";
  }

  // Verifier B: project the SAME measured throughput onto the keyspace the
  // design actually assumes — a true 128-bit random seed. Computed fresh
  // from this run's own numbers with BigInt, never a stored/hardcoded figure.
  const verdictB = document.getElementById("verdict-b");
  if (LAST_RATE && LAST_RATE > 0) {
    const ratePerSec = BigInt(Math.max(Math.round(LAST_RATE), 1));
    const totalCandidates = 2n ** 128n;
    const secondsNeeded = totalCandidates / ratePerSec;
    const yearsNeeded = secondsNeeded / 31536000n;
    const orderOfMagnitude = yearsNeeded > 0n ? yearsNeeded.toString().length - 1 : 0;
    verdictB.textContent =
      `at the ${Math.round(LAST_RATE).toLocaleString()} candidates/sec you just measured, exhausting ` +
      `a REAL 2^128-value keyspace would take roughly 10^${orderOfMagnitude} years — ` +
      `✗ REJECTED as infeasible. Same expand()/commit() functions, same browser tab — only the ` +
      `entropy differs.`;
    verdictB.className = "verdict ok";
  } else {
    verdictB.textContent = "Run the brute force above first — this projection uses its measured speed.";
  }

  document.getElementById("summary").textContent =
    "The vulnerability is never inside expand() or commit() — swap in real HKDF and SHA-256 and the " +
    "story is identical. CWE-330 (Use of Insufficiently Random Values) is a keyspace failure: a " +
    "“textbook-secure” construction is only as strong as the assumption that its seed is " +
    "actually unpredictable. Break that one assumption — seed from a PID, a clock, a counter — and " +
    "every bit of algorithm strength downstream becomes irrelevant. This is why Snake Oil square " +
    "#23, “we follow current NIST key-length guidance, so our use of cryptography is fine,” is a " +
    "myth: this week's Exhibit makes exactly that argument, entirely in terms of key length and " +
    "algorithm currency, and never once mentions where the key's randomness actually came from.";
});

loadScenario(PRESETS[0]);
