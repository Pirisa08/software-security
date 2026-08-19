// Man-in-the-middle on unauthenticated Diffie-Hellman, computed for real in the browser.
//
// Real: the modular exponentiation (BigInt, square-and-multiply) runs over an actual
// verified safe prime P = 2*Q+1 (P and Q both probable-prime tested), with G=2 as a
// working generator element for this specific P -- same DH math as
// week05-key-exchanges/common.py, just far smaller (97 bits, not RFC3526 Group 14's
// 2048) so every public value fits on screen. This sim makes no claim about what
// subgroup G=2 generates in the REAL 2048-bit group -- that's a separate question this
// week's slides deliberately leave conceptual (see "Not in today's demo").
// Toy: the session-key derivation, the message cipher, and the pubkey-authentication
// tag are small deterministic mixing functions standing in for real
// SHA-256 / AES-256-GCM / HMAC-SHA256 -- same simplification Week 3's mac-extend sim
// makes for its hash. What's NOT faked: Relay's two handshakes are two independently,
// honestly computed DH exchanges, and every verdict below falls out of a real equality
// check on computed values -- nothing branches on which button was clicked.

// --- A small, verified safe prime (P = 2*Q+1, both P and Q probable-prime tested) ---
const P = 146655170513638219830606613499n;
const G = 2n;

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

// Not cryptographically secure -- same simplification mac-extend.js makes with
// Math.random() for its toy secret. The vulnerability class demonstrated here doesn't
// depend on RNG quality, only on nobody checking WHOSE public value arrived.
function randomExponent() {
  let n = 0n;
  for (let i = 0; i < 7; i++) n = (n << 16n) | BigInt(Math.floor(Math.random() * 65536));
  return (n % (P - 3n)) + 2n;
}

function bytesOfStr(str) {
  return Array.from(new TextEncoder().encode(str));
}

function bytesOfBigInt(n) {
  let h = n.toString(16);
  if (h.length % 2) h = "0" + h;
  const out = [];
  for (let i = 0; i < h.length; i += 2) out.push(parseInt(h.slice(i, i + 2), 16));
  return out;
}

function hexBytes(bytes) {
  return bytes.map(b => b.toString(16).padStart(2, "0")).join("");
}

function bytesToStr(bytes) {
  return new TextDecoder().decode(new Uint8Array(bytes));
}

// A small Merkle-Damgard-shaped mixing function -- deterministic, avalanches on every
// input byte. Stands in for a real hash/HMAC the same way mac-extend.js's toyhash does;
// this sim isn't demonstrating hash internals, so it skips that sim's padding machinery.
function toyhash(bytes) {
  let s = 0x6a09e667 >>> 0;
  for (const b of bytes) {
    s = Math.imul(s ^ b, 0x01000193) >>> 0;
    s = ((s << 13) | (s >>> 19)) >>> 0;
  }
  return s >>> 0;
}

function hex32(n) {
  return (n >>> 0).toString(16).padStart(8, "0");
}

// Toy session-key derivation, standing in for common.py's derive_aes_key() (real
// SHA-256 of the raw DH shared-secret bytes).
function deriveKey(sharedSecret) {
  return toyhash(bytesOfBigInt(sharedSecret));
}

// Toy keyed hash standing in for common.py's hmac_pubkey() (real HMAC-SHA256). A bare
// prefix hash like this is exactly what Week 3's sim showed is length-extendable --
// fine for THIS demo (nobody here is extending anything), not a real HMAC replacement.
function toyMac(keyBytes, dataBytes) {
  return toyhash(keyBytes.concat(dataBytes));
}

// Toy stream cipher: XOR each plaintext byte against a keystream byte derived from the
// (real, DH-derived) key and the byte's position. Symmetric, so the same call encrypts
// and decrypts -- stands in for common.py's AES-256-GCM.
function toyCrypt(keyInt, bytes) {
  return bytes.map((b, i) => b ^ (toyhash([
    (keyInt >>> 24) & 0xff, (keyInt >>> 16) & 0xff, (keyInt >>> 8) & 0xff, keyInt & 0xff,
    i & 0xff, (i >>> 8) & 0xff,
  ]) & 0xff));
}

// --- Scenarios --------------------------------------------------------------
// Three different messages Alice sends -- same underlying mechanic every time
// (unauthenticated DH lets Relay run two independent, individually-valid handshakes).
// Preset 0's text is the literal SECRET_MESSAGE the real lab's alice.py sends, the one
// students see as "RELAY INTERCEPTED: ..." in their own docker compose logs.
const PRESETS = [
  { label: "Launch codes", data: "the launch code is 4471" },
  { label: "Wire transfer", data: "transfer $50,000 to acct 88214" },
  { label: "Login session token", data: "session=alice-f83d2c1a" },
];

let AUTH_KEY, current;

function loadScenario(preset) {
  current = preset;
  AUTH_KEY = bytesOfStr("auth_" + Math.random().toString(36).slice(2, 8)); // Alice+Bob only, never Relay

  document.getElementById("scenario").textContent = `data = "${preset.data}"`;

  document.querySelectorAll(".preset-btn").forEach((el, i) => {
    el.setAttribute("aria-pressed", PRESETS[i] === preset ? "true" : "false");
  });

  ["work", "intercepted", "verdict-a", "verdict-b", "summary"].forEach(id => {
    const el = document.getElementById(id);
    el.textContent = "";
    if (el.classList.contains("verdict")) el.className = "verdict";
  });
  renderAuthHint();
}

document.querySelectorAll(".preset-btn").forEach(btn => {
  btn.addEventListener("click", () => loadScenario(PRESETS[Number(btn.dataset.preset)]));
});

const authCheckbox = document.getElementById("authknown");
function renderAuthHint() {
  document.getElementById("authknown-hint").textContent = authCheckbox.checked
    ? "Relay can now compute the SAME tag Alice/Bob would -- Verifier B's check no longer " +
      "tells them anything, because it only proves someone with AUTH_KEY signed the key, " +
      "not that it was Alice or Bob."
    : "The normal case: Relay never has AUTH_KEY, so its guess at a tag essentially never " +
      "matches the real one.";
}
authCheckbox.addEventListener("change", renderAuthHint);

document.getElementById("run-btn").addEventListener("click", () => {
  // --- Fresh, real DH keypairs every run (ephemeral, like a real handshake) ---
  const aPriv = randomExponent(), aPub = modpow(G, aPriv, P);        // Alice, genuine
  const bPriv = randomExponent(), bPub = modpow(G, bPriv, P);        // Bob, genuine
  const rAPriv = randomExponent(), rAPub = modpow(G, rAPriv, P);     // Relay, posing as Bob
  const rBPriv = randomExponent(), rBPub = modpow(G, rBPriv, P);     // Relay, posing as Alice

  // --- Handshake #1: Alice <-> Relay (Relay posing as Bob) — real modpow both sides ---
  const keyAlice = modpow(rAPub, aPriv, P);            // Alice's own math
  const keyRelayWithAlice = modpow(aPub, rAPriv, P);   // Relay's own math
  // --- Handshake #2: Bob <-> Relay (Relay posing as Alice) ---
  const keyBob = modpow(rBPub, bPriv, P);
  const keyRelayWithBob = modpow(bPub, rBPriv, P);

  const kAlice = deriveKey(keyAlice), kRelayAlice = deriveKey(keyRelayWithAlice);
  const kBob = deriveKey(keyBob), kRelayBob = deriveKey(keyRelayWithBob);

  document.getElementById("work").textContent =
    `Relay generates two DH keypairs (real modpow, mod a ${P.toString(2).length}-bit prime):\n` +
    `  g^rA mod p = ${rAPub.toString(16)}   (sent to Alice, "I'm Bob")\n` +
    `  g^rB mod p = ${rBPub.toString(16)}   (sent to Bob, "I'm Alice")\n\n` +
    `Alice's shared secret   = (relay's rA)^a mod p = ${keyAlice.toString(16)}\n` +
    `Relay's matching secret = (Alice's real pubkey)^rA mod p = ${keyRelayWithAlice.toString(16)}\n` +
    `  -> ${keyAlice === keyRelayWithAlice ? "equal — relay derived the exact key Alice did" : "MISMATCH (would be a bug)"}\n\n` +
    `Bob's shared secret     = (relay's rB)^b mod p = ${keyBob.toString(16)}\n` +
    `Relay's matching secret = (Bob's real pubkey)^rB mod p = ${keyRelayWithBob.toString(16)}\n` +
    `  -> ${keyBob === keyRelayWithBob ? "equal — relay derived the exact key Bob did" : "MISMATCH (would be a bug)"}\n\n` +
    `Alice's session key vs Bob's session key: ${hex32(kAlice)} vs ${hex32(kBob)}\n` +
    `  -> ${kAlice === kBob ? "SAME (statistically shouldn't happen)" : "different — and neither side ever compares"}`;

  // --- Verifier A: vulnerable — plain DH, nobody checks anything, relay just relays ---
  const msgBytes = bytesOfStr(current.data);
  const ciphertextToRelay = toyCrypt(kAlice, msgBytes);
  const decryptedByRelay = toyCrypt(kRelayAlice, ciphertextToRelay);
  const reencryptedForBob = toyCrypt(kRelayBob, decryptedByRelay);
  const decryptedByBob = toyCrypt(kBob, reencryptedForBob);

  document.getElementById("intercepted").textContent =
    `Alice encrypts under her key and sends it to who she thinks is Bob:\n` +
    `  ciphertext = ${hexBytes(ciphertextToRelay)}\n\n` +
    `Relay decrypts with its Alice-side key:\n` +
    `  RELAY INTERCEPTED: "${bytesToStr(decryptedByRelay)}"\n\n` +
    `Relay re-encrypts the SAME plaintext under its Bob-side key and forwards it:\n` +
    `  ciphertext' = ${hexBytes(reencryptedForBob)}\n\n` +
    `Bob decrypts with his real key -- reads it, notices nothing:\n` +
    `  "${bytesToStr(decryptedByBob)}"`;

  const verdictA = document.getElementById("verdict-a");
  verdictA.textContent = "✓ ACCEPTED — both handshakes completed with no error, the message " +
    "was read in the clear, and it was forwarded so Bob never suspects a thing.";
  verdictA.className = "verdict bad";

  // --- Verifier B: fixed — HMAC-authenticated DH ---
  // ONE code path regardless of the checkbox: Relay signs with whatever key it actually
  // has (the real AUTH_KEY if it "leaked", a guess otherwise), and Alice/Bob check that
  // tag against a hash of the SAME pubkey under the real AUTH_KEY they hold. The verdict
  // is just whether those two independently-computed tags happen to match.
  const relayAuthKey = authCheckbox.checked
    ? AUTH_KEY
    : bytesOfStr("guess_" + Math.random().toString(36).slice(2, 8));

  const relayTagForAlice = toyMac(relayAuthKey, bytesOfBigInt(rAPub));  // what Relay actually sends
  const aliceExpectedTag = toyMac(AUTH_KEY, bytesOfBigInt(rAPub));      // what Alice independently computes
  const aliceAccepts = relayTagForAlice === aliceExpectedTag;

  const relayTagForBob = toyMac(relayAuthKey, bytesOfBigInt(rBPub));
  const bobExpectedTag = toyMac(AUTH_KEY, bytesOfBigInt(rBPub));
  const bobAccepts = relayTagForBob === bobExpectedTag;

  const verdictB = document.getElementById("verdict-b");
  if (aliceAccepts && bobAccepts) {
    verdictB.textContent = "✓ accepted — only because AUTH_KEY leaked to Relay above; " +
      "uncheck the box and re-run to see the honest fixed-mode outcome.";
    verdictB.className = "verdict bad";
  } else {
    const who = [!aliceAccepts && "Alice", !bobAccepts && "Bob"].filter(Boolean).join(" and ");
    verdictB.textContent = `✗ REJECTED — ${who} print "AUTH FAILED - ABORTING": the tag on ` +
      "Relay's substituted public key doesn't match, so no session key is ever derived. " +
      "Relay never reaches the point of decrypting anything.";
    verdictB.className = "verdict ok";
  }

  document.getElementById("summary").textContent =
    "The vulnerability is structural, not about the math: DH genuinely defeats a passive " +
    "eavesdropper (recovering a private exponent from a public value is the discrete-log " +
    "problem), but plain DH gives neither side a way to check WHO answered — only that the " +
    "handshake completed. HMAC-signing each public key closes that gap, but the fix is only " +
    "as strong as AUTH_KEY's secrecy, which is exactly what the checkbox above tests. Real " +
    "systems (TLS, SSH) authenticate DH with certificates/signatures instead of one shared " +
    "MAC key — same principle, a trust chain instead of a single shared secret.";
});

loadScenario(PRESETS[0]);
