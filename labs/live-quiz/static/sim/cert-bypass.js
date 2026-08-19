// Certificate-validation-bypass MITM: the same self-signed impostor certificate,
// checked (or not) by two different TLS clients.
//
// This is textbook RSA (Wikipedia's own p=61,q=53 example for the CA keypair) —
// NOT real X.509 DER encoding, NOT a real TLS 1.3 key schedule, and the numbers
// are small on purpose so every modular exponentiation is checkable by hand.
// Same simplification mac-extend.js makes for its toy Merkle-Damgard hash: the
// LESSON is structural (a signature is a genuine trapdoor -- only the holder of
// a matching private key produces one the matching public key accepts), not the
// specific algorithm or key size.
//
// Two things are computed for real, live, every click:
//   1. Whether the presented certificate's signature verifies against the ONE
//      public key Client B trusts (the demo CA's) -- real modpow, real mismatch.
//   2. Whether the key exchange itself succeeds -- it always does, for BOTH
//      clients, because the impostor genuinely holds the private key matching
//      whatever certificate it hands out. That's the counterintuitive fact this
//      week's lab keeps landing on: "encrypted" is true even while "encrypted to
//      the right party" is false. Certificate validation is the only thing that
//      tells those two claims apart.

function modpow(base, exp, mod) {
  base %= mod;
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

function fnv1a(str) {
  let h = 0x811c9dc5;
  for (const b of new TextEncoder().encode(str)) {
    h ^= b;
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

// The demo CA's keypair. Every client that validates trusts ONLY this public
// key (CA_E, CA_N) -- the same role ca.crt plays in the real lab.
const CA_N = 3233n, CA_E = 17n, CA_D = 2753n;
// The keypair the attacker generated for ITS OWN self-signed certificate --
// unrelated to the CA's. This is the private key impostor.key holds in the real
// lab: genuinely usable for a TLS handshake, just never vouched for by anyone.
const SELF_N = 2773n, SELF_E = 3n, SELF_D = 1779n;
const MODH = 2600n; // keeps every hash safely below both moduli above

// --- Scenarios ---------------------------------------------------------------
// Same underlying bug (CWE-295: nobody checked who signed the cert), three
// different systems. Preset 0 is the lab's own Alice/Bob/MITM topology and
// secret, verbatim; 1 mirrors the worksheet's Audit-the-AI snippet
// (verify=False on an internal API client); 2 is a third, distinct domain.
const PRESETS = [
  {
    label: "Vault code handoff",
    clientName: "Alice",
    targetHost: "bob",
    port: "8443",
    cn: "bob",
    san: "DNS:bob",
    secret: "the vault code is 7731",
  },
  {
    label: "Internal API bearer token",
    clientName: "the internal API client",
    targetHost: "api.internal.corp",
    port: "443",
    cn: "api.internal.corp",
    san: "DNS:api.internal.corp",
    secret: "Authorization: Bearer sk_internal_8841",
  },
  {
    label: "Bank session login",
    clientName: "the banking app",
    targetHost: "bank-api.example",
    port: "443",
    cn: "bank-api.example",
    san: "DNS:bank-api.example",
    secret: "session_token=sk_live_9f2c...(already authenticated)",
  },
];

function certString(p) {
  return `CN=${p.cn};SAN=${p.san}`;
}

let CUR, H;

function compromisedChecked() {
  return document.getElementById("compromised-ca").checked;
}

// What signs the certificate right now, given the toggle. Self-signed uses the
// attacker's OWN key (SELF_D/SELF_N) -- what mitm.py always does. The bonus
// toggle swaps in the CA's key (CA_D/CA_N), modelling a scenario this week's
// demo never produces: the CA itself handing out a signature over the
// attacker's claim.
function signCert(compromised) {
  return compromised ? modpow(H, CA_D, CA_N) : modpow(H, SELF_D, SELF_N);
}

function renderCert() {
  const compromised = compromisedChecked();
  const sig = signCert(compromised);
  const issuerLine = compromised
    ? `"Week12 Demo CA" -- signed with the CA's OWN private key (stolen)`
    : `self (the attacker generated this key; no CA involved)`;
  document.getElementById("cert-card").textContent =
    `subject:   CN=${CUR.cn}\n` +
    `SAN:       ${CUR.san}\n` +
    `issuer:    ${issuerLine}\n` +
    `signature (on the wire): ${sig}`;
  document.getElementById("compromised-hint").textContent = compromised
    ? "Models a compromised CA (worksheet Q5 / EiPE) -- the running lab never produces this; it's the \"what if\" this toggle previews."
    : "Normal lab behavior: the impostor signs with its own key, never the CA's -- exactly what mitm.py does.";
}

function loadScenario(preset) {
  CUR = preset;
  H = BigInt(fnv1a(certString(preset))) % MODH;

  document.getElementById("compromised-ca").checked = false;
  document.getElementById("connect-line").textContent =
    `${CUR.clientName} dials ${CUR.targetHost}:${CUR.port} -- but on this network path, whoever ` +
    `answers presents the certificate below, not necessarily ${CUR.targetHost} itself:`;
  renderCert();

  document.querySelectorAll(".preset-btn").forEach((el, i) => {
    el.setAttribute("aria-pressed", PRESETS[i] === preset ? "true" : "false");
  });
  ["work", "verdict-a", "verdict-b", "summary"].forEach(id => {
    const el = document.getElementById(id);
    el.textContent = "";
    if (el.classList.contains("verdict")) el.className = "verdict";
  });
}

document.querySelectorAll(".preset-btn").forEach(btn => {
  btn.addEventListener("click", () => loadScenario(PRESETS[Number(btn.dataset.preset)]));
});
document.getElementById("compromised-ca").addEventListener("change", renderCert);

document.getElementById("handshake-btn").addEventListener("click", () => {
  const compromised = compromisedChecked();
  const sig = signCert(compromised);

  // Client B's TWO checks -- both genuinely computed, neither assumed from the
  // toggle state.
  const hostnameOK = CUR.san === `DNS:${CUR.targetHost}`;
  const check = modpow(sig, CA_E, CA_N);
  const chainOK = check === H;
  const acceptB = hostnameOK && chainOK;

  // Key exchange: BOTH clients would negotiate a session key with whoever
  // answered, and it genuinely works, because the impostor holds SELF_D/SELF_N
  // -- the real private key for the certificate it presented. This is why the
  // handshake log says "succeeded": the crypto is real. Only Client B's chain
  // check runs first and can abort before this step ever completes.
  const clientRandom = (H * 31n + 7n) % SELF_N;
  const encryptedKey = modpow(clientRandom, SELF_E, SELF_N);
  const recoveredKey = modpow(encryptedKey, SELF_D, SELF_N);
  const keyExchangeOK = recoveredKey === clientRandom;

  document.getElementById("work").textContent =
    `cert claims: CN=${CUR.cn}, SAN=${CUR.san}\n` +
    `hash of the claimed identity (toy hash, not real X.509 DER): h = ${H}\n` +
    `signed with: ${compromised ? "the CA's OWN private key (stolen)" : "the attacker's own key (self-signed)"}\n` +
    `signature on the wire: sig = ${sig}\n\n` +
    `Client B, step 1 -- hostname (RFC 6125):\n` +
    `  "${CUR.san}" === "DNS:${CUR.targetHost}" ?  ${hostnameOK ? "PASS" : "FAIL"}\n\n` +
    `Client B, step 2 -- chain of trust, using ONLY the CA's public key it already holds:\n` +
    `  check = sig^${CA_E} mod ${CA_N} = ${check}\n` +
    `  expected (the claimed identity's hash): h = ${H}\n` +
    `  ${chainOK ? "check == h  ->  chain verifies" : "check != h  ->  no chain to the trusted CA"}\n\n` +
    `Key exchange (both clients get this far the same way -- the impostor really\n` +
    `holds the private key for whatever it presented):\n` +
    `  session key = ${clientRandom}\n` +
    `  encrypted under the presented public key: ${encryptedKey}\n` +
    `  decrypted by whoever holds the matching private key: ${recoveredKey}\n` +
    `  ${keyExchangeOK ? "round-trips correctly -- key exchange is never the problem" : "FAILED (should not happen)"}`;

  const verdictA = document.getElementById("verdict-a");
  verdictA.textContent =
    `✓ ACCEPTED -- CERT_NONE never asks step 1 or step 2 above; the session key ` +
    `round-trip you just watched is the only crypto that runs. ${CUR.clientName} sends ` +
    `"${CUR.secret}" to whoever answered. MITM logs it: MITM INTERCEPTED: ${CUR.secret}`;
  verdictA.className = "verdict bad";

  const verdictB = document.getElementById("verdict-b");
  if (acceptB) {
    verdictB.textContent =
      `✓ accepted -- hostname passed AND the chain now verifies (signed with the ` +
      `CA's own stolen key). Key exchange completes exactly like Client A's did -- ` +
      `nothing left to stop it. This is the compromised-CA gap the running lab never ` +
      `produces (worksheet Q5 / EiPE).`;
    verdictB.className = "verdict bad";
  } else if (!hostnameOK) {
    verdictB.textContent =
      `✗ REJECTED -- hostname mismatch: "${CUR.san}" does not match ` +
      `"DNS:${CUR.targetHost}". Handshake aborts before the chain check even runs.`;
    verdictB.className = "verdict ok";
  } else {
    verdictB.textContent =
      `✗ REJECTED -- self-signed certificate. Step 1 passed: the name was correct ` +
      `the whole time. Step 2 failed: sig^${CA_E} mod ${CA_N} != h, no path from this ` +
      `signature to a CA Client B trusts. Handshake aborts here -- before the key ` +
      `exchange above ever gets a chance to run, before the secret is sent.`;
    verdictB.className = "verdict ok";
  }

  document.getElementById("summary").textContent =
    "The break is structural, not cryptographic: TLS's own crypto (key exchange, " +
    "CertificateVerify) worked perfectly for both clients above -- the impostor really " +
    "does hold a matching private key. CERT_NONE / verify=False / InsecureSkipVerify " +
    "all skip the SAME one check: does this certificate chain to someone I already " +
    "trust? Rejecting it never depended on the name -- CN and SAN were correct the " +
    "whole time -- only on who vouched for it. And that check has exactly one blind " +
    "spot: toggle \"compromised CA\" above and watch even Client B accept the forgery.";
});

loadScenario(PRESETS[0]);
