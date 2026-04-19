import './style.css';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import {
  setup as ibeSetup,
  extract,
  encrypt,
  decrypt,
  decryptWrongKey,
  type IBESystem,
  type IBECiphertext,
} from './ibe.ts';
import {
  simulateTimeLimitedMessage,
  demonstrateKeyEscrow,
} from './scenarios.ts';

// ─── helpers ─────────────────────────────────────────────────────────────────

function hex(bytes: Uint8Array, maxBytes = 20): string {
  const slice = bytes.slice(0, maxBytes);
  const h = Array.from(slice)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return h + (bytes.length > maxBytes ? `…(${bytes.length}B)` : '');
}

function hexG1(pt: InstanceType<typeof bls.G1.Point>): string {
  const b = pt.toBytes(true);
  return hex(b, 12);
}

function hexG2(pt: InstanceType<typeof bls.G2.Point>): string {
  const b = pt.toBytes(true);
  return hex(b, 12);
}

function pad(msg: string, n: number): Uint8Array {
  const enc = new TextEncoder().encode(msg);
  const out = new Uint8Array(n);
  out.set(enc.slice(0, n));
  return out;
}

function unpad(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes).replace(/\0+$/, '');
}

function setHTML(id: string, html: string) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = html;
}

function getVal(id: string): string {
  const el = document.getElementById(id) as HTMLInputElement | null;
  return el ? el.value.trim() : '';
}

function disableBtn(id: string, disabled: boolean) {
  const el = document.getElementById(id) as HTMLButtonElement | null;
  if (el) {
    el.disabled = disabled;
    el.setAttribute('aria-disabled', String(disabled));
  }
}

function loading(id: string): void {
  setHTML(id, '<span class="spinner">⧗ Running…</span>');
}

// ─── Global IBE system ────────────────────────────────────────────────────────

let _system: IBESystem | null = null;
const MSG_BYTES = 32;

function getSystem(): IBESystem {
  if (!_system) throw new Error('Run Setup first (Exhibit 1)');
  return _system;
}

// ─── Boot ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  renderApp();
});

function renderApp() {
  const app = document.getElementById('app')!;
  app.innerHTML = `
    <a href="#main-content" class="skip-link">Skip to main content</a>
    <header class="lab-header">
      <div class="lab-header-text">
        <h1>IBE Gate — Identity-Based Encryption</h1>
        <div class="subtitle">Boneh-Franklin BasicIdent (2001) · BLS12-381 Pairings · IND-CPA</div>
      </div>
      <button class="theme-toggle" id="theme-toggle" aria-label="Toggle light/dark theme">Toggle Theme</button>
    </header>

    <div class="warning-box" role="note" aria-label="Security note">
      <div class="warning-title">⚠ IND-CPA ONLY — NOT IND-CCA</div>
      This demo implements BasicIdent from Boneh-Franklin 2001 §4.1.
      BasicIdent is semantically secure (IND-CPA) but NOT IND-CCA secure.
      An active adversary can perform ciphertext-malleability attacks.
      Production systems use FullIdent (§4.2) with the Fujisaki-Okamoto transform.
    </div>

    <nav aria-label="Exhibits" class="tab-nav" role="tablist">
      <button class="tab-btn" role="tab" aria-selected="true"  aria-controls="panel-setup"     id="tab-setup"     data-tab="setup">1 · Setup Ceremony</button>
      <button class="tab-btn" role="tab" aria-selected="false" aria-controls="panel-encrypt"   id="tab-encrypt"   data-tab="encrypt">2 · Encrypt to Stranger</button>
      <button class="tab-btn" role="tab" aria-selected="false" aria-controls="panel-wrongkey"  id="tab-wrongkey"  data-tab="wrongkey">3 · Wrong Key = Garbage</button>
      <button class="tab-btn" role="tab" aria-selected="false" aria-controls="panel-timelimit" id="tab-timelimit" data-tab="timelimit">4 · Time-Limited</button>
      <button class="tab-btn" role="tab" aria-selected="false" aria-controls="panel-escrow"    id="tab-escrow"    data-tab="escrow">5 · PKG Escrow Tradeoff</button>
    </nav>

    <main id="main-content">
      ${exhibit1()}
      ${exhibit2()}
      ${exhibit3()}
      ${exhibit4()}
      ${exhibit5()}
    </main>
  `;

  // Tab switching with ARIA
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const tab = (btn as HTMLElement).dataset.tab!;
      document.querySelectorAll<HTMLButtonElement>('.tab-btn').forEach((b) => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      document.querySelectorAll<HTMLElement>('.panel').forEach((p) => {
        p.classList.remove('active');
        p.setAttribute('aria-hidden', 'true');
      });
      btn.classList.add('active');
      (btn as HTMLButtonElement).setAttribute('aria-selected', 'true');
      const panel = document.getElementById(`panel-${tab}`)!;
      panel.classList.add('active');
      panel.setAttribute('aria-hidden', 'false');
    });
  });

  // Theme toggle
  document.getElementById('theme-toggle')!.addEventListener('click', () => {
    const cur = document.documentElement.getAttribute('data-theme');
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
  });

  wireExhibit1();
  wireExhibit2();
  wireExhibit3();
  wireExhibit4();
  wireExhibit5();
}

// ─── Exhibit 1: Setup Ceremony ────────────────────────────────────────────────

function exhibit1(): string {
  return `
  <div class="panel active" id="panel-setup" role="tabpanel" aria-labelledby="tab-setup" aria-hidden="false">
    <div class="card">
      <h2>Exhibit 1 — The Setup Ceremony</h2>
      <p style="color:var(--text-dim);margin-bottom:14px;font-size:13px;">
        The Private Key Generator (PKG) runs setup once. This produces system-wide
        public parameters and keeps the master secret <em>s</em> private.
      </p>
      <button class="btn btn-primary" id="btn-setup">▶ Run Setup</button>
      <div class="term" id="term-setup" aria-live="polite" aria-label="Setup ceremony output">Waiting to run setup…</div>
    </div>
    <div class="card" id="card-setup-math" style="display:none">
      <h2>Why This Works</h2>
      <div class="term" style="font-size:11px" aria-label="Mathematics explanation">
e(d_ID, U) = e(s·Q_ID, r·P)
           = e(Q_ID, P)^(s·r)
           = e(Q_ID, s·P)^r
           = e(Q_ID, P_pub)^r
           = g_ID^r

So H₂(e(d_ID, U)) = H₂(g_ID^r), which XORs back to M.

Security: Computing g_ID^r from U=r·P and public parameters requires
solving the Bilinear Diffie-Hellman Problem (BDH) in BLS12-381 — believed hard.
      </div>
    </div>
  </div>`;
}

function wireExhibit1() {
  document.getElementById('btn-setup')!.addEventListener('click', async () => {
    loading('term-setup');
    disableBtn('btn-setup', true);
    await new Promise((r) => setTimeout(r, 50));

    try {
      _system = ibeSetup(MSG_BYTES);
      const { P, Ppub } = _system.params;

      setHTML('term-setup', `
<span class="lbl-cyan">PRIVATE KEY GENERATOR — SETUP CEREMONY</span>
<span class="lbl-dim">───────────────────────────────────────</span>

Selecting BLS12-381 pairing-friendly groups…
  G1 = E(Fp),   48-byte compressed points
  G2 = E(Fp²),  96-byte compressed points
  G_T = Fp¹²,  576-byte elements
  r  = group order (255-bit prime)

Generator P ∈ G2:
  <span class="lbl-cyan">${hexG2(P)}…</span>

Generating master secret s ← random ∈ [1, r-1]
  Master secret s: <span class="censor">████████████████████████████████████████</span> (HIDDEN)

Computing P_pub = s · P ∈ G2:
  <span class="lbl-cyan">P_pub = ${hexG2(Ppub)}…</span>

Defining hash functions:
  H₁: identity → G1 point (RFC 9380 hash-to-curve)
  H₂: G_T element → 32 bytes (SHA-256)

<span class="lbl-green">✓ System parameters published: (G1, G2, G_T, e, r, P, P_pub)</span>
<span class="lbl-gold">  PKG holds s secretly. Master key: NEVER leaves the PKG.</span>
      `.trim());

      document.getElementById('card-setup-math')!.style.display = 'block';

      // Unlock other exhibits
      ['btn-encrypt', 'btn-wrongkey-run', 'btn-timelimit-run', 'btn-escrow-run'].forEach((id) => {
        disableBtn(id, false);
      });
    } catch (e) {
      setHTML('term-setup', `<span class="lbl-red">ERROR: ${e}</span>`);
    }

    disableBtn('btn-setup', false);
  });
}

// ─── Exhibit 2: Encrypt to Stranger ──────────────────────────────────────────

function exhibit2(): string {
  return `
  <div class="panel" id="panel-encrypt" role="tabpanel" aria-labelledby="tab-encrypt" aria-hidden="true">
    <div class="card">
      <h2>Exhibit 2 — Encrypt Before Recipient Exists</h2>
      <p style="color:var(--text-dim);margin-bottom:14px;font-size:13px;">
        Alice encrypts a message to Bob's email — before Bob has enrolled with the PKG.
        Bob can decrypt once the PKG issues his private key.
      </p>
      <div class="field-row">
        <label for="enc-identity">Recipient Identity (any string — email, role, phone…)</label>
        <input id="enc-identity" value="bob@newcompany.com" autocomplete="off" />
      </div>
      <div class="field-row">
        <label for="enc-message">Message (max 32 bytes)</label>
        <input id="enc-message" value="Q2 financials strictly confidential" autocomplete="off" />
      </div>
      <button class="btn btn-primary" id="btn-encrypt" disabled aria-disabled="true">🔒 Encrypt</button>
      <div class="term" id="term-encrypt" aria-live="polite" aria-label="Encryption output">Run Setup first (Exhibit 1).</div>
    </div>
    <div class="card" id="card-enroll" style="display:none">
      <h2>Bob Enrolls with PKG</h2>
      <button class="btn btn-gold" id="btn-enroll">👤 Bob Enrolls — PKG Extracts Key</button>
      <div class="term" id="term-enroll" aria-live="polite" aria-label="Enrollment output">Waiting…</div>
    </div>
    <div class="card" id="card-decrypt2" style="display:none">
      <h2>Bob Decrypts</h2>
      <button class="btn btn-primary" id="btn-decrypt2">🔓 Decrypt</button>
      <div class="term" id="term-decrypt2" aria-live="polite" aria-label="Decryption output">Waiting…</div>
    </div>
  </div>`;
}

let _ct2: IBECiphertext | null = null;
let _bobKey2: InstanceType<typeof bls.G1.Point> | null = null;

function wireExhibit2() {
  document.getElementById('btn-encrypt')!.addEventListener('click', async () => {
    const sys = getSystem();
    const identity = getVal('enc-identity');
    const msg = getVal('enc-message');
    loading('term-encrypt');

    await new Promise((r) => setTimeout(r, 50));
    try {
      const padded = pad(msg, MSG_BYTES);
      _ct2 = await encrypt(padded, identity, sys.params);

      setHTML('term-encrypt', `
<span class="lbl-cyan">ALICE ENCRYPTS TO "${identity}"</span>
<span class="lbl-dim">──────────────────────────────────────────</span>

Compute Q_ID = H₁("${identity}") ∈ G1:
  <span class="lbl-cyan">Q_ID = [hash-to-curve result] (via RFC 9380)</span>

Pick random r ← [1, r-1]:
  r = <span class="censor">████████████████</span> (discarded after encryption)

U = r · P ∈ G2  (96 bytes):
  <span class="lbl-magenta">U = ${hexG2(_ct2.U)}…</span>

g_ID = e(Q_ID, P_pub) ∈ G_T
V = M ⊕ H₂(g_ID^r)

Ciphertext:
  <span class="lbl-magenta">U = ${hexG2(_ct2.U)}…</span>
  <span class="lbl-magenta">V = ${hex(_ct2.V)}…</span>

<span class="lbl-green">✓ Ciphertext ready. Bob doesn't exist yet — and it doesn't matter.</span>
      `.trim());

      document.getElementById('card-enroll')!.style.display = 'block';
    } catch (e) {
      setHTML('term-encrypt', `<span class="lbl-red">ERROR: ${e}</span>`);
    }
  });

  document.getElementById('btn-enroll')!.addEventListener('click', async () => {
    if (!_ct2) return;
    const sys = getSystem();
    loading('term-enroll');
    await new Promise((r) => setTimeout(r, 50));

    _bobKey2 = extract(_ct2.identity, sys.masterKey);
    setHTML('term-enroll', `
<span class="lbl-gold">BOB ENROLLS WITH PKG</span>
<span class="lbl-dim">──────────────────────────────────────</span>

PKG authenticates Bob (out-of-band).
PKG computes: d_ID = s · H₁("${_ct2.identity}") ∈ G1

Bob's private key:
  <span class="lbl-gold">d_ID = ${hexG1(_bobKey2)}…</span>

<span class="lbl-green">✓ Private key delivered to Bob securely.</span>
<span class="lbl-dim">  Note: PKG authentication is NOT cryptographic here —</span>
<span class="lbl-dim">  it's trust in the PKG's identity verification process.</span>
    `.trim());

    document.getElementById('card-decrypt2')!.style.display = 'block';
  });

  document.getElementById('btn-decrypt2')!.addEventListener('click', async () => {
    if (!_ct2 || !_bobKey2) return;
    const sys = getSystem();
    loading('term-decrypt2');
    await new Promise((r) => setTimeout(r, 50));

    const decrypted = await decrypt(_ct2, _bobKey2, sys.params);
    const msg = unpad(decrypted);

    setHTML('term-decrypt2', `
<span class="lbl-gold">BOB DECRYPTS</span>
<span class="lbl-dim">──────────────────────────────────────</span>

Compute e(d_ID, U) ∈ G_T…
M = V ⊕ H₂(e(d_ID, U))

Decrypted message:
<span class="lbl-green">✓ "${msg}"</span>

<span class="lbl-dim">The mathematics:
  e(d_ID, U) = e(s·Q_ID, r·P)
             = e(Q_ID, P_pub)^r
             = g_ID^r

  H₂(e(d_ID, U)) = H₂(g_ID^r)  ← same mask as encryption
  V ⊕ that mask = M              ← original message recovered</span>
    `.trim());
  });
}

// ─── Exhibit 3: Wrong Key = Garbage ──────────────────────────────────────────

function exhibit3(): string {
  return `
  <div class="panel" id="panel-wrongkey" role="tabpanel" aria-labelledby="tab-wrongkey" aria-hidden="true">
    <div class="card">
      <h2>Exhibit 3 — Wrong Identity = Garbage</h2>
      <p style="color:var(--text-dim);margin-bottom:14px;font-size:13px;">
        Eve intercepts Alice's ciphertext. Eve has her OWN private key from the PKG.
        But encrypting to Alice means only Alice's key can decrypt it.
      </p>
      <div class="field-row">
        <label for="wk-alice">Alice's Identity</label>
        <input id="wk-alice" value="alice@example.com" autocomplete="off" />
      </div>
      <div class="field-row">
        <label for="wk-eve">Eve's Identity (her own, different key)</label>
        <input id="wk-eve" value="eve@example.com" autocomplete="off" />
      </div>
      <div class="field-row">
        <label for="wk-message">Message (encrypted to Alice)</label>
        <input id="wk-message" value="Q2 financials strictly confidential" autocomplete="off" />
      </div>
      <button class="btn btn-primary" id="btn-wrongkey-run" disabled aria-disabled="true">▶ Run Demonstration</button>
      <div class="cols-2" style="margin-top:14px">
        <div>
          <div style="color:var(--green);font-size:11px;margin-bottom:6px;text-transform:uppercase;" aria-hidden="true">Alice Decrypts (correct key)</div>
          <div class="term" id="term-wk-alice" aria-live="polite" aria-label="Alice decryption output">Waiting…</div>
        </div>
        <div>
          <div style="color:var(--red);font-size:11px;margin-bottom:6px;text-transform:uppercase;" aria-hidden="true">Eve Decrypts (wrong key)</div>
          <div class="term" id="term-wk-eve" aria-live="polite" aria-label="Eve decryption output (wrong key)">Waiting…</div>
        </div>
      </div>
    </div>
  </div>`;
}

function wireExhibit3() {
  document.getElementById('btn-wrongkey-run')!.addEventListener('click', async () => {
    const sys = getSystem();
    const aliceId = getVal('wk-alice');
    const eveId = getVal('wk-eve');
    const msgStr = getVal('wk-message');

    loading('term-wk-alice');
    loading('term-wk-eve');
    disableBtn('btn-wrongkey-run', true);
    await new Promise((r) => setTimeout(r, 50));

    try {
      const padded = pad(msgStr, MSG_BYTES);
      const ct = await encrypt(padded, aliceId, sys.params);

      const aliceKey = extract(aliceId, sys.masterKey);
      const eveKey = extract(eveId, sys.masterKey);

      const [aliceDecrypted, eveDecrypted] = await Promise.all([
        decrypt(ct, aliceKey, sys.params),
        decryptWrongKey(ct, eveKey, sys.params),
      ]);

      const aliceMsg = unpad(aliceDecrypted);
      const eveBytes = hex(eveDecrypted);

      setHTML('term-wk-alice', `
d_ID = s · H₁("${aliceId}")
e(d_ID, U) ∈ G_T ← correct pairing

V ⊕ H₂(correct GT) =

<span class="lbl-green">✓ "${aliceMsg}"</span>
    `.trim());

      setHTML('term-wk-eve', `
d_ID = s · H₁("${eveId}")
e(d_ID, U) ∈ G_T ← DIFFERENT pairing

V ⊕ H₂(wrong GT) =

<span class="lbl-red">✗ ${eveBytes}</span>
<span class="lbl-dim">  (random-looking garbage — not the message)</span>
    `.trim());
    } catch (e) {
      setHTML('term-wk-alice', `<span class="lbl-red">ERROR: ${e}</span>`);
      setHTML('term-wk-eve', `<span class="lbl-red">ERROR: ${e}</span>`);
    }

    disableBtn('btn-wrongkey-run', false);
  });
}

// ─── Exhibit 4: Time-Limited Capabilities ────────────────────────────────────

function exhibit4(): string {
  const tomorrow = new Date(Date.now() + 86400000).toISOString().slice(0, 10);
  return `
  <div class="panel" id="panel-timelimit" role="tabpanel" aria-labelledby="tab-timelimit" aria-hidden="true">
    <div class="card">
      <h2>Exhibit 4 — Time-Limited Capabilities</h2>
      <p style="color:var(--text-dim);margin-bottom:14px;font-size:13px;">
        The identity string itself encodes policy. Encrypt to "email || date"
        and implement a PKG policy that only extracts keys for today's date.
        The result: messages that can only be decrypted on a specific day.
      </p>
      <div class="field-row">
        <label for="tl-email">Recipient Email</label>
        <input id="tl-email" value="bob@example.com" autocomplete="off" />
      </div>
      <div class="field-row">
        <label for="tl-date">Valid Date (YYYY-MM-DD) — baked into the identity string</label>
        <input id="tl-date" type="date" value="${tomorrow}" />
      </div>
      <div class="field-row">
        <label for="tl-message">Message</label>
        <input id="tl-message" value="Embargo: release Q3 results on this date only" autocomplete="off" />
      </div>
      <button class="btn btn-primary" id="btn-timelimit-run" disabled aria-disabled="true">▶ Run Scenario</button>
      <div class="term" id="term-timelimit" aria-live="polite" aria-label="Time-limited scenario output">Run Setup first (Exhibit 1).</div>
    </div>
    <div class="card">
      <h2>Real-World Applications</h2>
      <div class="term" style="font-size:11px" aria-label="Real-world application examples">
Identity string as policy expression:
  "bob@example.com || 2026-05-15"    ← dated private key
  "alice@corp.com || project-x"      ← project-scoped access
  "reports@org.com || Q4-2026"       ← quarterly release window
  "doc-12345 || read-until-2027"     ← document expiry

The PKG's extraction policy becomes the access-control mechanism.
No separate ACL infrastructure needed — just identity strings.

Applications:
  • Document embargo (release at a specific date)
  • Emergency access windows
  • Broadcast encryption to subscribers "as of date X"
  • Time-locked per-message tokens
      </div>
    </div>
  </div>`;
}

function wireExhibit4() {
  document.getElementById('btn-timelimit-run')!.addEventListener('click', async () => {
    const sys = getSystem();
    const email = getVal('tl-email');
    const date = getVal('tl-date');
    const msgStr = getVal('tl-message');

    loading('term-timelimit');
    await new Promise((r) => setTimeout(r, 50));

    const result = await simulateTimeLimitedMessage(email, date, msgStr, sys);

    setHTML('term-timelimit', `
<span class="lbl-cyan">IDENTITY STRING: "${result.identity}"</span>
<span class="lbl-dim">───────────────────────────────────────────────</span>

Alice encrypts to identity = "${result.identity}"
  Ciphertext sealed to that specific string.
  <span class="lbl-magenta">U = ${hexG2(result.ciphertext.U)}…</span>
  <span class="lbl-magenta">V = ${hex(result.ciphertext.V)}…</span>

Bob requests private key for "${result.identity}":
  PKG policy: only extract keys for matching identities.
  <span class="lbl-gold">d_ID = s · H₁("${result.identity}")</span>
  Bob decrypts:
  <span class="${result.decryptedSuccessfully ? 'lbl-green' : 'lbl-red'}">${result.decryptedSuccessfully ? '✓ Decryption successful — correct identity key' : '✗ Decryption failed'}</span>

Bob tries key for "WRONG DATE" identity:
  <span class="${result.wrongDateFails ? 'lbl-green' : 'lbl-red'}">${result.wrongDateFails ? '✓ Wrong date → key mismatch → garbage output (as expected)' : '✗ Unexpected: wrong key succeeded'}</span>

<span class="lbl-dim">The identity string IS the access policy.
No separate ACL, no certificate, no PKI — just identity strings.</span>
    `.trim());
  });
}

// ─── Exhibit 5: PKG Escrow Tradeoff ──────────────────────────────────────────

function exhibit5(): string {
  return `
  <div class="panel" id="panel-escrow" role="tabpanel" aria-labelledby="tab-escrow" aria-hidden="true">
    <div class="escrow-box" role="alert" aria-label="Central trust warning">
      <div class="escrow-title">⚠ CENTRAL TRUST: The PKG holds master secret s</div>
      Because d_ID = s · H₁(ID), the PKG can compute ANY user's private key at any time.
      The PKG can decrypt every message sent in the system. This is architectural — not a bug.
    </div>
    <div class="card">
      <h2>Exhibit 5 — The PKG Escrow Tradeoff</h2>
      <div class="field-row">
        <label for="escrow-identity">Target Identity (PKG will derive this person's key)</label>
        <input id="escrow-identity" value="ceo@megacorp.com" autocomplete="off" />
      </div>
      <div class="field-row">
        <label for="escrow-message">Secret Message (encrypted to target)</label>
        <input id="escrow-message" value="Board meeting: vote to oust the CFO Thursday" autocomplete="off" />
      </div>
      <button class="btn btn-danger" id="btn-escrow-run" disabled aria-disabled="true">🔑 PKG Decrypts Everything</button>
      <div class="term" id="term-escrow" aria-live="polite" aria-label="Escrow demonstration output">Run Setup first (Exhibit 1).</div>
    </div>
    <div class="card">
      <h2>The Tradeoff</h2>
      <div class="cols-2">
        <div>
          <h3 style="color:var(--green)">Feature (for compliance)</h3>
          <div class="term" style="font-size:11px">
• Court-ordered decryption
  architecturally supported
• No "going dark" problem
• Compliance audits possible
• Regulatory key escrow
• Enterprise message archival
• Legal discovery workflows
          </div>
        </div>
        <div>
          <h3 style="color:var(--red)">Vulnerability (for privacy)</h3>
          <div class="term" style="font-size:11px">
• PKG insider threat
• Nation-state compelled
  disclosure
• Single point of failure
• No forward secrecy
• No cryptographic user
  privacy guarantees
          </div>
        </div>
      </div>
    </div>
    <div class="card">
      <h2>Mitigations (BasicIdent has NONE of these)</h2>
      <div class="term" style="font-size:11px">
Hierarchical IBE (HIBE):
  → Distribute key extraction across a tree of PKGs
  → Each PKG knows only a subtree of identities

Threshold IBE:
  → Master secret split among t-of-n PKGs
  → Extraction requires threshold cooperation (e.g. 3-of-5)

Distributed PKG:
  → Multiple independent PKGs issue partial keys
  → User combines partial keys → actual private key
  → No single PKG can impersonate users alone

The 2001 BasicIdent scheme has NONE of these.
Every production IBE deployment uses one or more.
      </div>
    </div>
    <div class="cross-links">
      <h3>Related Labs</h3>
      <a href="../crypto-lab-pairing-gate/">→ crypto-lab-pairing-gate — BLS signatures on BLS12-381 (same curve)</a>
      <a href="../crypto-lab-frost-threshold/">→ crypto-lab-frost-threshold — FROST threshold signatures</a>
      <a href="../crypto-lab-shamir-gate/">→ crypto-lab-shamir-gate — Shamir secret sharing</a>
      <a href="../crypto-lab-zk-proof-lab/">→ crypto-lab-zk-proof-lab — zero-knowledge proofs (no escrow)</a>
      <a href="../crypto-lab-blind-sign/">→ crypto-lab-blind-sign — Chaum blinding (escrow-free)</a>
      <a href="../crypto-lab-ratchet-wire/">→ crypto-lab-ratchet-wire — forward-secret messaging (stronger guarantee)</a>
    </div>
  </div>`;
}

function wireExhibit5() {
  document.getElementById('btn-escrow-run')!.addEventListener('click', async () => {
    const sys = getSystem();
    const identity = getVal('escrow-identity');
    const msgStr = getVal('escrow-message');

    loading('term-escrow');
    await new Promise((r) => setTimeout(r, 50));

    const result = await demonstrateKeyEscrow(msgStr, identity, sys);

    setHTML('term-escrow', `
<span class="lbl-red">PKG EXERCISES MASTER KEY — KEY ESCROW DEMONSTRATION</span>
<span class="lbl-dim">────────────────────────────────────────────────────</span>

Target identity: "${identity}"

User encrypts message to "${identity}":
  Ciphertext looks secure to outside observer.

PKG computes:
  Q_ID = H₁("${identity}") ∈ G1
  d_ID = s · Q_ID          ← PKG uses master secret s
  d_ID = <span class="lbl-gold">[derived, same key the user would receive]</span>

PKG applies d_ID to decrypt:
  M = V ⊕ H₂(e(d_ID, U))

Result:
<span class="lbl-${result.pkgCanDecrypt ? 'red' : 'green'}">${result.pkgCanDecrypt ? '⚠ PKG successfully decrypted: "' + msgStr + '"' : '✓ PKG could not decrypt (unexpected)'}</span>

<span class="lbl-amber">${result.explanation}</span>

<span class="lbl-dim">This is why IBE requires absolute trust in the PKG.
The escrow is a design decision — not an accident.</span>
    `.trim());
  });
}
