import './style.css';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import {
  setup as ibeSetup,
  extract,
  encrypt,
  decrypt,
  decryptWrongKey,
  demonstrateBilinearity,
  verifyPairingIdentity,
  type IBESystem,
  type IBECiphertext,
} from './ibe.ts';
import {
  setupHIBE,
  keyGenHIBE,
  delegateHIBE,
  encryptHIBE,
  decryptHIBE,
  recoverHIBESecret,
  isIdentityPrefix,
} from './hibe.ts';
import { hashToG1, gtToBytes, hashGTtoBytes, pairing, gtEquals } from './pairing.ts';
import { demonstrateKeyEscrow } from './scenarios.ts';
import { byteColor } from './palette.ts';
import {
  CLE_CONTEXT,
  CLE_MESSAGE_MAX_BYTES,
  decryptCLE,
  decryptCLETeaching,
  decryptPKI,
  encryptCLE,
  encryptPKI,
  generateCertificateAuthority,
  generateUserKeyPair,
  issueCertificate,
  issuePartialPrivateKey,
  setupCLE,
  typeIAttempt,
  typeIIAttempt,
} from './certificateless.ts';

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

// A GT element is a 576-byte Fp12 value. Show a short fingerprint of its
// canonical serialization so two elements can be compared by eye.
function hexGT(gt: ReturnType<typeof bls.pairing>): string {
  return hex(gtToBytes(gt), 16);
}

function bigToBytes(n: bigint): Uint8Array {
  let h = n.toString(16);
  if (h.length % 2) h = '0' + h;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
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

/**
 * What `pad` will ACTUALLY encrypt for a given input string. BasicIdent here
 * has a fixed 32-byte message space, so anything longer is silently cut — and
 * a success test written as `unpad(plaintext) === whatTheUserTyped` then reads
 * as a decryption FAILURE on every over-long input, including several of this
 * page's own defaults. Verdicts compare against this instead.
 */
function fitted(msg: string, n: number): string {
  return unpad(pad(msg, n));
}

/** Visible note when the message space truncated the user's input. */
function truncNote(msg: string, n: number): string {
  const kept = fitted(msg, n);
  if (kept === msg) return '';
  return `\n<span class="lbl-amber">  Note: BasicIdent's message space here is exactly ${n} bytes, so only
  "${escapeHtml(kept)}" was encrypted — the rest of your input was cut before encryption.</span>`;
}

function setHTML(id: string, html: string) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = html;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
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

// ─── Teaching helpers (visualisation only — never touch the crypto) ──────────

// `byteColor` — the deterministic byte→colour map — lives in ./palette.ts,
// where it can be unit-tested against the 3:1 floor every cell has to clear
// against the grid gap (WCAG 1.4.11). It is a pure display function of the real
// byte values; it invents nothing.

function hexByte(b: number): string {
  return b.toString(16).padStart(2, '0');
}

// Render a row of N bytes as an accessible colour grid. Each cell carries its
// hex value in title + aria-label, so meaning never rests on colour alone.
function byteGrid(
  bytes: Uint8Array,
  opts: { hidden?: boolean } = {}
): string {
  const cells = Array.from(bytes)
    .map((b, i) => {
      const label = `byte ${i}: 0x${hexByte(b)}`;
      const hide = opts.hidden ? ' mask-hidden' : '';
      return `<span class="byte-cell${hide}" role="img" aria-label="${label}" title="${label}" style="background:${byteColor(
        b
      )}" data-byte="${i}"></span>`;
    })
    .join('');
  return `<div class="byte-grid" role="group" aria-label="${bytes.length} bytes, one coloured cell each">${cells}</div>`;
}

// The XOR masking visualiser — the single most important "aha". Three real
// byte rows: the plaintext M, the pairing-derived mask H₂(g_ID^r), and their
// XOR V. Every cell's colour is a pure function of its real byte, so identical
// bytes look identical and the learner literally watches M become V.
//
// `mode` = 'encrypt' (M ⊕ mask = V) or 'decrypt' (V ⊕ mask = M).
// `scrambled` marks Eve's wrong-mask run so the result row reads as garbage.
function xorViz(
  top: Uint8Array,      // encrypt: M     | decrypt: V
  mask: Uint8Array,     // H₂(pairing)
  result: Uint8Array,   // encrypt: V     | decrypt: M
  opts: {
    topLabel: string;
    topSub: string;
    maskLabel: string;
    maskSub: string;
    resultLabel: string;
    resultSub: string;
    id: string;         // unique id so we can animate this instance
    revealMask?: boolean; // start with mask hidden, reveal on play
  }
): string {
  return `
  <div class="xor-viz" id="${opts.id}" role="group" aria-label="Byte-by-byte XOR: ${opts.topLabel} XOR mask equals ${opts.resultLabel}">
    <div class="xor-row">
      <div class="xor-row-label">${opts.topLabel}<span class="xr-sub">${opts.topSub}</span></div>
      ${byteGrid(top, { hidden: false })}
    </div>
    <div class="op-symbol" aria-hidden="true">⊕  XOR with the pairing-derived mask</div>
    <div class="xor-row">
      <div class="xor-row-label">${opts.maskLabel}<span class="xr-sub">${opts.maskSub}</span></div>
      ${byteGrid(mask, { hidden: !!opts.revealMask })}
    </div>
    <div class="op-symbol" aria-hidden="true">=  result</div>
    <div class="xor-row">
      <div class="xor-row-label">${opts.resultLabel}<span class="xr-sub">${opts.resultSub}</span></div>
      ${byteGrid(result, { hidden: !!opts.revealMask })}
    </div>
    <div class="xor-legend">
      Each square is one byte; its colour is a deterministic function of the byte value, so identical bytes look identical. Hover a square to read its hex. ${
        opts.revealMask
          ? 'Watch the mask and result fill in cell by cell.'
          : ''
      }
    </div>
  </div>`;
}

// Animate the mask + result rows filling in, cell by cell. Honest: the cells
// were already rendered with their true bytes; we only reveal them in sequence.
function animateXor(id: string): void {
  const root = document.getElementById(id);
  if (!root) return;
  const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  const hidden = Array.from(
    root.querySelectorAll<HTMLElement>('.byte-cell.mask-hidden')
  );
  if (reduce) {
    hidden.forEach((c) => c.classList.remove('mask-hidden'));
    return;
  }
  hidden.forEach((cell, i) => {
    setTimeout(() => {
      cell.classList.remove('mask-hidden');
      cell.classList.add('pop');
    }, Math.min(i, 40) * 22);
  });
}

// A public / secret / master-secret value chip using the fixed convention.
// kind: 'public' | 'secret' | 'master'
function chip(kind: 'public' | 'secret' | 'master', text: string): string {
  const map = {
    public: { ic: '◇', cls: 'v-public', sr: 'public value, anyone can compute' },
    secret: { ic: '🔒', cls: 'v-secret', sr: 'private value, requires the master secret' },
    master: { ic: '⛔', cls: 'v-master', sr: 'master secret, never leaves the PKG' },
  } as const;
  const m = map[kind];
  return `<span class="vchip ${m.cls}"><span class="vchip-ic" aria-hidden="true">${m.ic}</span><span class="sr-only">${m.sr}: </span>${text}</span>`;
}

// Full 576-byte GT inspector: scans EVERY byte of both serialisations, reports
// the exact mismatch count, and shows the raw dump colour-coded match/diff so
// the learner can confirm the "all 576 bytes match" claim instead of trusting
// a 16-byte fingerprint. Honest by construction: it diffs the real bytes.
function gtInspector(a: Uint8Array, b: Uint8Array, labelId: string): string {
  const n = Math.min(a.length, b.length);
  let mismatches = 0;
  const rowsA: string[] = [];
  for (let i = 0; i < a.length; i++) {
    const same = i < n && a[i] === b[i];
    if (!same) mismatches++;
    const cls = same ? 'gd-match' : 'gd-diff';
    rowsA.push(`<span class="${cls}">${hexByte(a[i])}</span>`);
  }
  const dump = rowsA.join('');
  const ok = mismatches === 0 && a.length === b.length;
  const summary = ok
    ? `<span class="lbl-green">✓ Scanned all ${a.length} bytes — <strong>0 mismatches</strong>.</span> Both sides serialise to byte-identical Fp12 elements.`
    : `<span class="lbl-red">✗ ${mismatches} of ${a.length} bytes differ.</span>`;
  return `
    <details class="gt-inspect">
      <summary aria-controls="${labelId}">Show full ${a.length} bytes and verify every one</summary>
      <div id="${labelId}">
        <div class="gt-diff-summary">${summary}</div>
        <div class="gt-hex-dump" tabindex="0" role="region" aria-label="Full ${a.length}-byte comparison of both pairing results, green where they match">${dump}</div>
      </div>
    </details>`;
}

// ─── Protocol flow diagram ────────────────────────────────────────────────────
// A single persistent picture of who-holds-what and what-travels-where. Each
// button lights the arrow(s) for the step it runs, so the learner always knows
// where the current terminal dump sits in the whole protocol.

interface FlowStep {
  arrows: string[]; // data-arrow ids to light
  caption: string;  // may contain safe inline HTML we control
}

const FLOW_STEPS: Record<string, FlowStep> = {
  setup: {
    arrows: ['pub'],
    caption:
      '<strong>Setup.</strong> The PKG picks master secret <em>s</em> and publishes P_pub = s·P. These parameters are public — everyone can now encrypt to any identity.',
  },
  encrypt: {
    arrows: ['u', 'pairA'],
    caption:
      '<strong>Encrypt.</strong> Alice picks random <em>r</em>, sends U = r·P, and masks her message with e(Q_ID, P_pub)^r — a point on the shared G_T node. Bob need not exist yet.',
  },
  extract: {
    arrows: ['dID'],
    caption:
      '<strong>Extract.</strong> The PKG uses <em>s</em> to issue Bob the private key d_ID = s·Q_ID. This is the only arrow that needs the master secret — and the reason the PKG can read everything.',
  },
  decrypt: {
    arrows: ['pairA', 'pairB'],
    caption:
      '<strong>Decrypt.</strong> Bob computes e(d_ID, U) and lands on the <em>exact same</em> G_T element Alice used. Same element → same mask → message recovered. Both pairings meet at the centre.',
  },
  escrow: {
    arrows: ['dID', 'pairB'],
    caption:
      '<strong>Escrow.</strong> Because the PKG holds <em>s</em>, it can issue d_ID for anyone and walk the recipient\'s exact decryption path. The topology itself grants it read access.',
  },
};

function flowDiagram(): string {
  // Coordinates: PKG top-centre, Alice left, Bob right, G_T node bottom-centre.
  return `
  <div class="flow-wrap" role="group" aria-labelledby="flow-h">
    <h2 id="flow-h">The Protocol at a Glance</h2>
    <p class="flow-caption" id="flow-caption" aria-live="polite">Run a step below and this map lights the matching arrow — so you always see where that terminal output sits in the whole scheme. <span class="lbl-dim">Green = anyone can compute · gold = needs the master secret.</span></p>
    <svg class="flow-svg" id="flow-svg" viewBox="0 0 640 330" role="img" aria-label="Diagram of the IBE protocol: a PKG at top publishes public parameters to Alice and issues a private key to Bob; Alice sends a ciphertext to Bob; both sides' pairings meet at a shared G_T element in the centre.">
      <defs>
        <marker id="ah-pub" markerWidth="9" markerHeight="9" refX="7" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 z" class="arrow-head public" data-head="pub"/></marker>
        <marker id="ah-u" markerWidth="9" markerHeight="9" refX="7" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 z" class="arrow-head public" data-head="u"/></marker>
        <marker id="ah-dID" markerWidth="9" markerHeight="9" refX="7" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 z" class="arrow-head secret" data-head="dID"/></marker>
        <marker id="ah-pA" markerWidth="9" markerHeight="9" refX="7" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 z" class="arrow-head public" data-head="pairA"/></marker>
        <marker id="ah-pB" markerWidth="9" markerHeight="9" refX="7" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 z" class="arrow-head secret" data-head="pairB"/></marker>
      </defs>

      <!-- Actor: PKG -->
      <g>
        <rect class="actor-box" x="248" y="14" width="144" height="52" rx="6"/>
        <text class="actor-label" x="320" y="36" text-anchor="middle">PKG</text>
        <text class="actor-role" x="320" y="53" text-anchor="middle">holds master s</text>
      </g>
      <!-- Actor: Alice -->
      <g>
        <rect class="actor-box" x="24" y="150" width="150" height="52" rx="6"/>
        <text class="actor-label" x="99" y="172" text-anchor="middle">Alice</text>
        <text class="actor-role" x="99" y="189" text-anchor="middle">sender</text>
      </g>
      <!-- Actor: Bob -->
      <g>
        <rect class="actor-box" x="466" y="150" width="150" height="52" rx="6"/>
        <text class="actor-label" x="541" y="172" text-anchor="middle">Bob</text>
        <text class="actor-role" x="541" y="189" text-anchor="middle">recipient (identity)</text>
      </g>
      <!-- Shared G_T node -->
      <g>
        <rect class="gt-node" id="flow-gt" x="256" y="256" width="128" height="52" rx="26"/>
        <text class="gt-node-label" x="320" y="279" text-anchor="middle">G_T element</text>
        <text class="actor-role" x="320" y="296" text-anchor="middle">the shared mask</text>
      </g>

      <!-- Arrow: s·P published  (PKG -> Alice) -->
      <path class="arrow public" data-arrow="pub" d="M250,52 C170,70 110,110 100,146" marker-end="url(#ah-pub)"/>
      <text class="arrow-label public" data-label="pub" x="120" y="104" text-anchor="middle">P_pub = s·P (public)</text>

      <!-- Arrow: U = r·P  (Alice -> Bob) -->
      <path class="arrow public" data-arrow="u" d="M176,176 L462,176" marker-end="url(#ah-u)"/>
      <text class="arrow-label public" data-label="u" x="320" y="168" text-anchor="middle">U = r·P  (ciphertext)</text>

      <!-- Arrow: d_ID issued  (PKG -> Bob) -->
      <path class="arrow secret" data-arrow="dID" d="M392,50 C480,70 540,108 545,146" marker-end="url(#ah-dID)"/>
      <text class="arrow-label secret" data-label="dID" x="520" y="104" text-anchor="middle">d_ID = s·Q_ID (secret)</text>

      <!-- Arrow: Alice's pairing g_ID^r  (Alice -> G_T) -->
      <path class="arrow public" data-arrow="pairA" d="M120,204 C170,244 220,262 252,272" marker-end="url(#ah-pA)"/>
      <text class="arrow-label public" data-label="pairA" x="150" y="248" text-anchor="middle">g_ID^r</text>

      <!-- Arrow: Bob's pairing e(d_ID,U)  (Bob -> G_T) -->
      <path class="arrow secret" data-arrow="pairB" d="M520,204 C470,244 420,262 388,272" marker-end="url(#ah-pB)"/>
      <text class="arrow-label secret" data-label="pairB" x="490" y="248" text-anchor="middle">e(d_ID, U)</text>
    </svg>
  </div>`;
}

// Light the arrows for a given step and update the caption. Idempotent.
function highlightFlow(step: keyof typeof FLOW_STEPS): void {
  const svg = document.getElementById('flow-svg');
  const cap = document.getElementById('flow-caption');
  if (!svg) return;
  const spec = FLOW_STEPS[step];
  if (!spec) return;
  const lit = new Set(spec.arrows);
  svg.querySelectorAll('[data-arrow]').forEach((el) => {
    el.classList.toggle('lit', lit.has(el.getAttribute('data-arrow') || ''));
  });
  svg.querySelectorAll('[data-label]').forEach((el) => {
    el.classList.toggle('lit', lit.has(el.getAttribute('data-label') || ''));
  });
  svg.querySelectorAll('[data-head]').forEach((el) => {
    el.classList.toggle('lit', lit.has(el.getAttribute('data-head') || ''));
  });
  // GT node glows whenever a pairing arrow is active.
  const gt = document.getElementById('flow-gt');
  if (gt) gt.classList.toggle('lit', lit.has('pairA') || lit.has('pairB'));
  if (cap && spec.caption) cap.innerHTML = spec.caption;
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
    <header class="cl-hero">
      <div class="cl-hero-main">
        <h1 class="cl-hero-title">IBE Gate</h1>
        <p class="cl-hero-sub">Boneh-Franklin BasicIdent · 2001 · BLS12-381 pairing</p>
        <p class="cl-hero-desc">Encrypt a message to any email address — no certificate, no enrollment — then watch the PKG derive that identity's private key on demand.</p>
      </div>
      <aside class="cl-hero-why" aria-label="Why it matters">
        <span class="cl-hero-why-label">WHY IT MATTERS</span>
        <p class="cl-hero-why-text">IBE strips away the certificate plumbing that makes public-key crypto hard to deploy. The catch: the key-generating server can derive anyone's private key, so it can read every message — the escrow tradeoff you must weigh.</p>
      </aside>
    </header>

    <div class="warning-box" role="note" aria-label="Security note">
      <div class="warning-title">⚠ IND-CPA ONLY — NOT IND-CCA</div>
      This demo implements BasicIdent from Boneh-Franklin 2001 §4.1.
      BasicIdent is semantically secure (IND-CPA) but NOT IND-CCA secure.
      An active adversary can perform ciphertext-malleability attacks.
      Production systems use FullIdent (§4.2) with the Fujisaki-Okamoto transform.
    </div>

    ${flowDiagram()}

    <div class="value-legend" role="group" aria-label="Public versus secret value key">
      <span class="vl-item">${chip('public', 'Q_ID, U, P_pub')}</span>
      <span class="vl-item vl-note">Derivable by anyone from public data.</span>
      <span class="vl-item">${chip('secret', 'd_ID')}</span>
      <span class="vl-item vl-note">Needs the master secret s.</span>
      <span class="vl-item">${chip('master', 's')}</span>
      <span class="vl-item vl-note">Never leaves the PKG.</span>
    </div>

    <nav aria-label="Exhibits" class="tab-nav" role="tablist">
      <button class="tab-btn" role="tab" aria-selected="true"  aria-controls="panel-setup"     id="tab-setup"     data-tab="setup">1 · Setup Ceremony</button>
      <button class="tab-btn" role="tab" aria-selected="false" aria-controls="panel-encrypt"   id="tab-encrypt"   data-tab="encrypt">2 · Encrypt to Stranger</button>
      <button class="tab-btn" role="tab" aria-selected="false" aria-controls="panel-wrongkey"  id="tab-wrongkey"  data-tab="wrongkey">3 · Wrong Key = Garbage</button>
      <button class="tab-btn" role="tab" aria-selected="false" aria-controls="panel-timelimit" id="tab-timelimit" data-tab="timelimit">4 · Time-Limited</button>
      <button class="tab-btn" role="tab" aria-selected="false" aria-controls="panel-escrow"    id="tab-escrow"    data-tab="escrow">5 · PKG Escrow Tradeoff</button>
      <button class="tab-btn" role="tab" aria-selected="false" aria-controls="panel-hibe"      id="tab-hibe"      data-tab="hibe">6 · HIBE Delegation</button>
      <button class="tab-btn" role="tab" aria-selected="false" aria-controls="panel-cle"       id="tab-cle"       data-tab="cle">7 · PKI, IBE, or CLE?</button>
    </nav>

    <main id="main-content">
      ${exhibit1()}
      ${exhibit2()}
      ${exhibit3()}
      ${exhibit4()}
      ${exhibit5()}
      ${exhibit6()}
      ${exhibit7()}
    </main>
<footer style="margin-top:3rem;padding:2rem 1rem;border-top:1px solid rgba(128,128,128,.25);text-align:center;font-size:.85rem;line-height:1.9;font-family:ui-monospace,Menlo,Consolas,monospace">
  <div><strong>Related demos:</strong> <a href="https://systemslibrarian.github.io/crypto-lab-pairing-gate/" style="color:var(--cyan)">pairing-gate</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-iron-letter/" style="color:var(--cyan)">iron-letter</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-pki-chain/" style="color:var(--cyan)">pki-chain</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-envelope-kms/" style="color:var(--cyan)">envelope-kms</a></div>
  <div style="margin-top:.5rem"><a href="https://github.com/systemslibrarian/crypto-lab-ibe-gate" style="color:var(--cyan)">Source on GitHub</a> &middot; <a href="https://crypto-lab.systemslibrarian.dev/" style="color:var(--cyan)">More crypto-lab demos</a></div>
  <div style="margin-top:.75rem;color:var(--text-dim)">&ldquo;So whether you eat or drink or whatever you do, do it all for the glory of God.&rdquo; &mdash; 1 Corinthians 10:31</div>
</footer>
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

  wireExhibit1();
  wireExhibit2();
  wireExhibit3();
  wireExhibit4();
  wireExhibit5();
  wireExhibit6();
  wireExhibit7();
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
      <details class="gt-inspect" style="margin-bottom:12px">
        <summary>New to pairings? Read this first (30-second primer)</summary>
        <div style="font-size:12.5px;color:var(--text-dim);line-height:1.6;padding:4px 2px 0">
          A <strong>group</strong> here is just a set of points you can add together.
          BLS12-381 gives us three of them:
          <strong>G1</strong> and <strong>G2</strong> are two curves whose points we add,
          and <strong>G_T</strong> is a set of big numbers we multiply.
          A <strong>pairing</strong> <code>e</code> is a function that eats one point
          from G1 and one from G2 and spits out a number in G_T — with one magic property:
          a scalar multiplied into either input slides into the <em>exponent</em> of the
          output. That single property (bilinearity) is the whole engine below.
          <strong>Hash-to-curve</strong> (RFC 9380) is how we turn an arbitrary string
          like an email into a genuine, uniformly-random G1 point — that is what makes an
          identity usable as a public key.
        </div>
      </details>
      <button class="btn btn-primary" id="btn-setup">▶ Run Setup</button>
      <div class="term" id="term-setup" role="log" aria-live="polite" aria-label="Setup ceremony output">Waiting to run setup…</div>
    </div>
    <div class="card">
      <h2>First, The One Magic Property</h2>
      <p style="color:var(--text-dim);margin-bottom:14px;font-size:13px;">
        Everything below rests on a single property of the BLS12-381 pairing
        <em>e</em>: it is <strong>bilinear</strong>. Pulling a scalar out of either
        input multiplies in the exponent of the output:
        <code>e(a·P, b·Q) = e(P, Q)<sup>a·b</sup></code>. We don't ask you to take
        that on faith — pick two random scalars and watch both sides land on the
        <em>exact same</em> group element.
      </p>
      <button class="btn btn-primary" id="btn-bilinear">▶ Test Bilinearity (random a, b)</button>
      <div class="term" id="term-bilinear" role="log" aria-live="polite" aria-label="Bilinearity test output">Waiting…</div>
    </div>
    <div class="card" id="card-setup-math" style="display:none">
      <h2>Why This Works</h2>
      <div class="term" style="font-size:11px" role="group" aria-label="Mathematics explanation">
e(d_ID, U) = e(s·Q_ID, r·P)
           = e(Q_ID, P)^(s·r)
           = e(Q_ID, s·P)^r
           = e(Q_ID, P_pub)^r
           = g_ID^r

So H₂(e(d_ID, U)) = H₂(g_ID^r), which XORs back to M.

Decryption is just the bilinearity test above with a = s (hidden inside d_ID)
and b = r (the sender's random scalar). Same property, applied to a secret.

Security: Computing g_ID^r from U=r·P and public parameters requires
solving a Bilinear Diffie-Hellman problem in BLS12-381 — believed hard.

One honest footnote on the groups: Boneh-Franklin write BasicIdent over a
SYMMETRIC map ê: G1×G1→G2, with Q_ID, P, P_pub and rP all in one group, and
reduce security to BDH there. BLS12-381's pairing is Type 3 ASYMMETRIC — no
efficient map between G1 and G2 — so this demo puts Q_ID, d_ID in G1 and
P, P_pub, U in G2. The identity above is unchanged, but the assumption it
rests on is the asymmetric (co-)BDH variant, not the paper's symmetric BDH.
      </div>
    </div>
  </div>`;
}

function wireExhibit1() {
  document.getElementById('btn-bilinear')!.addEventListener('click', async () => {
    loading('term-bilinear');
    disableBtn('btn-bilinear', true);
    await new Promise((r) => setTimeout(r, 50));

    try {
      const { a, b, left, right, equal } = demonstrateBilinearity();
      setHTML('term-bilinear', `
<span class="lbl-cyan">BILINEARITY TEST — e(a·P, b·Q) =? e(P, Q)^(a·b)</span>
<span class="lbl-dim">──────────────────────────────────────────────</span>

Random scalars (fresh each run):
  a = <span class="lbl-amber">${hex(bigToBytes(a), 12)}</span>
  b = <span class="lbl-amber">${hex(bigToBytes(b), 12)}</span>

LEFT  — pair first, then the scalars ride along inside:
  e(a·P, b·Q)      = <span class="lbl-magenta">${hexGT(left)}</span>

RIGHT — pair the generators, then exponentiate by a·b:
  e(P, Q)^(a·b)    = <span class="lbl-green">${hexGT(right)}</span>

<span class="lbl-${equal ? 'green' : 'red'}">${
        equal
          ? '✓ IDENTICAL — all 576 bytes match. The scalars moved into the exponent.'
          : '✗ MISMATCH — this should never happen.'
      }</span>

<span class="lbl-dim">This is the whole trick. IBE decryption is this same move with the
master secret s and the sender's random r as the two scalars.</span>
      `.trim());
    } catch (e) {
      setHTML('term-bilinear', `<span class="lbl-red">ERROR: ${e}</span>`);
    }
    disableBtn('btn-bilinear', false);
  });

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
  Master secret s: <span class="censor" aria-hidden="true">████████████████████████████████████████</span> ${chip('master', 's — HIDDEN')}

Computing P_pub = s · P ∈ G2:
  ${chip('public', `P_pub = ${hexG2(Ppub)}…`)}

Defining hash functions:
  H₁: identity → G1 point (RFC 9380 hash-to-curve)
  H₂: G_T element → 32 bytes (SHA-256)

<span class="lbl-green">✓ System parameters published: (G1, G2, G_T, e, r, P, P_pub)</span>
<span class="lbl-gold">  PKG holds s secretly. Master key: NEVER leaves the PKG.</span>
      `.trim());

      highlightFlow('setup');
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
    <div class="cols-2" style="margin-bottom:16px">
      <div class="contrast-box contrast-bad">
        <div class="contrast-title">✗ Classic PKI / RSA</div>
        Alice wants to email <code class="pki-recipient">bob@newcompany.com</code>.
        First she needs the recipient's <em>public-key certificate</em>.
        They have never enrolled → no certificate exists anywhere →
        no key server has them → <strong>Alice is blocked. She cannot encrypt.</strong>
      </div>
      <div class="contrast-box contrast-good">
        <div class="contrast-title">✓ Identity-Based Encryption</div>
        Alice types <code class="pki-recipient">bob@newcompany.com</code> and encrypts.
        The <em>email address itself is the public key</em> —
        no certificate, no lookup, no enrolment first.
        <strong>The recipient can be issued a key years later and still decrypt.</strong>
      </div>
    </div>
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
      <div class="term" id="term-encrypt" role="log" aria-live="polite" aria-label="Encryption output">Run Setup first (Exhibit 1).</div>
    </div>
    <div class="card" id="card-enroll" style="display:none">
      <h2>Bob Enrolls with PKG</h2>
      <button class="btn btn-gold" id="btn-enroll">👤 Bob Enrolls — PKG Extracts Key</button>
      <div class="term" id="term-enroll" role="log" aria-live="polite" aria-label="Enrollment output">Waiting…</div>
    </div>
    <div class="card" id="card-decrypt2" style="display:none">
      <h2>Bob Decrypts</h2>
      <button class="btn btn-primary" id="btn-decrypt2">🔓 Decrypt</button>
      <div class="term" id="term-decrypt2" role="log" aria-live="polite" aria-label="Decryption output">Waiting…</div>
    </div>
  </div>`;
}

let _ct2: IBECiphertext | null = null;
let _bobKey2: InstanceType<typeof bls.G1.Point> | null = null;

function wireExhibit2() {
  // Keep the PKI-vs-IBE contrast box honest: echo whatever recipient the user
  // actually types. Falls back to the placeholder when the field is empty.
  const encId = document.getElementById('enc-identity') as HTMLInputElement | null;
  const syncContrast = () => {
    const who = (encId?.value.trim() || 'bob@newcompany.com');
    document.querySelectorAll('.pki-recipient').forEach((el) => {
      el.textContent = who;
    });
  };
  if (encId) {
    syncContrast();
    encId.addEventListener('input', syncContrast);
  }

  document.getElementById('btn-encrypt')!.addEventListener('click', async () => {
    const sys = getSystem();
    const identity = getVal('enc-identity');
    const msg = getVal('enc-message');
    loading('term-encrypt');

    await new Promise((r) => setTimeout(r, 50));
    try {
      const padded = pad(msg, MSG_BYTES);
      _ct2 = await encrypt(padded, identity, sys.params);
      const Q_ID = hashToG1(identity);

      // Recompute the SAME mask the encryption used, from the retained real
      // GT element g_ID^r. This is not a second encryption — it is exactly
      // H₂(g_ID^r), so padded ⊕ mask === V holds by construction.
      const mask = await hashGTtoBytes(_ct2._demoGtMask, MSG_BYTES);

      setHTML('term-encrypt', `
<span class="lbl-cyan">ALICE ENCRYPTS TO "${identity}"</span>
<span class="lbl-dim">──────────────────────────────────────────</span>

Compute Q_ID = H₁("${identity}") ∈ G1  (RFC 9380 hash-to-curve):
  ${chip('public', `Q_ID = ${hexG1(Q_ID)}…`)}
  <span class="lbl-dim">^ this point IS Bob's public key — anyone can derive it from his email.</span>

Pick random r ← [1, r-1]:
  r = <span class="censor" aria-hidden="true">████████████████</span> (discarded after encryption)

U = r · P ∈ G2  (96 bytes) — travels to Bob as part of the ciphertext:
  ${chip('public', `U = ${hexG2(_ct2.U)}…`)}

g_ID = e(Q_ID, P_pub) ∈ G_T,  then mask = H₂(g_ID^r),  V = M ⊕ mask${truncNote(msg, MSG_BYTES)}
      `.trim() +
        '\n' +
        xorViz(padded, mask, _ct2.V, {
          topLabel: 'M (plaintext)',
          topSub: '32 bytes of your message',
          maskLabel: 'H₂(g_ID^r)',
          maskSub: 'mask from the pairing',
          resultLabel: 'V (ciphertext)',
          resultSub: 'M ⊕ mask — what Bob receives',
          id: 'xor-encrypt',
          revealMask: true,
        }));

      animateXor('xor-encrypt');
      highlightFlow('encrypt');
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
    highlightFlow('extract');
    setHTML('term-enroll', `
<span class="lbl-gold">BOB ENROLLS WITH PKG</span>
<span class="lbl-dim">──────────────────────────────────────</span>

PKG authenticates Bob (out-of-band).
PKG computes: d_ID = s · H₁("${_ct2.identity}") ∈ G1
  <span class="lbl-dim">Same Q_ID anyone could compute — but multiplied by the secret s.
  Only the PKG can take this step. That is the whole asymmetry.</span>

Bob's private key:
  ${chip('secret', `d_ID = ${hexG1(_bobKey2)}…`)}

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

    // Prove correctness for THIS ciphertext: recompute the recipient-side
    // pairing and compare it byte-for-byte to the sender's g_ID^r.
    const proof = verifyPairingIdentity(_ct2, _bobKey2);

    // Bob's mask = H₂(e(d_ID,U)). Since the pairing identity holds, this is the
    // SAME 32 bytes Alice used, so V ⊕ maskBob === M. Honest recomputation.
    const maskBob = await hashGTtoBytes(proof.recipientGt, MSG_BYTES);
    const senderBytes = gtToBytes(proof.senderGt);
    const recipientBytes = gtToBytes(proof.recipientGt);

    highlightFlow('decrypt');
    setHTML('term-decrypt2', `
<span class="lbl-gold">BOB DECRYPTS</span>
<span class="lbl-dim">──────────────────────────────────────</span>

Bob computes e(d_ID, U) ∈ G_T, hashes it to the mask, and un-masks V:
M = V ⊕ H₂(e(d_ID, U))
      `.trim() +
      '\n' +
      xorViz(_ct2.V, maskBob, decrypted, {
        topLabel: 'V (ciphertext)',
        topSub: 'what Bob received',
        maskLabel: 'H₂(e(d_ID,U))',
        maskSub: 'mask Bob reconstructs',
        resultLabel: 'M (recovered)',
        resultSub: 'V ⊕ mask — the original bytes',
        id: 'xor-decrypt',
        revealMask: true,
      }) +
      '\n' +
      `
Decrypted message:
<span class="lbl-green">✓ "${msg}"</span>

<span class="lbl-cyan">PROOF — the two sides really are the same G_T element:</span>
  Sender computed   e(Q_ID, P_pub)^r = <span class="lbl-magenta">${hexGT(proof.senderGt)}</span>
  Bob computes      e(d_ID, U)       = <span class="lbl-green">${hexGT(proof.recipientGt)}</span>
<span class="lbl-${proof.equal ? 'green' : 'red'}">  ${
      proof.equal
        ? '✓ Fingerprints match — but don\'t take the 16-byte prefix on faith:'
        : '✗ Mismatch — should never happen.'
    }</span>
      `.trimEnd() +
      gtInspector(senderBytes, recipientBytes, 'gt-inspect-decrypt') +
      `
<span class="lbl-dim">  Bob never saw r. He reconstructed the sender's exact masking element
  using only his private key d_ID and the public U. That is the magic.</span>
    `.trimEnd());
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
          <div class="term" id="term-wk-alice" role="log" aria-live="polite" aria-label="Alice decryption output">Waiting…</div>
        </div>
        <div>
          <div style="color:var(--red);font-size:11px;margin-bottom:6px;text-transform:uppercase;" aria-hidden="true">Eve Decrypts (wrong key)</div>
          <div class="term" id="term-wk-eve" role="log" aria-live="polite" aria-label="Eve decryption output (wrong key)">Waiting…</div>
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

      // Both masks, computed honestly from the real pairings each key produces.
      // Alice's pairing e(d_ID,U) == the sender's g_ID^r, so her mask un-masks
      // V back to M. Eve's e(d_Eve,U) is a DIFFERENT G_T element, so her mask
      // is different and V ⊕ maskEve is the visible garbage eveDecrypted.
      const aliceMask = await hashGTtoBytes(pairing(aliceKey, ct.U), MSG_BYTES);
      const eveMask = await hashGTtoBytes(pairing(eveKey, ct.U), MSG_BYTES);

      setHTML('term-wk-alice', `
${chip('secret', `d_ID = s·H₁("${aliceId}")`)}  ← the key this ciphertext was sealed to
e(d_ID, U) ∈ G_T — the correct pairing → correct mask
      `.trim() +
        '\n' +
        xorViz(ct.V, aliceMask, aliceDecrypted, {
          topLabel: 'V',
          topSub: 'ciphertext',
          maskLabel: 'H₂(e(d_ID,U))',
          maskSub: 'correct mask',
          resultLabel: 'M',
          resultSub: 'recovered plaintext',
          id: 'xor-wk-alice',
          revealMask: true,
        }) +
        `\n<span class="lbl-${aliceMsg === fitted(msgStr, MSG_BYTES) ? 'green' : 'red'}">${
          aliceMsg === fitted(msgStr, MSG_BYTES) ? '✓' : '✗'
        } "${aliceMsg}"</span>${truncNote(msgStr, MSG_BYTES)}`);

      setHTML('term-wk-eve', `
${chip('secret', `d_Eve = s·H₁("${eveId}")`)}  ← Eve's own valid key, wrong identity
e(d_Eve, U) ∈ G_T — a DIFFERENT pairing → different mask
      `.trim() +
        '\n' +
        xorViz(ct.V, eveMask, eveDecrypted, {
          topLabel: 'V',
          topSub: 'same ciphertext',
          maskLabel: 'H₂(e(d_Eve,U))',
          maskSub: 'WRONG mask',
          resultLabel: 'M′',
          resultSub: 'scrambled bytes',
          id: 'xor-wk-eve',
          revealMask: true,
        }) +
        `\n<span class="lbl-red">✗ ${eveBytes}</span>\n<span class="lbl-dim">  Different mask → V ⊕ mask ≠ M. Eve holds a real key — just not <em>this</em> identity's.</span>`);

      animateXor('xor-wk-alice');
      animateXor('xor-wk-eve');
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
        Encrypt to "email || date" and the ciphertext is bound to that exact string.
        But the string is <em>not</em> a cryptographic clock — anyone who obtains the
        matching key can decrypt at any time. What actually creates a time-lock is the
        <strong>PKG's issuance policy</strong>: its refusal to hand out an off-date key.
        Play the PKG below and see the difference for yourself.
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

      <fieldset class="pkg-gate">
        <legend class="pkg-gate-title">You are the PKG. Bob asks for the key today — do you issue it?</legend>
        <p>Nothing in the math stops key issuance. The date in the identity string is
        just text; the time-lock is whatever <strong>you</strong>, the PKG, decide to
        enforce when Bob requests a key. Pick a policy and watch what actually gates access.</p>
        <div class="gate-choices">
          <label class="gate-opt">
            <input type="radio" name="pkg-gate" value="issue" checked />
            <span>Issue the key for the requested date
              <span class="go-note">Honest PKG, on-date request → Bob decrypts.</span></span>
          </label>
          <label class="gate-opt">
            <input type="radio" name="pkg-gate" value="refuse" />
            <span>Refuse — my policy only issues on the valid date
              <span class="go-note">Off-date request → no key issued → Bob is stuck. THIS is the time-lock.</span></span>
          </label>
          <label class="gate-opt">
            <input type="radio" name="pkg-gate" value="collude" />
            <span>Issue the off-date key anyway (compromised / colluding PKG)
              <span class="go-note">Same s, same math → Bob decrypts early. The string never stopped it.</span></span>
          </label>
        </div>
      </fieldset>

      <button class="btn btn-primary" id="btn-timelimit-run" disabled aria-disabled="true">▶ Run Scenario</button>
      <div class="term" id="term-timelimit" role="log" aria-live="polite" aria-label="Time-limited scenario output">Run Setup first (Exhibit 1).</div>
    </div>
    <div class="card">
      <h2>Real-World Applications</h2>
      <div class="term" style="font-size:11px" role="group" aria-label="Real-world application examples">
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
    const gate =
      (document.querySelector('input[name="pkg-gate"]:checked') as HTMLInputElement | null)
        ?.value ?? 'issue';

    loading('term-timelimit');
    await new Promise((r) => setTimeout(r, 50));

    try {
      const identity = `${email} || ${date}`;
      const padded = pad(msgStr, MSG_BYTES);
      // Alice always encrypts to the dated identity — this step never changes.
      const ct = await encrypt(padded, identity, sys.params);

      // The gate models the PKG's ISSUANCE decision, which is the real lock.
      let header: string;
      let body: string;

      if (gate === 'refuse') {
        // Off-date policy: the PKG declines to run Extract for the DATED
        // identity. Bob is not keyless, though — he already holds the key for
        // his plain address, which the PKG issues freely. So instead of
        // asserting "stays locked", run the only decryption actually available
        // to him and show what it produces.
        const undatedId = email;
        const undatedKey = extract(undatedId, sys.masterKey);
        const attempt = await decrypt(ct, undatedKey, sys.params);
        const recovered = unpad(attempt) === msgStr;
        header = `<span class="lbl-gold">PKG POLICY: REFUSE OFF-DATE KEY</span>`;
        body = `
Bob requests d_ID for "${identity}" — but the PKG's clock says it's not
the valid date yet, so it declines to extract:
  ${chip('secret', 'd_ID = s · H₁("…") — NOT ISSUED')}

Bob is not keyless: the PKG issues keys for his plain address on demand, so
he holds d = s·H₁("${undatedId}"). We actually run that key against this
ciphertext rather than assert the outcome:

  M′ = V ⊕ H₂(e(d, U)) = <span class="lbl-red">${hex(attempt)}</span>

<span class="lbl-${recovered ? 'red' : 'green'}">${
          recovered
            ? '✗ It decrypted — that must never happen; treat it as a bug in this demo.'
            : '✓ Garbage. e(d, U) is a different G_T element, so the mask is wrong.'
        }</span>
<span class="lbl-dim">  His only other option is to recover g_ID^r from U = r·P and the public
  parameters — a Bilinear Diffie-Hellman problem, believed hard.</span>
<span class="lbl-amber">  Note WHAT enforced this: the PKG's refusal, not the string.
  The date inside the identity is inert text — it cannot decline anything.
  Only a policy that governs issuance can.</span>`;
      } else {
        // Both 'issue' and 'collude' actually run Extract; the difference is
        // purely whether policy SHOULD have allowed it. The math is identical.
        const key = extract(identity, sys.masterKey);
        const out = await decrypt(ct, key, sys.params);
        const recoveredStr = unpad(out);
        const ok = recoveredStr === fitted(msgStr, MSG_BYTES);

        if (gate === 'issue') {
          header = `<span class="lbl-green">PKG POLICY: ISSUE (on-date, authorised)</span>`;
          body = `
It is the valid date. The PKG authenticates Bob and issues:
  ${chip('secret', `d_ID = s · H₁("${identity}")`)}

Bob decrypts:
  <span class="${ok ? 'lbl-green' : 'lbl-red'}">${ok ? `✓ "${recoveredStr}"` : `✗ Decryption failed — recovered "${recoveredStr}"`}</span>${truncNote(msgStr, MSG_BYTES)}

<span class="lbl-dim">Access happened because the PKG CHOSE to issue — exactly on schedule.</span>`;
        } else {
          header = `<span class="lbl-red">COMPROMISED PKG: ISSUE OFF-DATE ANYWAY</span>`;
          body = `
A colluding or breached PKG ignores the date policy and issues the key
early. Nothing in the ciphertext resists this — the identity string is
the same text either way:
  ${chip('secret', `d_ID = s · H₁("${identity}")`)}

Bob (or an attacker with PKG help) decrypts BEFORE the embargo:
  <span class="${ok ? 'lbl-red' : 'lbl-green'}">${ok ? `⚠ "${recoveredStr}" — released early` : `✗ Decryption failed — recovered "${recoveredStr}"`}</span>${truncNote(msgStr, MSG_BYTES)}

<span class="lbl-amber">  The "time-lock" was only ever a promise by the key issuer.
  Same escrow power from Exhibit 5, pointed at the clock.</span>`;
        }
      }

      setHTML('term-timelimit', `
<span class="lbl-cyan">IDENTITY STRING: "${identity}"</span>
<span class="lbl-dim">───────────────────────────────────────────────</span>

Alice encrypts to "${identity}" — sealed to that exact string:
  ${chip('public', `U = ${hexG2(ct.U)}…`)}
  ${chip('public', `V = ${hex(ct.V)}…`)}

${header}
      `.trimEnd() + '\n' + body.trimStart());
    } catch (e) {
      setHTML('term-timelimit', `<span class="lbl-red">ERROR: ${e}</span>`);
    }
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
      <div class="term" id="term-escrow" role="log" aria-live="polite" aria-label="Escrow demonstration output">Run Setup first (Exhibit 1).</div>
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
    highlightFlow('escrow');

    setHTML('term-escrow', `
<span class="lbl-red">PKG EXERCISES MASTER KEY — KEY ESCROW DEMONSTRATION</span>
<span class="lbl-dim">────────────────────────────────────────────────────</span>

Target identity: "${identity}"

User encrypts message to "${identity}":
  Ciphertext looks secure to outside observer.

PKG computes:
  ${chip('public', 'Q_ID = H₁("…") — anyone could get this far')}
  d_ID = s · Q_ID          ← PKG multiplies in master secret ${chip('master', 's')}
  ${chip('secret', 'd_ID = [derived — the SAME key the user would receive]')}

PKG applies d_ID to decrypt:
  M = V ⊕ H₂(e(d_ID, U))

Result — this is what the PKG's derived key actually returned, not an echo
of what you typed:
<span class="lbl-${result.pkgCanDecrypt ? 'red' : 'green'}">${
      result.pkgCanDecrypt
        ? '⚠ PKG successfully decrypted: "' + result.decryptedMessage + '"'
        : '✓ PKG could not decrypt (unexpected — this should never happen): "' +
          result.decryptedMessage +
          '"'
    }</span>${truncNote(msgStr, MSG_BYTES)}

<span class="lbl-amber">${result.explanation}</span>

<span class="lbl-dim">This is why IBE requires absolute trust in the PKG.
The escrow is a design decision — not an accident.</span>
    `.trim());
  });
}


// ─── Exhibit 6: Executable HIBE delegation ────────────────────────────────────

function exhibit6(): string {
  return `
  <div class="panel" id="panel-hibe" role="tabpanel" aria-labelledby="tab-hibe" aria-hidden="true">
    <div class="card">
      <h2>Exhibit 6 — A Parent Key Really Derives Its Descendant</h2>
      <p style="color:var(--text-dim);margin-bottom:14px;font-size:13px;">
        This is a separate Type-3 HIBE construction, not Boneh–Franklin BasicIdent with slashes in a string.
        The PKG issues only the root key. That root key delegates to a department, and the department delegates
        again to a user <strong>without receiving the master secret</strong>.
      </p>
      <div class="field-row">
        <label for="hibe-root">Root identity</label>
        <input id="hibe-root" value="acme" autocomplete="off" />
      </div>
      <div class="field-row">
        <label for="hibe-dept">Department</label>
        <input id="hibe-dept" value="finance" autocomplete="off" />
      </div>
      <div class="field-row">
        <label for="hibe-user">User</label>
        <input id="hibe-user" value="alice" autocomplete="off" />
      </div>
      <div class="field-row">
        <label for="hibe-message">Message (max 32 bytes)</label>
        <input id="hibe-message" value="Quarterly forecast: internal" autocomplete="off" />
      </div>
      <button class="btn btn-primary" id="btn-hibe-run">🌳 Run real delegation</button>
      <div class="term" id="term-hibe" role="log" aria-live="polite" aria-label="Hierarchical IBE delegation output">Ready to build a three-level hierarchy.</div>
    </div>

    <div class="card">
      <h2>What this proves — and what it does not</h2>
      <div class="term" style="font-size:11px;white-space:pre-wrap">
<span class="lbl-green">Real in this exhibit</span>
• Type-3 asymmetric BLS12-381 pairings
• Parent → child and child → grandchild key delegation
• Fresh and delegated keys for the same identity both decrypt
• A same-depth sibling key runs the pairing math and lands on the wrong G_T secret
• The PKG can still freshly extract any branch: root escrow remains

<span class="lbl-amber">Deliberate limits</span>
• Bounded depth 3 for the learner exercise
• Text components are domain-separated and hashed to Z_r
• The paper encrypts G_T elements directly; this demo hashes the recovered G_T element to a 32-byte mask
• This KEM/DEM teaching adaptation does not claim the paper's full security proof
      </div>
      <p style="color:var(--text-dim);margin-top:12px;font-size:12px;">
        Construction basis: Ramanna, Chatterjee &amp; Sarkar, Appendix G, extending their asymmetric-pairing Scheme 6.
      </p>
    </div>
  </div>`;
}

function wireExhibit6(): void {
  document.getElementById('btn-hibe-run')?.addEventListener('click', async () => {
    const btn = document.getElementById('btn-hibe-run') as HTMLButtonElement;
    const root = getVal('hibe-root');
    const dept = getVal('hibe-dept');
    const user = getVal('hibe-user');
    const msg = getVal('hibe-message');

    if (!root || !dept || !user) {
      setHTML('term-hibe', '<span class="lbl-red">Enter all three identity components.</span>');
      return;
    }

    btn.disabled = true;
    btn.setAttribute('aria-disabled', 'true');
    loading('term-hibe');

    try {
      const system = setupHIBE(3, MSG_BYTES);
      const rootKey = keyGenHIBE([root], system.masterKey, system.params);
      const deptKey = delegateHIBE(rootKey, dept, system.params);
      const userKey = delegateHIBE(deptKey, user, system.params);
      const target = [root, dept, user];

      const message = pad(msg, MSG_BYTES);
      const ct = await encryptHIBE(message, target, system.params);
      const delegatedPlain = await decryptHIBE(ct, userKey, system.params);
      const delegatedShared = recoverHIBESecret(ct, userKey);

      const freshKey = keyGenHIBE(target, system.masterKey, system.params);
      const freshPlain = await decryptHIBE(ct, freshKey, system.params);

      const siblingName = dept.toLowerCase() === 'hr' ? 'finance' : 'hr';
      const siblingDept = delegateHIBE(rootKey, siblingName, system.params);
      const siblingUser = delegateHIBE(siblingDept, user, system.params);
      const siblingShared = recoverHIBESecret(ct, siblingUser);
      const siblingPlain = await decryptHIBE(ct, siblingUser, system.params);

      const delegatedOk = unpad(delegatedPlain) === fitted(msg, MSG_BYTES);
      const freshOk = unpad(freshPlain) === fitted(msg, MSG_BYTES);
      const siblingSecretDiffers = !gtEquals(siblingShared, ct._demoShared);
      const siblingPlainDiffers = Array.from(siblingPlain).some((b, i) => b !== message[i]);
      const subtree = isIdentityPrefix([root, dept], target);
      const siblingIsOutside = !isIdentityPrefix([root, dept], [root, siblingName, user]);
      const shown = {
        root: escapeHtml(root),
        dept: escapeHtml(dept),
        user: escapeHtml(user),
        sibling: escapeHtml(siblingName),
        target: target.map(escapeHtml).join(' / '),
        delegatedPlain: escapeHtml(unpad(delegatedPlain)),
        freshPlain: escapeHtml(unpad(freshPlain)),
      };

      setHTML('term-hibe', `
<span class="lbl-cyan">TYPE-3 HIBE — EXECUTABLE DELEGATION</span>
<span class="lbl-dim">───────────────────────────────────────────────</span>

PKG fresh extraction:
  root key = [${shown.root}]
  master secret used here: <span class="lbl-gold">YES</span>

Parent delegation — no master-secret input:
  [${shown.root}] → [${shown.root} / ${shown.dept}]
  [${shown.root} / ${shown.dept}] → [${shown.target}]
  department key covers target subtree: <span class="${subtree ? 'lbl-green' : 'lbl-red'}">${subtree ? 'YES' : 'NO'}</span>

Ciphertext target:
  [${shown.target}]

Delegated descendant decrypt:
  recovered = "${shown.delegatedPlain}"
  sender/recipient G_T secret match: <span class="${gtEquals(delegatedShared, ct._demoShared) ? 'lbl-green' : 'lbl-red'}">${gtEquals(delegatedShared, ct._demoShared) ? 'YES' : 'NO'}</span>
  verdict: <span class="${delegatedOk ? 'lbl-green' : 'lbl-red'}">${delegatedOk ? '✓ DESCENDANT KEY DECRYPTS' : '✗ FAILED'}</span>

Fresh PKG key for the same target:
  recovered = "${shown.freshPlain}"
  verdict: <span class="${freshOk ? 'lbl-green' : 'lbl-red'}">${freshOk ? '✓ PKG ESCROW STILL REACHES THIS BRANCH' : '✗ FAILED'}</span>

Sibling compromise:
  wrong branch = [${shown.root} / ${shown.sibling} / ${shown.user}]
  outside [${shown.root} / ${shown.dept}] subtree: <span class="${siblingIsOutside ? 'lbl-green' : 'lbl-red'}">${siblingIsOutside ? 'YES' : 'NO'}</span>
  pairing math executed at the same depth
  recovered G_T secret equals sender's: <span class="${siblingSecretDiffers ? 'lbl-red' : 'lbl-green'}">${siblingSecretDiffers ? 'NO' : 'YES'}</span>
  plaintext equals target plaintext: <span class="${siblingPlainDiffers ? 'lbl-red' : 'lbl-green'}">${siblingPlainDiffers ? 'NO' : 'YES'}</span>
  verdict: <span class="${siblingSecretDiffers && siblingPlainDiffers ? 'lbl-green' : 'lbl-red'}">${siblingSecretDiffers && siblingPlainDiffers ? '✓ SIBLING BRANCH CANNOT OPEN IT' : '✗ BOUNDARY FAILED'}</span>

<span class="lbl-amber">What hierarchy changes:</span>
  The root PKG no longer has to issue every descendant key itself.
  A delegated node can create keys only below its own identity prefix.
  Compromising [${shown.root} / ${shown.dept}] exposes that subtree's future delegations,
  but not the sibling [${shown.root} / ${shown.sibling}] branch.
  The root PKG still retains escrow over every branch.
${truncNote(msg, MSG_BYTES)}
      `.trim());
    } catch (e) {
      setHTML('term-hibe', `<span class="lbl-red">ERROR: ${e}</span>`);
    } finally {
      btn.disabled = false;
      btn.setAttribute('aria-disabled', 'false');
    }
  });
}

// ─── Exhibit 7: PKI / IBE / certificateless ownership split ─────────────────

function exhibit7(): string {
  return `
  <div class="panel" id="panel-cle" role="tabpanel" aria-labelledby="tab-cle" aria-hidden="true">
    <div class="card">
      <h2>Exhibit 7 — Who Must Be Compromised?</h2>
      <p style="color:var(--text-dim);margin-bottom:14px;font-size:13px;">
        Run three real routes to the same identity. PKI verifies a P-256 CA signature before using
        the certified RSA key. IBE uses BasicIdent, so the KGC can extract the whole recipient key.
        The certificateless route splits authority between an IBE partial key and a user-generated
        RSA secret, then runs Huang–Wong's <code>IBE → PKE → one-time MAC</code> envelope mechanics.
      </p>
      <div class="field-row">
        <label for="cle-identity">Target identity</label>
        <input id="cle-identity" value="student@example.edu" autocomplete="off" />
      </div>
      <div class="field-row">
        <label for="cle-message">Message (at most ${CLE_MESSAGE_MAX_BYTES} UTF-8 bytes)</label>
        <input id="cle-message" value="capstone draft" autocomplete="off" />
      </div>
      <button class="btn btn-primary" id="btn-cle-run">Run all three routes and adversaries</button>
      <div class="term" id="term-cle" role="log" aria-live="polite" aria-label="PKI IBE and certificateless comparison output">Ready to generate fresh CA, KGC, user, and attacker keys.</div>
    </div>

    <div class="card">
      <h2>The two certificateless adversaries are not interchangeable</h2>
      <div class="term" style="font-size:11px;white-space:pre-wrap">
<span class="lbl-cyan">Type I — public-key replacement</span>
May replace the target user's public key and knows its own replacement secret.
Does <strong>not</strong> receive the target partial private key or KGC master secret.

<span class="lbl-gold">Type II — malicious-but-passive KGC</span>
Knows the master secret and therefore the target partial private key.
Does <strong>not</strong> receive or replace the target user's independently generated secret key.

Giving one actor both capabilities is the explicit compromise control — it decrypts.
Key replacement can still deny service, and CLE does not authenticate a directory by itself.
      </div>
    </div>

    <div class="card">
      <h2>Exact model boundary</h2>
      <p style="color:var(--text-dim);font-size:12px;line-height:1.65;">
        This is a <strong>bounded mechanics adaptation</strong>, not a proof or production CLE scheme.
        Huang and Wong's 2007 generic theorem assumes an IND-ID-CCA2 IBE, IND-CCA2 public-key
        encryption, and a strong one-time MAC. This lab deliberately reuses Boneh–Franklin
        <strong>BasicIdent, which is only IND-CPA</strong>; therefore the theorem does not apply to
        this composition. RSA-OAEP-2048/SHA-256 and HMAC-SHA-256 are real WebCrypto operations,
        and the inner BasicIdent operation uses the lab's real BLS12-381 pairing code. The
        omniscient class trace names an internal failure stage, but the attacker API receives
        only one explicit reject bit, rather than a named failure-stage oracle. This teaching
        code is not constant-time and makes no timing-side-channel claim.
        The two actor runs are one-shot teaching cases, not full adaptive security games:
        Type I uses an explicit public group-element guess for the missing partial key, while
        Type II generates an unrelated RSA key internally. No extraction or decryption oracle
        is simulated.
      </p>
      <p style="color:var(--text-dim);font-size:12px;line-height:1.65;margin-top:10px;">
        Primary sources:
        <a href="https://eprint.iacr.org/2007/095" target="_blank" rel="noreferrer">Huang–Wong, §4 and §4.2</a>
        for the generic construction and
        <a href="https://eprint.iacr.org/2003/126" target="_blank" rel="noreferrer">Al-Riyami–Paterson</a>
        for the Type-I/Type-II certificateless model.
      </p>
    </div>
  </div>`;
}

function boolVerdict(ok: boolean, yes: string, no: string, id: string): string {
  return `<span id="${id}" data-verdict="${ok ? 'pass' : 'fail'}" class="${ok ? 'lbl-green' : 'lbl-red'}">${ok ? yes : no}</span>`;
}

function sameBytes(a: Uint8Array | null, b: Uint8Array): boolean {
  return !!a && a.length === b.length && a.every((value, i) => value === b[i]);
}

function wireExhibit7(): void {
  document.getElementById('btn-cle-run')?.addEventListener('click', async () => {
    const btn = document.getElementById('btn-cle-run') as HTMLButtonElement;
    const identity = getVal('cle-identity');
    const message = getVal('cle-message');
    if (!identity || !message) {
      setHTML('term-cle', '<span class="lbl-red">Enter a target identity and message.</span>');
      return;
    }

    btn.disabled = true;
    btn.setAttribute('aria-disabled', 'true');
    loading('term-cle');

    try {
      const encodedMessage = new TextEncoder().encode(message);
      if (encodedMessage.length > CLE_MESSAGE_MAX_BYTES) {
        throw new Error(`Message is ${encodedMessage.length} UTF-8 bytes; the bounded envelope permits ${CLE_MESSAGE_MAX_BYTES}.`);
      }

      const system = setupCLE();
      const [user, attacker, ca] = await Promise.all([
        generateUserKeyPair(),
        generateUserKeyPair(),
        generateCertificateAuthority(),
      ]);
      const targetPartial = issuePartialPrivateKey(identity, CLE_CONTEXT, system);
      const otherPartial = issuePartialPrivateKey(`not-${identity}`, CLE_CONTEXT, system);

      // PKI: a real CA signature authenticates the identity -> RSA-key binding.
      const certificate = await issueCertificate(
        identity,
        CLE_CONTEXT,
        user.publicKey,
        ca.privateKey
      );
      const pkiCiphertext = await encryptPKI(
        encodedMessage,
        identity,
        CLE_CONTEXT,
        certificate,
        ca.publicKey
      );
      const pkiPlain = await decryptPKI(pkiCiphertext.ciphertext, user.privateKey);
      const pkiHonest = sameBytes(pkiPlain, encodedMessage);
      const oldCipherForAttacker = await decryptPKI(pkiCiphertext.ciphertext, attacker.privateKey);
      const forgedCertificate = await issueCertificate(
        identity,
        CLE_CONTEXT,
        attacker.publicKey,
        ca.privateKey
      );
      const futurePki = await encryptPKI(
        encodedMessage,
        identity,
        CLE_CONTEXT,
        forgedCertificate,
        ca.publicKey
      );
      const futureForAttacker = await decryptPKI(futurePki.ciphertext, attacker.privateKey);
      const caRedirectsFuture = sameBytes(futureForAttacker, encodedMessage);
      const caReadsRecorded = sameBytes(oldCipherForAttacker, encodedMessage);

      // IBE: the KGC master is sufficient because it can extract the target key.
      const directIbe = ibeSetup(MSG_BYTES);
      const directMessage = pad(message, MSG_BYTES);
      const directCiphertext = await encrypt(directMessage, identity, directIbe.params);
      const kgcTargetKey = extract(identity, directIbe.masterKey);
      const kgcPlain = await decrypt(directCiphertext, kgcTargetKey, directIbe.params);
      const kgcReadsIbe = sameBytes(kgcPlain, directMessage);

      // CLE honest route, then each adversary with only its permitted inputs.
      const honest = await encryptCLE(
        message,
        identity,
        CLE_CONTEXT,
        system.params,
        user.publicKey
      );
      const honestResult = await decryptCLE(
        honest,
        identity,
        CLE_CONTEXT,
        system.params,
        targetPartial,
        user.privateKey
      );
      const replacementEnvelope = await encryptCLE(
        message,
        identity,
        CLE_CONTEXT,
        system.params,
        attacker.publicKey
      );
      const typeI = await typeIAttempt(
        replacementEnvelope,
        identity,
        CLE_CONTEXT,
        system.params,
        attacker.privateKey
      );
      const typeII = await typeIIAttempt(
        honest,
        identity,
        CLE_CONTEXT,
        system.params,
        targetPartial
      );
      const combined = await decryptCLE(
        replacementEnvelope,
        identity,
        CLE_CONTEXT,
        system.params,
        targetPartial,
        attacker.privateKey
      );
      const displacedUser = await decryptCLE(
        replacementEnvelope,
        identity,
        CLE_CONTEXT,
        system.params,
        targetPartial,
        user.privateKey
      );
      const typeITrace = await decryptCLETeaching(
        replacementEnvelope,
        identity,
        CLE_CONTEXT,
        system.params,
        otherPartial,
        attacker.privateKey
      );
      const typeIITrace = await decryptCLETeaching(
        honest,
        identity,
        CLE_CONTEXT,
        system.params,
        targetPartial,
        attacker.privateKey
      );
      const tamperedTag = honest.tag.slice();
      tamperedTag[0] ^= 1;
      const tampered = await decryptCLE(
        { c2: honest.c2, tag: tamperedTag },
        identity,
        CLE_CONTEXT,
        system.params,
        targetPartial,
        user.privateKey
      );

      setHTML('term-cle', `
<span class="lbl-cyan">THREE KEY-OWNERSHIP ROUTES — FRESH RUN</span>
<span class="lbl-dim">────────────────────────────────────────────────────</span>
Target = "${escapeHtml(identity)}"
Message = "${escapeHtml(message)}" (${encodedMessage.length} UTF-8 bytes)

<span class="lbl-cyan">PKI — CA signs identity + user public key</span>
  CA signature verified before encryption: ${boolVerdict(pkiCiphertext.certificateAccepted, 'YES', 'NO', 'cle-pki-cert')}
  honest user secret decrypts: ${boolVerdict(pkiHonest, 'YES', 'NO', 'cle-pki-honest')}
  compromised CA redirects a future send: ${boolVerdict(caRedirectsFuture, 'YES', 'NO', 'cle-pki-future')}
  same attacker reads recorded honest-key ciphertext: ${boolVerdict(!caReadsRecorded, 'NO', 'YES', 'cle-pki-recorded')}

<span class="lbl-cyan">IBE — identity only; KGC owns full extraction power</span>
  KGC derives d_ID from master s and decrypts: ${boolVerdict(kgcReadsIbe, 'YES', 'NO', 'cle-ibe-kgc')}

<span class="lbl-cyan">CLE adaptation — target partial + user secret</span>
  honest holder has both contributions: ${boolVerdict(honestResult.accepted && honestResult.message === message, 'ACCEPT', 'REJECT', 'cle-honest')}
  Type I (replacement secret, public key guess; no target partial input): ${boolVerdict(!typeI.accepted, 'REJECT', 'ACCEPT', 'cle-type-i')}
  Type II (target partial, unrelated user secret): ${boolVerdict(!typeII.accepted, 'REJECT', 'ACCEPT', 'cle-type-ii')}
  combined compromise (target partial + replacement secret): ${boolVerdict(combined.accepted && combined.message === message, 'ACCEPT', 'REJECT', 'cle-combined')}
  honest user after public-key replacement: ${boolVerdict(!displacedUser.accepted, 'REJECT — availability lost', 'ACCEPT', 'cle-displaced')}
  one-bit tag mutation: ${boolVerdict(!tampered.accepted, 'REJECT', 'ACCEPT', 'cle-tamper')}

Envelope from this run:
  c1 serialized before RSA-OAEP = 189 bytes (4 magic + 1 flags + 32 binding + 96 U + 56 V)
  c2 RSA-OAEP ciphertext = ${honest.c2.length} bytes; fingerprint ${hex(honest.c2, 8)}
  HMAC-SHA-256 tag = ${honest.tag.length} bytes; fingerprint ${hex(honest.tag, 8)}

<span class="lbl-amber">Observer boundary</span>
  attacker-visible result for either failed attempt = REJECT only
  omniscient teaching trace, Type I internal stop = ${escapeHtml(typeITrace.stage)}
  omniscient teaching trace, Type II internal stop = ${escapeHtml(typeIITrace.stage)}
  timing is not hardened or claimed constant-time in this browser model

<span class="lbl-amber">Interpretation</span>
  PKI moves authenticated key binding to the CA. IBE gives the KGC escrow.
  This CLE envelope makes neither adversary class sufficient alone, but a key
  replacement can still block delivery, and a directory still needs authentication.
  These live outcomes demonstrate mechanics; they do not upgrade BasicIdent to CCA security.
      `.trim());
    } catch (error) {
      setHTML('term-cle', `<span class="lbl-red">ERROR: ${escapeHtml(String(error))}</span>`);
    } finally {
      btn.disabled = false;
      btn.setAttribute('aria-disabled', 'false');
    }
  });
}
