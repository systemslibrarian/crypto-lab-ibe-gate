# crypto-lab-ibe-gate

## What It Is

Browser-based demo of Boneh-Franklin Identity-Based Encryption (IBE), implementing the 2001
BasicIdent scheme from "Identity-Based Encryption from the Weil Pairing" (Boneh & Franklin).
Uses BLS12-381 pairings via `@noble/curves` for the bilinear map e: G1 × G2 → GT. All four IBE
algorithms — setup, extract, encrypt, decrypt — follow the paper's BasicIdent definitions.
Demonstrates encryption to unenrolled recipients, time-limited capabilities via identity string
policy, role-based encryption, and the fundamental key-escrow tradeoff where the Private Key
Generator can decrypt any message in the system.

A sixth exhibit adds **real hierarchical key delegation** using the Type-3 HIBE extension of
Ramanna, Chatterjee & Sarkar's asymmetric-pairing Scheme 6 (Appendix G of
[ePrint 2012/024](https://eprint.iacr.org/2012/024)). The root key delegates a department key, that
key delegates a user key without receiving the master secret, and a same-depth sibling key is allowed
to run the pairing algebra and demonstrably recovers the wrong GT secret. This is a separate HIBE
construction; slash-separated Boneh-Franklin identities are not presented as delegation.

A seventh exhibit makes the PKI / IBE / certificateless ownership split executable. Its PKI route
verifies a real WebCrypto P-256 CA signature over a length-framed identity, context, and RSA public
key before encrypting. Its IBE route shows that the KGC master secret alone can derive the recipient
key. Its certificateless route follows the envelope mechanics in Huang and Wong, ePrint 2007/095
§4.2: `c1 = IBE.Enc(ID, m || mk)`, `c2 = PKE.Enc(upk, c1)`, and
`tag = MAC_mk(c2)`. Separate Type-I (public-key replacement, no target partial key) and Type-II
(KGC/target partial key, no target user secret or replacement) attempts fail, while an explicit
combined-compromise control decrypts. The route uses the existing real BasicIdent/BLS12-381 code,
WebCrypto RSA-OAEP-2048/SHA-256, and HMAC-SHA-256; it is not a hardcoded scenario.
The actor runs are bounded one-shot cases rather than full adaptive games: Type I uses a public
group-element guess for the absent target partial key, Type II creates an unrelated RSA key internally,
and no extraction or decryption oracle is simulated.

**One deliberate deviation from the paper.** Boneh-Franklin define BasicIdent over a *symmetric*
admissible bilinear map `ê: G1 × G1 → G2` — Q_ID, P, P_pub and the ciphertext component rP all
live in the same group, and the security reduction is to BDH in ⟨G1, G2, ê⟩. BLS12-381 has no
such map; its pairing is **Type 3 asymmetric** with no efficient homomorphism between G1 and G2.
So this demo splits the scheme the standard way — `Q_ID, d_ID ∈ G1` and `P, P_pub, U ∈ G2` — which
keeps the correctness identity `e(d_ID, U) = e(Q_ID, P_pub)^r` exactly as written but moves the
hardness assumption to the asymmetric (co-)BDH variant rather than the paper's symmetric BDH. The
algebra on screen is the paper's; the group assignment is not.

The walkthrough is built to be *seen*, not just narrated: a persistent SVG protocol map lights
the active arrow as each step runs (P_pub published, U sent, d_ID issued, both pairings converging
on the shared G_T mask); the XOR masking step is shown as animated coloured byte-grids so you watch
a message become ciphertext and back; a consistent public/secret colour-and-icon convention marks
what anyone can compute (Q_ID, U, P_pub, green) versus what needs the master secret (d_ID, gold-lock;
s, redacted); and the byte-for-byte pairing-equality claim is made inspectable — an expander scans
all 576 bytes of both G_T elements and reports the exact mismatch count instead of a truncated
fingerprint.

## When to Use It

- Understanding how IBE eliminates certificate distribution in favor of identity-based addressing
- Teaching bilinear pairings through a complete protocol (setup to decrypt, not just pairing primitives)
- Evaluating IBE for enterprise email encryption, regulated industries, or policy-encoded access control
- Comparing IBE's centralized trust model to PKI, Signal Protocol, and threshold schemes
- Comparing PKI, IBE, and certificateless key ownership with separate Type-I and Type-II adversaries
- **Not for:** applications requiring key escrow resistance (use PKI or end-to-end schemes with forward secrecy); the PKG is a single point of compromise in BasicIdent
- Do NOT use this in production — it is a from-the-paper teaching implementation (pure-TypeScript pairings, BasicIdent/IND-CPA only), not a hardened IBE library.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-ibe-gate](https://systemslibrarian.github.io/crypto-lab-ibe-gate/)**

Run the full Boneh-Franklin BasicIdent protocol in the browser: a Private Key Generator runs setup, extracts a private key for an identity string, and you encrypt a message to any identity and decrypt it — every step over real BLS12-381 pairings via `@noble/curves`. The demo shows encryption to unenrolled recipients, time-limited and role-based identities encoded directly in the identity string, and makes the key-escrow tradeoff concrete by letting the PKG's master secret derive any user's key. The time-limited exhibit lets *you* play the PKG at an issuance gate — issue, refuse, or collude — to make explicit that a date baked into an identity is inert text; the time-lock is enforced by the PKG's issuance policy, not by the string, and a compromised PKG can hand out the off-date key anyway.

The HIBE tab builds a three-level hierarchy in a fresh Type-3 system, extracts only the root key with
the master secret, delegates department and user keys recursively, encrypts to the descendant, and
compares that successful path with a sibling branch that executes the same-depth decryption math but
lands on the wrong GT secret. It also freshly extracts the target key at the PKG to show that hierarchy
reduces routine root issuance without removing root escrow.

The PKI/IBE/CLE tab generates fresh CA, KGC, user, and attacker keys on every run. It verifies an
honest PKI route, demonstrates what a compromised CA can redirect (a future send, not a recorded
honest-key ciphertext), executes the KGC's IBE escrow path, and then runs the two certificateless
adversary classes with APIs that omit the capability each class is forbidden to receive. The learner
sees a single explicit reject result from either failed attacker attempt; an explicitly labelled
omniscient teaching trace separately names the internal stop. This removes a named-stage response,
not timing leakage: the browser teaching code is not constant-time and claims no timing defense.

## What Can Go Wrong

- **The PKG can decrypt every message.** Master secret `s` lets PKG derive any identity's private key. This is architectural, not a bug. The HIBE exhibit reduces how often the root must issue descendant keys, but the root PKG can still freshly extract every branch; HIBE delegation does not remove root escrow.
- BasicIdent is IND-CPA but not IND-CCA. An active attacker can modify ciphertexts. Production systems use FullIdent (Boneh-Franklin 2001 Section 4.2) with a Fujisaki-Okamoto transform for IND-CCA security.
- **The certificateless exhibit is a mechanics adaptation, not Huang–Wong's security theorem.** Their generic result assumes an IND-ID-CCA2 IBE, IND-CCA2 PKE, and strong one-time MAC. This lab deliberately reuses IND-CPA BasicIdent, so the composition does not satisfy the theorem's premises and no CLE security proof is claimed. The 23-byte message bound comes from fitting a canonical 189-byte inner ciphertext beneath RSA-OAEP-2048/SHA-256's 190-byte input ceiling.
- Certificateless encryption does not authenticate a public-key directory by itself. A Type-I replacement remains an availability attack against the honest user, and combining the target partial key with the replacement/user secret decrypts.
- Private keys must be transmitted securely from PKG to user. This requires out-of-band authentication — the PKG has to know the user is who they claim to be before issuing `d_ID`.
- Revocation is hard. Unlike PKI where certificates can be revoked, an issued IBE private key is valid forever for that identity. Workarounds use short-lived identities (email || timestamp) or include revocation lists.
- BLS12-381 pairings are computationally expensive. Measured here (Node 24, `@noble/curves` 2.2, Apple silicon): a warm single pairing is around 15 ms, and a cold first call — JIT warm-up included — is closer to 70 ms; a browser is in the same order of magnitude, not the same number. Every exhibit therefore runs one to two pairings per click, which is why they feel instant but not free. Production deployments use C/Rust/assembly with optimized pairing libraries.

## Real-World Usage

Introduced by Adi Shamir in 1984 as a concept; first practical construction by Dan Boneh and Matthew Franklin at CRYPTO 2001. Full version published in SIAM Journal on Computing (2003). The best-known commercial deployment is Voltage SecureMail, the IBE-based enterprise email product from Voltage Security — a company founded on the Boneh-Franklin work and since passed through HP, HPE Software, Micro Focus and (since the Micro Focus acquisition closed in 2023) OpenText, where it still ships as Voltage SecureMail. IBE was also standardized as IEEE Std 1363.3-2013 (Identity-Based Cryptographic Techniques using Pairings) and in IETF RFC 5091. Hierarchical IBE (HIBE) extends the scheme to multi-level PKG structures; threshold IBE distributes the master secret. The underlying bilinear pairing here is BLS12-381, the same curve used in Ethereum's consensus layer, Filecoin, Chia, and Zcash Sapling for BLS aggregated signatures — note that BLS12-381 postdates the paper by 16 years and is not a curve Boneh-Franklin proposed.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-ibe-gate
cd crypto-lab-ibe-gate
npm install
npm run dev
```

## Run the Tests

```bash
npm test            # 50 Vitest tests (IBE, HIBE, CLE/PKI, and palette)
npm run build       # tsc + production bundle (the browser gate runs against this)
npm run test:a11y   # Playwright: 18 functional + 2 full-state WCAG/reflow drives
```

`npm run test:a11y` runs the whole `e2e/` directory, which is two gates:

- **`e2e/functional.spec.ts`** — drives the built page in Chromium and asserts
  the states the page claims, so the exhibits are tested rather than merely
  visited. Wherever a verdict has a computation on screen, the verdict is
  checked against *that run's* numbers instead of a hardcoded string: the
  "✓ IDENTICAL — all 576 bytes match" banner is only accepted if the two printed
  G_T fingerprints really are equal; every XOR byte-grid is re-XORed from its own
  rendered cells and compared to the row below it; the decrypt proof's sender and
  recipient fingerprints are compared to each other; and the inspector's
  "0 mismatches" counter is checked against the actual number of diff-coloured
  cells in the 576-byte dump the same run produced. All three failure paths are
  covered — Eve's wrong-identity key, the PKG's REFUSE policy, and the colluding
  PKG — each asserted to reach its failure state *and* to say why. The HIBE claim test additionally
  drives a custom three-level identity, requires descendant decryption, and checks that the sibling
  branch reports a different recovered GT secret and plaintext after the pairing math actually runs.
  The CLE claim tests require every positive and negative live verdict to match its expected outcome,
  check the actual RSA/HMAC sizes, rerun for fresh ciphertext, and exercise the UTF-8 bound.
- **`e2e/a11y.spec.ts`** — axe-core WCAG 2.1 A/AA, arithmetic text contrast, non-text contrast
  ratchets, keyboard-reachable scrollers, and reflow checks over every state at desktop and 380 px.

The unit suite (`test/ibe.test.ts`) runs against the real `@noble/curves`
pairing — no mocks — and covers:

- **Bilinearity** `e(a·P, b·Q) = e(P, Q)^(a·b)` (random and fixed scalars) and pairing non-degeneracy.
- **The BasicIdent correctness identity** `e(d_ID, U) = e(Q_ID, P_pub)^r`, checked byte-for-byte over the raw Fp12 serialization.
- **Encrypt → extract → decrypt round-trip** for empty, single-char, role, time-limited, and Unicode identities.
- **Forgery rejection:** a wrong-identity key or a foreign PKG's master secret does NOT recover the plaintext.
- **Key escrow:** a PKG-derived key decrypts any identity (the architectural tradeoff, asserted rather than asserted-away).
- **Primitive correctness:** deterministic `H₁` hash-to-curve into the prime-order subgroup, deterministic length-correct `H₂` XOF, and semantic security via fresh randomness `r` per encryption.

The separate HIBE suite (`test/hibe.test.ts`) checks fresh depth-1/2/3 keys, parent→child and
recursive delegation without the master secret, fresh/delegated correctness for the same identity,
structural rejection of a too-shallow parent key, same-depth sibling failure through the actual pairing
algebra, maximum-depth enforcement, and retained root-PKG escrow.

The certificateless/PKI suite (`test/certificateless.test.ts`) checks the 189-byte canonical inner
encoding and 256-byte RSA ciphertext, honest two-contribution recovery, fresh envelopes, UTF-8 bounds,
identity/context binding, tag and outer-ciphertext tampering, uniform public rejection, distinct Type-I
and Type-II capability sets, the combined-compromise control, real P-256 certificate verification, and
the difference between future CA redirection and decryption of a recorded ciphertext.

### HIBE construction and limits

The HIBE core follows Appendix G of Ramanna, Chatterjee & Sarkar, *Variants of Waters' Dual-System
Primitives Using Asymmetric Pairings*. That construction is explicitly for a Type-3 pairing
`e: G1 × G2 → GT`: public ciphertext components are in G1 while delegated/decryption-key components
are in G2. Text identity components are domain-separated and hashed to scalars in `Z_r` for this lab.
The paper masks a message element in GT directly; the browser exhibit instead hashes the recovered GT
element to a fixed 32-byte XOR mask so it can reuse the lab's byte visual language. That adaptation is
for teaching and does **not** claim the paper's full security proof. The learner exercise is bounded to
depth 3; the core supports a small configured bound for tests.

### Certificateless construction and limits

The seventh exhibit is based on Qiong Huang and Duncan S. Wong, *Generic Certificateless Encryption
in the Standard Model*, [ePrint 2007/095](https://eprint.iacr.org/2007/095), especially §§2, 3, 4,
and 4.2. Its adversary split follows Sattam S. Al-Riyami and Kenneth G. Paterson,
*Certificateless Public Key Cryptography*, [ePrint 2003/126](https://eprint.iacr.org/2003/126).
The implementation preserves Huang–Wong's order: recover `c1` with the user secret, recover `m || mk`
with the partial key, then verify `MAC_mk(c2)`. Because authentication cannot precede those decryptions,
named internal failure stages are restricted to the omniscient classroom view and never returned by
the attacker-facing API. That result-shape boundary is not a constant-time claim. Context and identity
are additionally length-framed and committed inside the
canonical teaching encoding. This is a defensive binding adaptation; it does not repair the missing
IND-ID-CCA2 premise or turn the composition into a standardized CLE format.

## Related Demos

- [crypto-lab-pairing-gate](https://systemslibrarian.github.io/crypto-lab-pairing-gate/) — BLS signatures on the same BLS12-381 pairing this scheme is built on.
- [crypto-lab-iron-letter](https://systemslibrarian.github.io/crypto-lab-iron-letter/) — ECIES/RSA-OAEP public-key encryption, the certificate-based alternative to IBE.
- [crypto-lab-pki-chain](https://systemslibrarian.github.io/crypto-lab-pki-chain/) — X.509 certificate distribution, exactly what identity-based addressing removes.
- [crypto-lab-envelope-kms](https://systemslibrarian.github.io/crypto-lab-envelope-kms/) — centralized key management and the DEK/KEK trust model, a cousin of IBE's key escrow.

## Stack

- Vite + TypeScript strict + vanilla CSS
- `@noble/curves/bls12-381` for BLS12-381 pairing operations
- No backends. Deploys to GitHub Pages.

## The BasicIdent Scheme

```
Setup:    s ← random; P_pub = s·P ∈ G2
Extract:  d_ID = s · H₁(ID) ∈ G1
Encrypt:  r ← random; U = r·P; V = M ⊕ H₂(e(H₁(ID), P_pub)^r)
Decrypt:  M = V ⊕ H₂(e(d_ID, U))

Correctness: e(d_ID, U) = e(s·Q_ID, r·P) = e(Q_ID, P_pub)^r
```

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
