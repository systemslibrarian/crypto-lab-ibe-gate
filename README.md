# crypto-lab-ibe-gate

## What It Is

Browser-based demo of Boneh-Franklin Identity-Based Encryption (IBE), implementing the 2001
BasicIdent scheme from "Identity-Based Encryption from the Weil Pairing" (Boneh & Franklin).
Uses BLS12-381 pairings via `@noble/curves` for the bilinear map e: G1 × G2 → GT. All four IBE
algorithms — setup, extract, encrypt, decrypt — follow the paper's BasicIdent definitions.
Demonstrates encryption to unenrolled recipients, time-limited capabilities via identity string
policy, role-based encryption, and the fundamental key-escrow tradeoff where the Private Key
Generator can decrypt any message in the system.

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
- **Not for:** applications requiring key escrow resistance (use PKI or end-to-end schemes with forward secrecy); the PKG is a single point of compromise in BasicIdent
- Do NOT use this in production — it is a from-the-paper teaching implementation (pure-TypeScript pairings, BasicIdent/IND-CPA only), not a hardened IBE library.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-ibe-gate](https://systemslibrarian.github.io/crypto-lab-ibe-gate/)**

Run the full Boneh-Franklin BasicIdent protocol in the browser: a Private Key Generator runs setup, extracts a private key for an identity string, and you encrypt a message to any identity and decrypt it — every step over real BLS12-381 pairings via `@noble/curves`. The demo shows encryption to unenrolled recipients, time-limited and role-based identities encoded directly in the identity string, and makes the key-escrow tradeoff concrete by letting the PKG's master secret derive any user's key. The time-limited exhibit lets *you* play the PKG at an issuance gate — issue, refuse, or collude — to make explicit that a date baked into an identity is inert text; the time-lock is enforced by the PKG's issuance policy, not by the string, and a compromised PKG can hand out the off-date key anyway.

## What Can Go Wrong

- **The PKG can decrypt every message.** Master secret `s` lets PKG derive any identity's private key. This is architectural, not a bug. Organizations deploying IBE must either accept this (for compliance) or use Hierarchical/Threshold/Distributed variants.
- BasicIdent is IND-CPA but not IND-CCA. An active attacker can modify ciphertexts. Production systems use FullIdent (Boneh-Franklin 2001 Section 4.2) with a Fujisaki-Okamoto transform for IND-CCA security.
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
npm test        # 21 Vitest crypto unit tests (Boneh-Franklin over BLS12-381)
npm run test:a11y   # axe-core WCAG A/AA gate (Playwright, both themes)
```

The unit suite (`test/ibe.test.ts`) runs against the real `@noble/curves`
pairing — no mocks — and covers:

- **Bilinearity** `e(a·P, b·Q) = e(P, Q)^(a·b)` (random and fixed scalars) and pairing non-degeneracy.
- **The BasicIdent correctness identity** `e(d_ID, U) = e(Q_ID, P_pub)^r`, checked byte-for-byte over the raw Fp12 serialization.
- **Encrypt → extract → decrypt round-trip** for empty, single-char, role, time-limited, and Unicode identities.
- **Forgery rejection:** a wrong-identity key or a foreign PKG's master secret does NOT recover the plaintext.
- **Key escrow:** a PKG-derived key decrypts any identity (the architectural tradeoff, asserted rather than asserted-away).
- **Primitive correctness:** deterministic `H₁` hash-to-curve into the prime-order subgroup, deterministic length-correct `H₂` XOF, and semantic security via fresh randomness `r` per encryption.

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

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
