# crypto-lab-ibe-gate

## What It Is

Browser-based demo of Boneh-Franklin Identity-Based Encryption (IBE), implementing the 2001
BasicIdent scheme from "Identity-Based Encryption from the Weil Pairing" (Boneh & Franklin).
Uses BLS12-381 pairings via `@noble/curves` for the bilinear map e: G1 × G2 → GT. All IBE
protocol steps — setup, extract, encrypt, decrypt — implemented from the original paper.
Demonstrates encryption to unenrolled recipients, time-limited capabilities via identity string
policy, role-based encryption, and the fundamental key-escrow tradeoff where the Private Key
Generator can decrypt any message in the system.

## When to Use It

- Understanding how IBE eliminates certificate distribution in favor of identity-based addressing
- Teaching bilinear pairings through a complete protocol (setup to decrypt, not just pairing primitives)
- Evaluating IBE for enterprise email encryption, regulated industries, or policy-encoded access control
- Comparing IBE's centralized trust model to PKI, Signal Protocol, and threshold schemes
- **Not for:** applications requiring key escrow resistance (use PKI or end-to-end schemes with forward secrecy); the PKG is a single point of compromise in BasicIdent
- Do NOT use this in production — it is a from-the-paper teaching implementation (pure-TypeScript pairings, BasicIdent/IND-CPA only), not a hardened IBE library.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-ibe-gate](https://systemslibrarian.github.io/crypto-lab-ibe-gate/)**

Run the full Boneh-Franklin BasicIdent protocol in the browser: a Private Key Generator runs setup, extracts a private key for an identity string, and you encrypt a message to any identity and decrypt it — every step over real BLS12-381 pairings via `@noble/curves`. The demo shows encryption to unenrolled recipients, time-limited and role-based identities encoded directly in the identity string, and makes the key-escrow tradeoff concrete by letting the PKG's master secret derive any user's key.

## What Can Go Wrong

- **The PKG can decrypt every message.** Master secret `s` lets PKG derive any identity's private key. This is architectural, not a bug. Organizations deploying IBE must either accept this (for compliance) or use Hierarchical/Threshold/Distributed variants.
- BasicIdent is IND-CPA but not IND-CCA. An active attacker can modify ciphertexts. Production systems use FullIdent (Boneh-Franklin 2001 Section 4.2) with a Fujisaki-Okamoto transform for IND-CCA security.
- Private keys must be transmitted securely from PKG to user. This requires out-of-band authentication — the PKG has to know the user is who they claim to be before issuing `d_ID`.
- Revocation is hard. Unlike PKI where certificates can be revoked, an issued IBE private key is valid forever for that identity. Workarounds use short-lived identities (email || timestamp) or include revocation lists.
- BLS12-381 pairings are computationally expensive. Pure TypeScript pairing takes ~100ms in a browser. Production deployments use C/Rust/assembly with optimized pairing libraries.

## Real-World Usage

Introduced by Adi Shamir in 1984 as a concept; first practical construction by Dan Boneh and Matthew Franklin at CRYPTO 2001. Full version published in SIAM Journal on Computing (2003). Real-world deployments include Voltage Security (now Micro Focus SecureMail, enterprise email encryption), TrendMicro PrivateKey (secure document sharing), IEEE 1363.3 standardization, and research deployments in healthcare and government systems. Hierarchical IBE (HIBE) extends the scheme to multi-level PKG structures; threshold IBE distributes the master secret. The underlying bilinear pairing is BLS12-381, the same curve used in Ethereum 2.0, Filecoin, Chia, and Zcash for BLS aggregated signatures.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-ibe-gate
cd crypto-lab-ibe-gate
npm install
npm run dev
```

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

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
