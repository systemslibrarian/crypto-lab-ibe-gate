import { describe, it, expect } from 'vitest';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import {
  setup,
  extract,
  encrypt,
  decrypt,
  verifyPairingIdentity,
  demonstrateBilinearity,
} from '../src/ibe.ts';
import {
  BLS12_381,
  pairing,
  gtPow,
  gtEquals,
  hashToG1,
  hashGTtoBytes,
  xorBytes,
  randomScalar,
} from '../src/pairing.ts';

/**
 * Crypto unit tests for the Boneh-Franklin BasicIdent IBE demo.
 *
 * These tests exercise the ACTUAL pairing math the UI relies on. They would
 * catch:
 *   - a broken/mocked pairing (round-trip would fail, or forgeries decrypt),
 *   - a non-bilinear map (bilinearity identity would fail),
 *   - a swapped G1/G2 or wrong-order pairing call,
 *   - an H₂ that isn't deterministic (mask would differ sender vs recipient).
 */

const M32 = () => {
  const m = new Uint8Array(32);
  for (let i = 0; i < 32; i++) m[i] = (i * 7 + 3) & 0xff;
  return m;
};

describe('pairing primitives (BLS12-381)', () => {
  it('bilinearity: e(a·P, b·Q) == e(P, Q)^(a·b)', () => {
    const { equal } = demonstrateBilinearity();
    expect(equal).toBe(true);
  });

  it('bilinearity holds for fixed known scalars a=3, b=5', () => {
    const P = BLS12_381.G1.Point.BASE;
    const Q = BLS12_381.G2.Point.BASE;
    const a = 3n;
    const b = 5n;
    const left = pairing(P.multiply(a), Q.multiply(b));
    const right = gtPow(pairing(P, Q), (a * b) % BLS12_381.r);
    expect(gtEquals(left, right)).toBe(true);
  });

  it('pairing is non-degenerate: e(P, Q) != 1 (GT identity)', () => {
    const P = BLS12_381.G1.Point.BASE;
    const Q = BLS12_381.G2.Point.BASE;
    const e = pairing(P, Q);
    const one = bls.fields.Fp12.ONE;
    expect(gtEquals(e, one)).toBe(false);
  });

  it('bilinearity is symmetric across which side carries the scalar', () => {
    // e(s·Q_ID, r·P) == e(Q_ID, s·P)^r  — the core IBE decryption identity.
    const Q_ID = hashToG1('alice@example.com');
    const P = BLS12_381.G2.Point.BASE;
    const s = randomScalar();
    const r = randomScalar();
    const lhs = pairing(Q_ID.multiply(s), P.multiply(r)); // e(d_ID, U)
    const rhs = gtPow(pairing(Q_ID, P.multiply(s)), r); // e(Q_ID, P_pub)^r
    expect(gtEquals(lhs, rhs)).toBe(true);
  });
});

describe('hashToG1 (H₁, RFC 9380 hash-to-curve)', () => {
  it('is deterministic for the same identity', () => {
    const a = hashToG1('bob@acme.com');
    const b = hashToG1('bob@acme.com');
    expect(a.equals(b)).toBe(true);
  });

  it('maps distinct identities to distinct points', () => {
    const a = hashToG1('bob@acme.com');
    const b = hashToG1('bob@acme.org');
    expect(a.equals(b)).toBe(false);
  });

  it('produces points in the correct prime-order subgroup', () => {
    const p = hashToG1('carol@example.com');
    // Point must be valid and on-curve; assertValidity throws otherwise.
    expect(() => p.assertValidity()).not.toThrow();
  });
});

describe('hashGTtoBytes (H₂)', () => {
  it('is deterministic and length-correct', async () => {
    const gt = pairing(BLS12_381.G1.Point.BASE, BLS12_381.G2.Point.BASE);
    const a = await hashGTtoBytes(gt, 32);
    const b = await hashGTtoBytes(gt, 32);
    expect(a.length).toBe(32);
    expect(Array.from(a)).toEqual(Array.from(b));
  });

  it('different GT elements yield different digests', async () => {
    const gt1 = pairing(BLS12_381.G1.Point.BASE, BLS12_381.G2.Point.BASE);
    const gt2 = gtPow(gt1, 2n);
    const a = await hashGTtoBytes(gt1, 32);
    const b = await hashGTtoBytes(gt2, 32);
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });

  it('counter-mode XOF extends past 32 bytes correctly', async () => {
    const gt = pairing(BLS12_381.G1.Point.BASE, BLS12_381.G2.Point.BASE);
    const long = await hashGTtoBytes(gt, 64);
    const short = await hashGTtoBytes(gt, 32);
    expect(long.length).toBe(64);
    // First 32 bytes come from counter 0, identical to the 32-byte request.
    expect(Array.from(long.subarray(0, 32))).toEqual(Array.from(short));
  });
});

describe('xorBytes', () => {
  it('is an involution: x ⊕ k ⊕ k == x', () => {
    const x = M32();
    const k = new Uint8Array(32).map(() => (Math.random() * 256) | 0);
    expect(Array.from(xorBytes(xorBytes(x, k), k))).toEqual(Array.from(x));
  });

  it('throws on length mismatch', () => {
    expect(() => xorBytes(new Uint8Array(4), new Uint8Array(5))).toThrow();
  });
});

describe('IBE end-to-end (BasicIdent)', () => {
  it('setup produces P_pub = s·P', () => {
    const sys = setup(32);
    const expected = sys.params.P.multiply(sys.masterKey.s);
    expect(sys.params.Ppub.equals(expected)).toBe(true);
  });

  it('round-trip: decrypt(extract, encrypt(M)) == M', async () => {
    const sys = setup(32);
    const id = 'alice@example.com';
    const M = M32();
    const ct = await encrypt(M, id, sys.params);
    const d_ID = extract(id, sys.masterKey);
    const out = await decrypt(ct, d_ID, sys.params);
    expect(Array.from(out)).toEqual(Array.from(M));
  });

  it('round-trip works for a variety of identities', async () => {
    const sys = setup(32);
    for (const id of ['', 'a', 'CEO@acme.com', 'bob@x.io || 2026-07-11', '👤@u.ni']) {
      const M = M32();
      const ct = await encrypt(M, id, sys.params);
      const out = await decrypt(ct, extract(id, sys.masterKey), sys.params);
      expect(Array.from(out), `id=${id}`).toEqual(Array.from(M));
    }
  });

  it('wrong identity key does NOT recover the plaintext', async () => {
    const sys = setup(32);
    const M = M32();
    const ct = await encrypt(M, 'alice@example.com', sys.params);
    const wrongKey = extract('mallory@example.com', sys.masterKey);
    const out = await decrypt(ct, wrongKey, sys.params);
    expect(Array.from(out)).not.toEqual(Array.from(M));
  });

  it('wrong master secret (foreign PKG) does NOT recover the plaintext', async () => {
    const sysA = setup(32);
    const sysB = setup(32); // independent PKG, different s
    const M = M32();
    const ct = await encrypt(M, 'alice@example.com', sysA.params);
    // Correct identity, but key from the wrong system.
    const foreignKey = extract('alice@example.com', sysB.masterKey);
    const out = await decrypt(ct, foreignKey, sysA.params);
    expect(Array.from(out)).not.toEqual(Array.from(M));
  });

  it('encrypt rejects messages of the wrong length', async () => {
    const sys = setup(32);
    await expect(encrypt(new Uint8Array(16), 'x', sys.params)).rejects.toThrow();
  });

  it('correctness identity e(d_ID,U) == e(Q_ID,P_pub)^r holds byte-for-byte', async () => {
    const sys = setup(32);
    const id = 'proof@example.com';
    const ct = await encrypt(M32(), id, sys.params);
    const d_ID = extract(id, sys.masterKey);
    const { recipientGt, senderGt, equal } = verifyPairingIdentity(ct, d_ID);
    expect(equal).toBe(true);
    // Explicit byte-for-byte over the raw Fp12 serialization.
    expect(gtEquals(recipientGt, senderGt)).toBe(true);
  });

  it('key escrow: PKG-derived key decrypts any identity (architectural tradeoff)', async () => {
    const sys = setup(32);
    const M = M32();
    const target = 'victim@example.com';
    const ct = await encrypt(M, target, sys.params);
    // PKG never saw the user's key but derives it from the master secret.
    const escrowKey = extract(target, sys.masterKey);
    const out = await decrypt(ct, escrowKey, sys.params);
    expect(Array.from(out)).toEqual(Array.from(M));
  });

  it('two encryptions of the same message differ (fresh randomness r)', async () => {
    const sys = setup(32);
    const M = M32();
    const c1 = await encrypt(M, 'a@b.c', sys.params);
    const c2 = await encrypt(M, 'a@b.c', sys.params);
    // U = r·P must differ; V must differ too.
    expect(c1.U.equals(c2.U)).toBe(false);
    expect(Array.from(c1.V)).not.toEqual(Array.from(c2.V));
    // But both still decrypt to M.
    const k = extract('a@b.c', sys.masterKey);
    expect(Array.from(await decrypt(c1, k, sys.params))).toEqual(Array.from(M));
    expect(Array.from(await decrypt(c2, k, sys.params))).toEqual(Array.from(M));
  });
});
