import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  BLS12_381,
  randomScalar,
  pairing,
  gtPow,
  hashGTtoBytes,
  xorBytes,
  type G1Point,
  type G2Point,
  type GTElement,
} from './pairing.ts';

/**
 * Bounded teaching implementation of the asymmetric-pairing HIBE construction
 * in Ramanna–Sarkar, "Variants of Waters' Dual-System Primitives Using
 * Asymmetric Pairings", Appendix G (ePrint 2012/024).
 *
 * The paper encrypts a GT element directly. This lab uses the same HIBE
 * encapsulation/delegation algebra as a KEM/DEM teaching adaptation: the
 * recovered GT element is hashed to a fixed-length byte mask.
 *
 * This module is not a production HIBE implementation and does not claim the
 * paper's proof for this byte-message adaptation.
 */

const R = BLS12_381.r;
const Fp12 = bls.fields.Fp12;

export interface HIBEPublicParams {
  maxDepth: number;
  messageBytes: number;
  P1: G1Point;
  aP1: G1Point;
  tauP1: G1Point;
  Q1: G1Point[];
  W1: G1Point;
  U1: G1Point[];
  eggAlpha: GTElement;
}

interface HIBEDelegationParams {
  P2: G2Point;
  V2: G2Point;
  Vp2: G2Point;
  Q2: G2Point[];
  W2: G2Point;
  U2: G2Point[];
}

export interface HIBEMasterKey {
  alphaP2: G2Point;
  delegation: HIBEDelegationParams;
}

export interface HIBESystem {
  params: HIBEPublicParams;
  masterKey: HIBEMasterKey;
}

export interface HIBEPrivateKey {
  identity: string[];
  identityScalars: bigint[];
  K1: G2Point;
  K2: G2Point;
  K3: G2Point[];
  D: G2Point[];
  keyTags: bigint[];
  delegation: HIBEDelegationParams;
  origin: 'root-extraction' | 'delegation';
}

export interface HIBECiphertext {
  identity: string[];
  identityScalars: bigint[];
  C1: G1Point;
  C2: G1Point;
  C3: G1Point;
  E: G1Point[];
  cipherTags: bigint[];
  V: Uint8Array;
  /** Demo-only sender-side encapsulated GT element for correctness checks. */
  _demoShared: GTElement;
}

function mod(x: bigint): bigint {
  const y = x % R;
  return y >= 0n ? y : y + R;
}

function addPointsG1(parts: Array<{ point: G1Point; scalar: bigint }>): G1Point {
  let out = bls.G1.Point.ZERO as G1Point;
  for (const { point, scalar } of parts) {
    out = out.add(point.multiply(mod(scalar))) as G1Point;
  }
  return out;
}

function addPointsG2(parts: Array<{ point: G2Point; scalar: bigint }>): G2Point {
  let out = bls.G2.Point.ZERO as G2Point;
  for (const { point, scalar } of parts) {
    out = out.add(point.multiply(mod(scalar))) as G2Point;
  }
  return out;
}

function invMod(x: bigint): bigint {
  let a = mod(x);
  if (a === 0n) throw new Error('HIBE tag collision: inverse of zero');
  // R is prime, but extended Euclid keeps the arithmetic explicit.
  let t = 0n;
  let newT = 1n;
  let r = R;
  let newR = a;
  while (newR !== 0n) {
    const q = r / newR;
    [t, newT] = [newT, t - q * newT];
    [r, newR] = [newR, r - q * newR];
  }
  if (r !== 1n) throw new Error('HIBE scalar is not invertible');
  return mod(t);
}

function gtMul(a: GTElement, b: GTElement): GTElement {
  return Fp12.mul(a, b);
}

function gtDiv(a: GTElement, b: GTElement): GTElement {
  return Fp12.mul(a, Fp12.inv(b));
}

function bytesToScalar(bytes: Uint8Array): bigint {
  let x = 0n;
  for (const b of bytes) x = (x << 8n) | BigInt(b);
  return mod(x);
}

/**
 * Convert each textual identity component to Z_r with explicit level/domain
 * separation. The cited construction takes identity components in Z_p.
 */
export function identityComponentScalar(component: string, level: number): bigint {
  const input = new TextEncoder().encode(
    `CryptoLab-HIBE-RS-G-v1|level=${level}|${component}`,
  );
  return bytesToScalar(sha256(input));
}

function identityScalars(identity: readonly string[]): bigint[] {
  return identity.map((component, i) => identityComponentScalar(component, i + 1));
}

function validateIdentity(identity: readonly string[], maxDepth: number): void {
  if (identity.length < 1 || identity.length > maxDepth) {
    throw new Error(`HIBE identity depth must be between 1 and ${maxDepth}`);
  }
  if (identity.some((x) => x.length === 0)) {
    throw new Error('HIBE identity components must be non-empty');
  }
}

function pairedBases(
  count: number,
): { g1: G1Point[]; g2: G2Point[] } {
  const g1: G1Point[] = [];
  const g2: G2Point[] = [];
  for (let i = 0; i < count; i++) {
    const x = randomScalar();
    g1.push(bls.G1.Point.BASE.multiply(x) as G1Point);
    g2.push(bls.G2.Point.BASE.multiply(x) as G2Point);
  }
  return { g1, g2 };
}

/**
 * Setup the Appendix-G public/delegation parameters for a bounded hierarchy.
 */
export function setupHIBE(maxDepth = 3, messageBytes = 32): HIBESystem {
  if (!Number.isInteger(maxDepth) || maxDepth < 1 || maxDepth > 8) {
    throw new Error('This teaching HIBE supports maxDepth 1..8');
  }
  const P1 = bls.G1.Point.BASE as G1Point;
  const P2 = bls.G2.Point.BASE as G2Point;

  const a = randomScalar();
  const v = randomScalar();
  const vp = randomScalar();
  const alpha = randomScalar();
  const tau = mod(v + a * vp);

  const q = pairedBases(maxDepth);
  const u = pairedBases(maxDepth);
  const w = pairedBases(1);

  const V2 = P2.multiply(v) as G2Point;
  const Vp2 = P2.multiply(vp) as G2Point;
  const alphaP2 = P2.multiply(alpha) as G2Point;

  return {
    params: {
      maxDepth,
      messageBytes,
      P1,
      aP1: P1.multiply(a) as G1Point,
      tauP1: P1.multiply(tau) as G1Point,
      Q1: q.g1,
      W1: w.g1[0]!,
      U1: u.g1,
      eggAlpha: gtPow(pairing(P1, P2), alpha),
    },
    masterKey: {
      alphaP2,
      delegation: {
        P2,
        V2,
        Vp2,
        Q2: q.g2,
        W2: w.g2[0]!,
        U2: u.g2,
      },
    },
  };
}

/**
 * Fresh root extraction by the PKG for an arbitrary identity vector.
 */
export function keyGenHIBE(
  identity: readonly string[],
  masterKey: HIBEMasterKey,
  params: HIBEPublicParams,
): HIBEPrivateKey {
  validateIdentity(identity, params.maxDepth);
  const ids = identityScalars(identity);
  const randomizers = ids.map(() => randomScalar());
  const keyTags = ids.map(() => randomScalar());
  const r = randomizers.reduce((a, b) => mod(a + b), 0n);
  const d = masterKey.delegation;

  const K1 = masterKey.alphaP2.add(d.V2.multiply(r)) as G2Point;
  const K2 = d.Vp2.multiply(r) as G2Point;
  const K3: G2Point[] = [];
  const D: G2Point[] = [];

  for (let i = 0; i < ids.length; i++) {
    const ri = randomizers[i]!;
    K3.push(d.P2.multiply(ri) as G2Point);
    const base = addPointsG2([
      { point: d.Q2[i]!, scalar: ids[i]! },
      { point: d.W2, scalar: keyTags[i]! },
      { point: d.U2[i]!, scalar: 1n },
    ]);
    D.push(base.multiply(ri) as G2Point);
  }

  return {
    identity: [...identity],
    identityScalars: ids,
    K1,
    K2,
    K3,
    D,
    keyTags,
    delegation: d,
    origin: 'root-extraction',
  };
}

/**
 * Delegate from a parent key to exactly one child component without using the
 * master secret. Existing components are re-randomized as in Appendix G.
 */
export function delegateHIBE(
  parent: HIBEPrivateKey,
  childComponent: string,
  params: HIBEPublicParams,
): HIBEPrivateKey {
  if (parent.identity.length >= params.maxDepth) {
    throw new Error('Cannot delegate beyond the configured HIBE depth');
  }
  if (!childComponent) throw new Error('Child identity component must be non-empty');

  const d = parent.delegation;
  const childLevel = parent.identity.length + 1;
  const childScalar = identityComponentScalar(childComponent, childLevel);
  const deltas = parent.identity.map(() => randomScalar());
  const rChild = randomScalar();
  const childTag = randomScalar();
  const deltaSum = [...deltas, rChild].reduce((a, b) => mod(a + b), 0n);

  const K1 = parent.K1.add(d.V2.multiply(deltaSum)) as G2Point;
  const K2 = parent.K2.add(d.Vp2.multiply(deltaSum)) as G2Point;
  const K3: G2Point[] = [];
  const D: G2Point[] = [];

  for (let i = 0; i < parent.identity.length; i++) {
    const delta = deltas[i]!;
    K3.push(parent.K3[i]!.add(d.P2.multiply(delta)) as G2Point);
    const rerandBase = addPointsG2([
      { point: d.Q2[i]!, scalar: parent.identityScalars[i]! },
      { point: d.W2, scalar: parent.keyTags[i]! },
      { point: d.U2[i]!, scalar: 1n },
    ]);
    D.push(parent.D[i]!.add(rerandBase.multiply(delta)) as G2Point);
  }

  K3.push(d.P2.multiply(rChild) as G2Point);
  const childBase = addPointsG2([
    { point: d.Q2[childLevel - 1]!, scalar: childScalar },
    { point: d.W2, scalar: childTag },
    { point: d.U2[childLevel - 1]!, scalar: 1n },
  ]);
  D.push(childBase.multiply(rChild) as G2Point);

  return {
    identity: [...parent.identity, childComponent],
    identityScalars: [...parent.identityScalars, childScalar],
    K1,
    K2,
    K3,
    D,
    keyTags: [...parent.keyTags, childTag],
    delegation: d,
    origin: 'delegation',
  };
}

/**
 * Encrypt bytes to an identity vector using the paper's HIBE encapsulation,
 * then hash the encapsulated GT element as a teaching KEM/DEM mask.
 */
export async function encryptHIBE(
  message: Uint8Array,
  identity: readonly string[],
  params: HIBEPublicParams,
): Promise<HIBECiphertext> {
  validateIdentity(identity, params.maxDepth);
  if (message.length !== params.messageBytes) {
    throw new Error(`Message must be exactly ${params.messageBytes} bytes`);
  }

  const ids = identityScalars(identity);
  const s = randomScalar();
  const cipherTags = ids.map(() => randomScalar());

  const C1 = params.P1.multiply(s) as G1Point;
  const C2 = params.aP1.multiply(s) as G1Point;
  const C3 = params.W1
    .multiply(s)
    .add(params.tauP1.multiply(mod(-s))) as G1Point;

  const E = ids.map((id, i) => {
    const base = addPointsG1([
      { point: params.Q1[i]!, scalar: id },
      { point: params.W1, scalar: cipherTags[i]! },
      { point: params.U1[i]!, scalar: 1n },
    ]);
    return base.multiply(s) as G1Point;
  });

  const shared = gtPow(params.eggAlpha, s);
  const mask = await hashGTtoBytes(shared, params.messageBytes);

  return {
    identity: [...identity],
    identityScalars: ids,
    C1,
    C2,
    C3,
    E,
    cipherTags,
    V: xorBytes(message, mask),
    _demoShared: shared,
  };
}


/**
 * Recover the HIBE encapsulated GT element from the private key/ciphertext.
 */
export function recoverHIBESecret(
  ciphertext: HIBECiphertext,
  key: HIBEPrivateKey,
): GTElement {
  // Identity equality is deliberately NOT checked here. A same-depth wrong key
  // must run the actual pairing algebra and recover the wrong GT element; that
  // is what demonstrates cryptographic branch separation. Only a structural
  // depth mismatch is rejected before the math.
  if (ciphertext.E.length !== key.K3.length) {
    throw new Error('HIBE ciphertext/key depth mismatch');
  }

  let A1 = Fp12.ONE as GTElement;
  for (let i = 0; i < ciphertext.E.length; i++) {
    const diff = mod(ciphertext.cipherTags[i]! - key.keyTags[i]!);
    if (diff === 0n) throw new Error('HIBE cipher/key tag collision');
    const numerator = pairing(ciphertext.E[i]!, key.K3[i]!);
    const denominator = pairing(ciphertext.C1, key.D[i]!);
    const term = gtPow(gtDiv(numerator, denominator), invMod(diff));
    A1 = gtMul(A1, term);
  }

  let sumK3 = bls.G2.Point.ZERO as G2Point;
  for (const point of key.K3) sumK3 = sumK3.add(point) as G2Point;

  const A2 = gtMul(
    gtMul(pairing(ciphertext.C1, key.K1), pairing(ciphertext.C2, key.K2)),
    pairing(ciphertext.C3, sumK3),
  );

  // Paper: M = (C0 * A1) / A2. Therefore encapsulated secret = A2 / A1.
  return gtDiv(A2, A1);
}

export async function decryptHIBE(
  ciphertext: HIBECiphertext,
  key: HIBEPrivateKey,
  params: HIBEPublicParams,
): Promise<Uint8Array> {
  const shared = recoverHIBESecret(ciphertext, key);
  const mask = await hashGTtoBytes(shared, params.messageBytes);
  return xorBytes(ciphertext.V, mask);
}

/** Prefix relation used by the learner's subtree-compromise experiment. */
export function isIdentityPrefix(
  prefix: readonly string[],
  identity: readonly string[],
): boolean {
  return prefix.length <= identity.length && prefix.every((x, i) => x === identity[i]);
}
