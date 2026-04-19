import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { sha256 } from '@noble/hashes/sha2.js';

/**
 * BLS12-381 groups.
 * G1 = points on E(Fp), compressed 48 bytes
 * G2 = points on E(Fp2), compressed 96 bytes
 * GT = elements of Fp12
 * r  = group order (prime, ~255 bits)
 */
export const BLS12_381 = {
  r: bls.fields.Fr.ORDER,     // subgroup order
  G1: bls.G1,
  G2: bls.G2,
  G1_BYTES: 48,               // compressed G1 point
  G2_BYTES: 96,               // compressed G2 point
  GT_BYTES: 576,              // Fp12 element, 12 × 48 bytes
} as const;

export type G1Point = InstanceType<typeof bls.G1.Point>;
export type G2Point = InstanceType<typeof bls.G2.Point>;
export type GTElement = ReturnType<typeof bls.pairing>;

/** Generate a random scalar in [1, r-1]. */
export function randomScalar(): bigint {
  const r = BLS12_381.r;
  const byteLen = Math.ceil(r.toString(16).length / 2) + 8; // extra bytes for bias reduction
  while (true) {
    const bytes = new Uint8Array(byteLen);
    crypto.getRandomValues(bytes);
    let val = 0n;
    for (const b of bytes) {
      val = (val << 8n) | BigInt(b);
    }
    const candidate = val % (r - 1n) + 1n;
    if (candidate >= 1n && candidate < r) {
      return candidate;
    }
  }
}

/**
 * Compute the BLS12-381 pairing e: G1 × G2 → GT.
 * This is the Type 3 asymmetric pairing.
 *
 * Note: @noble/curves expects (G1, G2) order.
 */
export function pairing(g1: G1Point, g2: G2Point): GTElement {
  return bls.pairing(g1, g2);
}

/**
 * Hash an identity string to a G1 point using RFC 9380 hash-to-curve.
 * This is H₁ in the Boneh-Franklin scheme.
 */
export function hashToG1(identity: string): G1Point {
  const msg = new TextEncoder().encode(identity);
  return bls.G1.hashToCurve(msg) as G1Point;
}

/**
 * Hash a GT element to an n-byte string (H₂).
 * Serialize the GT element canonically, SHA-256, XOF if needed.
 */
export async function hashGTtoBytes(
  gt: GTElement,
  outputBytes: number
): Promise<Uint8Array> {
  const gtBytes = gtToBytes(gt);
  // Use SHA-256 repeatedly if we need more than 32 bytes (simple counter-mode XOF)
  const result = new Uint8Array(outputBytes);
  let offset = 0;
  let counter = 0;
  while (offset < outputBytes) {
    const counterByte = new Uint8Array([counter]);
    const combined = new Uint8Array(gtBytes.length + 1);
    combined.set(gtBytes);
    combined.set(counterByte, gtBytes.length);
    const hash = sha256(combined);
    const toCopy = Math.min(hash.length, outputBytes - offset);
    result.set(hash.subarray(0, toCopy), offset);
    offset += toCopy;
    counter++;
  }
  return result;
}

/** Serialize GT element to canonical bytes (576 bytes for Fp12). */
export function gtToBytes(gt: GTElement): Uint8Array {
  return bls.fields.Fp12.toBytes(gt);
}

/** XOR two byte arrays of equal length. */
export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) {
    throw new Error(`xorBytes: length mismatch ${a.length} vs ${b.length}`);
  }
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}
