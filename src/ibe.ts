import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import {
  BLS12_381,
  randomScalar,
  pairing,
  gtPow,
  gtEquals,
  hashToG1,
  hashGTtoBytes,
  xorBytes,
  type G1Point,
  type G2Point,
  type GTElement,
} from './pairing.ts';

export type { G1Point, G2Point, GTElement };

export interface IBESystemParams {
  P: G2Point;           // generator in G2
  Ppub: G2Point;        // master public key = s · P
  messageBytes: number; // output length for H₂ (e.g. 32 for AES-256 key)
}

export interface IBEMasterKey {
  s: bigint; // master secret scalar
}

export interface IBESystem {
  params: IBESystemParams;
  masterKey: IBEMasterKey;
}

export interface IBECiphertext {
  U: G2Point;        // r · P
  V: Uint8Array;     // M ⊕ H₂(g_ID^r)
  identity: string;  // displayed for demo; not sent in real deployment
  /**
   * DEMO ONLY — NOT part of a real ciphertext and NEVER transmitted.
   * The encryption-side group element g_ID^r = e(Q_ID, P_pub)^r. We retain it
   * so the UI can prove, byte-for-byte, that the recipient's independently
   * computed e(d_ID, U) lands on the exact same GT element. In a real
   * deployment r is discarded the instant encryption finishes.
   */
  _demoGtMask: GTElement;
}

/**
 * SETUP: Run ONCE by the Private Key Generator (PKG).
 * Produces system-wide parameters and master secret.
 */
export function setup(messageBytes: number = 32): IBESystem {
  // G2 generator P
  const P = bls.G2.Point.BASE as G2Point;

  // Random master secret s ∈ [1, r-1]
  const s = randomScalar();

  // P_pub = s · P in G2
  const Ppub = P.multiply(s) as G2Point;

  return {
    params: { P, Ppub, messageBytes },
    masterKey: { s },
  };
}

/**
 * DEMO: the bilinearity property that makes the whole scheme possible.
 *
 *   e(a·P, b·Q) = e(P, Q)^(a·b)
 *
 * IBE decryption is just this identity applied with a = s (master secret,
 * folded into d_ID) and b = r (the sender's random scalar). We pick random
 * a, b, compute each side independently, and compare byte-for-byte.
 */
export function demonstrateBilinearity(): {
  a: bigint;
  b: bigint;
  left: GTElement;  // e(a·P, b·Q)
  right: GTElement; // e(P, Q)^(a·b)
  equal: boolean;
} {
  const P = BLS12_381.G1.Point.BASE as G1Point;
  const Q = BLS12_381.G2.Point.BASE as G2Point;
  const a = randomScalar();
  const b = randomScalar();

  const left = pairing(P.multiply(a) as G1Point, Q.multiply(b) as G2Point);
  const right = gtPow(pairing(P, Q), (a * b) % BLS12_381.r);

  return { a, b, left, right, equal: gtEquals(left, right) };
}

/**
 * EXTRACT: PKG derives a private key for a given identity.
 * This is the step that requires PKG trust.
 *
 * d_ID = s · H₁(ID) ∈ G1
 */
export function extract(
  identity: string,
  masterKey: IBEMasterKey
): G1Point {
  const Q_ID = hashToG1(identity);
  return Q_ID.multiply(masterKey.s) as G1Point;
}

/**
 * ENCRYPT: Anyone with system params can encrypt to any identity.
 * No certificate lookup, no key distribution.
 *
 * r = random scalar
 * U = r · P
 * g_ID = e(H₁(ID), P_pub)
 * V = M ⊕ H₂(g_ID^r)
 */
export async function encrypt(
  message: Uint8Array,
  identity: string,
  params: IBESystemParams
): Promise<IBECiphertext> {
  if (message.length !== params.messageBytes) {
    throw new Error(
      `Message must be exactly ${params.messageBytes} bytes, got ${message.length}`
    );
  }

  const Q_ID = hashToG1(identity);

  // Random encryption scalar (called 'rnd' to avoid shadowing module scope)
  const rnd = randomScalar();

  // U = rnd · P in G2
  const U = params.P.multiply(rnd) as G2Point;

  // g_ID = e(Q_ID, P_pub) in G_T
  const g_ID = pairing(Q_ID, params.Ppub);

  // g_ID^rnd in G_T
  const g_ID_r = gtPow(g_ID, rnd);

  // V = M ⊕ H₂(g_ID^rnd)
  const mask = await hashGTtoBytes(g_ID_r, params.messageBytes);
  const V = xorBytes(message, mask);

  return { U, V, identity, _demoGtMask: g_ID_r };
}

/**
 * DECRYPT: Recipient with their extracted private key d_ID.
 *
 *   M = V ⊕ H₂(e(d_ID, U))
 */
export async function decrypt(
  ciphertext: IBECiphertext,
  privateKey: G1Point,
  params: IBESystemParams
): Promise<Uint8Array> {
  // e(d_ID, U) — d_ID in G1, U in G2
  const gt = pairing(privateKey, ciphertext.U);
  const mask = await hashGTtoBytes(gt, params.messageBytes);
  return xorBytes(ciphertext.V, mask);
}

/**
 * DEMO: prove the Boneh-Franklin correctness identity holds for THIS ciphertext.
 *
 * The recipient computes  e(d_ID, U).
 * The sender had computed  e(Q_ID, P_pub)^r  (retained as _demoGtMask).
 * The theorem says these are the same GT element. We don't assert it — we
 * recompute the recipient side and compare the two byte-for-byte.
 *
 *   e(d_ID, U) = e(s·Q_ID, r·P) = e(Q_ID, P)^(s·r) = e(Q_ID, s·P)^r
 *              = e(Q_ID, P_pub)^r
 */
export function verifyPairingIdentity(
  ciphertext: IBECiphertext,
  privateKey: G1Point
): { recipientGt: GTElement; senderGt: GTElement; equal: boolean } {
  const recipientGt = pairing(privateKey, ciphertext.U); // e(d_ID, U)
  const senderGt = ciphertext._demoGtMask;               // e(Q_ID, P_pub)^r
  return { recipientGt, senderGt, equal: gtEquals(recipientGt, senderGt) };
}

/**
 * Simulate attempted decryption with the WRONG private key.
 * Returns whatever garbage M' the math produces — useful for demo.
 */
export async function decryptWrongKey(
  ciphertext: IBECiphertext,
  wrongPrivateKey: G1Point,
  params: IBESystemParams
): Promise<Uint8Array> {
  return decrypt(ciphertext, wrongPrivateKey, params);
}
