import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import {
  randomScalar,
  pairing,
  hashToG1,
  hashGTtoBytes,
  xorBytes,
  type G1Point,
  type G2Point,
} from './pairing.ts';

export type { G1Point, G2Point };

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
  const g_ID_r = bls.fields.Fp12.pow(g_ID, rnd);

  // V = M ⊕ H₂(g_ID^rnd)
  const mask = await hashGTtoBytes(g_ID_r, params.messageBytes);
  const V = xorBytes(message, mask);

  return { U, V, identity };
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
