import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import {
  decrypt as decryptIBE,
  encrypt as encryptIBE,
  extract,
  setup,
  type G1Point,
  type IBESystem,
  type IBESystemParams,
} from './ibe.ts';

/**
 * Executable mechanics for the generic certificateless construction in
 * Huang--Wong (ePrint 2007/095, section 4.2):
 *
 *   c1  = IBE.Enc(mpk, ID, m || mk)
 *   c2  = PKE.Enc(upk, c1)
 *   tag = MAC_mk(c2)
 *
 * This module deliberately does NOT claim the paper's IND-CCA theorem. The
 * inner IBE in this lab is Boneh--Franklin BasicIdent (IND-CPA), while the
 * theorem requires an IND-ID-CCA2 IBE, an IND-CCA2 PKE, and a strong one-time
 * MAC. The code is a bounded, real-primitive demonstration of the ownership
 * split and attack models, not a production CLE scheme.
 */

export const CLE_MESSAGE_MAX_BYTES = 23;
export const CLE_INNER_BYTES = 56;
export const CLE_SERIALIZED_C1_BYTES = 189;
export const CLE_CONTEXT = 'crypto-lab-ibe-gate/cle-mechanics/v1';

const MAGIC = new Uint8Array([0x43, 0x4c, 0x30, 0x31]); // "CL01"
const INNER_MESSAGE_SLOT_BYTES = 24; // length byte + at most 23 message bytes
const MAC_KEY_BYTES = 32;
const ID_DIGEST_BYTES = 32;
const G2_COMPRESSED_BYTES = 96;

export interface CLESystem extends IBESystem {}

export interface CLECiphertext {
  /** RSA-OAEP encryption of the 189-byte serialized BasicIdent ciphertext. */
  c2: Uint8Array;
  /** HMAC-SHA-256 over c2, keyed by the fresh key hidden inside c1. */
  tag: Uint8Array;
}

export interface CLEPublicEnvelope extends CLECiphertext {
  identity: string;
  context: string;
}

export interface CLEDecryptResult {
  accepted: boolean;
  message?: string;
}

export type CLEFailureStage =
  | 'outer-pke'
  | 'inner-format'
  | 'identity-binding'
  | 'message-format'
  | 'mac'
  | 'accepted';

/** Omniscient teaching trace. Never expose `stage` as attacker feedback. */
export interface CLETeachingResult extends CLEDecryptResult {
  stage: CLEFailureStage;
}

export interface IdentityCertificate {
  identity: string;
  context: string;
  subjectPublicKeyInfo: Uint8Array;
  signature: Uint8Array;
}

export interface PkiCiphertext {
  ciphertext: Uint8Array;
  certificateAccepted: boolean;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function u32(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function frame(bytes: Uint8Array): Uint8Array {
  return concat(u32(bytes.length), bytes);
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

/** Copy into an ArrayBuffer-backed view accepted by TypeScript 7's WebCrypto types. */
function webBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy;
}

function canonicalIdentity(identity: string, context: string): string {
  // Length framing prevents concatenation ambiguity. The resulting hex string
  // is what BasicIdent hashes to G1, so context is cryptographically bound.
  const bytes = concat(frame(utf8('CLE-ID-v1')), frame(utf8(context)), frame(utf8(identity)));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', webBytes(bytes)));
}

async function identityDigest(identity: string, context: string): Promise<Uint8Array> {
  return sha256(concat(frame(utf8('CLE-ID-DIGEST-v1')), frame(utf8(context)), frame(utf8(identity))));
}

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

async function hmac(keyBytes: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    webBytes(keyBytes),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, webBytes(message)));
}

async function verifyHmac(
  keyBytes: Uint8Array,
  message: Uint8Array,
  tag: Uint8Array
): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    'raw',
    webBytes(keyBytes),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  return crypto.subtle.verify('HMAC', key, webBytes(tag), webBytes(message));
}

function encodePayload(message: string, macKey: Uint8Array): Uint8Array {
  const encoded = utf8(message);
  if (encoded.length > CLE_MESSAGE_MAX_BYTES) {
    throw new Error(`Message must be at most ${CLE_MESSAGE_MAX_BYTES} UTF-8 bytes`);
  }
  if (macKey.length !== MAC_KEY_BYTES) throw new Error('MAC key must be 32 bytes');

  const out = new Uint8Array(CLE_INNER_BYTES);
  out[0] = encoded.length;
  out.set(encoded, 1);
  out.set(macKey, INNER_MESSAGE_SLOT_BYTES);
  return out;
}

function decodePayload(bytes: Uint8Array): { message: string; macKey: Uint8Array } | null {
  if (bytes.length !== CLE_INNER_BYTES) return null;
  const messageLength = bytes[0];
  if (messageLength > CLE_MESSAGE_MAX_BYTES) return null;
  // Canonical zero padding makes random/wrong-key plaintext overwhelmingly
  // likely to fail before the MAC, and avoids accepting multiple encodings.
  for (let i = 1 + messageLength; i < INNER_MESSAGE_SLOT_BYTES; i++) {
    if (bytes[i] !== 0) return null;
  }
  const messageBytes = bytes.slice(1, 1 + messageLength);
  const message = new TextDecoder('utf-8', { fatal: true }).decode(messageBytes);
  if (!equalBytes(utf8(message), messageBytes)) return null;
  return { message, macKey: bytes.slice(INNER_MESSAGE_SLOT_BYTES) };
}

async function serializeInner(
  U: InstanceType<typeof bls.G2.Point>,
  V: Uint8Array,
  identity: string,
  context: string
): Promise<Uint8Array> {
  const compressed = U.toBytes(true);
  if (compressed.length !== G2_COMPRESSED_BYTES) throw new Error('Unexpected G2 encoding length');
  if (V.length !== CLE_INNER_BYTES) throw new Error('Unexpected BasicIdent payload length');
  const out = concat(MAGIC, new Uint8Array([0]), await identityDigest(identity, context), compressed, V);
  if (out.length !== CLE_SERIALIZED_C1_BYTES) throw new Error('Unexpected c1 encoding length');
  return out;
}

async function parseInner(
  bytes: Uint8Array,
  identity: string,
  context: string
): Promise<
  | { ok: true; U: InstanceType<typeof bls.G2.Point>; V: Uint8Array }
  | { ok: false; stage: 'inner-format' | 'identity-binding' }
> {
  if (bytes.length !== CLE_SERIALIZED_C1_BYTES) return { ok: false, stage: 'inner-format' };
  if (!equalBytes(bytes.slice(0, MAGIC.length), MAGIC) || bytes[MAGIC.length] !== 0) {
    return { ok: false, stage: 'inner-format' };
  }
  const digestStart = MAGIC.length + 1;
  const digestEnd = digestStart + ID_DIGEST_BYTES;
  if (!equalBytes(bytes.slice(digestStart, digestEnd), await identityDigest(identity, context))) {
    return { ok: false, stage: 'identity-binding' };
  }
  try {
    const pointEnd = digestEnd + G2_COMPRESSED_BYTES;
    const U = bls.G2.Point.fromBytes(bytes.slice(digestEnd, pointEnd));
    const V = bytes.slice(pointEnd);
    if (V.length !== CLE_INNER_BYTES) return { ok: false, stage: 'inner-format' };
    return { ok: true, U, V };
  } catch {
    return { ok: false, stage: 'inner-format' };
  }
}

export function setupCLE(): CLESystem {
  return setup(CLE_INNER_BYTES);
}

export function issuePartialPrivateKey(
  identity: string,
  context: string,
  system: CLESystem
): G1Point {
  return extract(canonicalIdentity(identity, context), system.masterKey);
}

export async function generateUserKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function encryptCLE(
  message: string,
  identity: string,
  context: string,
  params: IBESystemParams,
  userPublicKey: CryptoKey
): Promise<CLEPublicEnvelope> {
  if (params.messageBytes !== CLE_INNER_BYTES) {
    throw new Error(`CLE requires an IBE message space of ${CLE_INNER_BYTES} bytes`);
  }
  const macKey = randomBytes(MAC_KEY_BYTES);
  const innerPayload = encodePayload(message, macKey);
  const inner = await encryptIBE(innerPayload, canonicalIdentity(identity, context), params);
  const c1 = await serializeInner(inner.U, inner.V, identity, context);
  const c2 = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, userPublicKey, webBytes(c1))
  );
  const tag = await hmac(macKey, c2);
  return { c2, tag, identity, context };
}

export async function decryptCLETeaching(
  envelope: CLECiphertext,
  identity: string,
  context: string,
  params: IBESystemParams,
  partialPrivateKey: G1Point,
  userPrivateKey: CryptoKey
): Promise<CLETeachingResult> {
  let serialized: Uint8Array;
  try {
    serialized = new Uint8Array(
      await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, userPrivateKey, webBytes(envelope.c2))
    );
  } catch {
    return { accepted: false, stage: 'outer-pke' };
  }

  const parsed = await parseInner(serialized, identity, context);
  if (!parsed.ok) return { accepted: false, stage: parsed.stage };

  const plaintext = await decryptIBE(
    { U: parsed.U, V: parsed.V },
    partialPrivateKey,
    params
  );
  let decoded: ReturnType<typeof decodePayload>;
  try {
    decoded = decodePayload(plaintext);
  } catch {
    decoded = null;
  }
  if (!decoded) return { accepted: false, stage: 'message-format' };
  if (!(await verifyHmac(decoded.macKey, envelope.c2, envelope.tag))) {
    return { accepted: false, stage: 'mac' };
  }
  return { accepted: true, message: decoded.message, stage: 'accepted' };
}

/**
 * Recipient API: a single accept/reject bit plus plaintext only on success.
 * It intentionally collapses named internal failure stages into one explicit
 * response. This teaching code does not claim constant-time execution; timing
 * and microarchitectural side channels are outside this browser model.
 */
export async function decryptCLE(
  envelope: CLECiphertext,
  identity: string,
  context: string,
  params: IBESystemParams,
  partialPrivateKey: G1Point,
  userPrivateKey: CryptoKey
): Promise<CLEDecryptResult> {
  const result = await decryptCLETeaching(
    envelope,
    identity,
    context,
    params,
    partialPrivateKey,
    userPrivateKey
  );
  return result.accepted
    ? { accepted: true, message: result.message }
    : { accepted: false };
}

/**
 * Type-I adversary: may replace a public key, but this API has no target
 * partial-key or master-secret input. It runs the inner operation with the
 * public G1 generator as an explicit attacker-chosen key guess.
 */
export async function typeIAttempt(
  envelope: CLECiphertext,
  targetIdentity: string,
  context: string,
  params: IBESystemParams,
  replacementPrivateKey: CryptoKey
): Promise<CLEDecryptResult> {
  return decryptCLE(
    envelope,
    targetIdentity,
    context,
    params,
    bls.G1.Point.BASE,
    replacementPrivateKey
  );
}

/**
 * Type-II adversary: knows the KGC side. This API has no user-secret or
 * replacement-key input; it creates an unrelated key internally for the
 * attempted outer decryption.
 */
export async function typeIIAttempt(
  envelope: CLECiphertext,
  targetIdentity: string,
  context: string,
  params: IBESystemParams,
  targetPartialKey: G1Point
): Promise<CLEDecryptResult> {
  const unrelated = await generateUserKeyPair();
  return decryptCLE(
    envelope,
    targetIdentity,
    context,
    params,
    targetPartialKey,
    unrelated.privateKey
  );
}

function certificatePayload(identity: string, context: string, spki: Uint8Array): Uint8Array {
  return concat(
    frame(utf8('CRYPTO-LAB-PKI-CERT-v1')),
    frame(utf8(context)),
    frame(utf8(identity)),
    frame(spki)
  );
}

export async function generateCertificateAuthority(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
}

export async function issueCertificate(
  identity: string,
  context: string,
  userPublicKey: CryptoKey,
  caPrivateKey: CryptoKey
): Promise<IdentityCertificate> {
  const subjectPublicKeyInfo = new Uint8Array(await crypto.subtle.exportKey('spki', userPublicKey));
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      caPrivateKey,
      webBytes(certificatePayload(identity, context, subjectPublicKeyInfo))
    )
  );
  return { identity, context, subjectPublicKeyInfo, signature };
}

export async function verifyCertificate(
  certificate: IdentityCertificate,
  expectedIdentity: string,
  expectedContext: string,
  caPublicKey: CryptoKey
): Promise<boolean> {
  if (
    certificate.identity !== expectedIdentity ||
    certificate.context !== expectedContext
  ) {
    return false;
  }
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    caPublicKey,
    webBytes(certificate.signature),
    webBytes(certificatePayload(
      certificate.identity,
      certificate.context,
      certificate.subjectPublicKeyInfo
    ))
  );
}

export async function encryptPKI(
  message: Uint8Array,
  identity: string,
  context: string,
  certificate: IdentityCertificate,
  caPublicKey: CryptoKey
): Promise<PkiCiphertext> {
  const certificateAccepted = await verifyCertificate(
    certificate,
    identity,
    context,
    caPublicKey
  );
  if (!certificateAccepted) throw new Error('Certificate rejected');
  const publicKey = await crypto.subtle.importKey(
    'spki',
    webBytes(certificate.subjectPublicKeyInfo),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
  );
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, webBytes(message))
  );
  return { ciphertext, certificateAccepted };
}

export async function decryptPKI(
  ciphertext: Uint8Array,
  userPrivateKey: CryptoKey
): Promise<Uint8Array | null> {
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, userPrivateKey, webBytes(ciphertext))
    );
  } catch {
    return null;
  }
}

