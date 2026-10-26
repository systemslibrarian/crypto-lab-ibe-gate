import { beforeAll, describe, expect, it } from 'vitest';
import {
  CLE_CONTEXT,
  CLE_INNER_BYTES,
  CLE_MESSAGE_MAX_BYTES,
  CLE_SERIALIZED_C1_BYTES,
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
  verifyCertificate,
  type CLEPublicEnvelope,
  type CLESystem,
  type IdentityCertificate,
} from '../src/certificateless.ts';
import type { G1Point } from '../src/ibe.ts';

const ID = 'student@example.edu';
const OTHER_ID = 'other@example.edu';
const MESSAGE = 'meet at noon';

function altered(bytes: Uint8Array, index = 0): Uint8Array {
  const copy = bytes.slice();
  copy[index] ^= 1;
  return copy;
}

function replace(
  envelope: CLEPublicEnvelope,
  change: Partial<Pick<CLEPublicEnvelope, 'c2' | 'tag'>>
): CLEPublicEnvelope {
  return { ...envelope, ...change };
}

describe('Huang--Wong certificateless mechanics adaptation', () => {
  let system: CLESystem;
  let user: CryptoKeyPair;
  let attacker: CryptoKeyPair;
  let targetPartial: G1Point;
  let honest: CLEPublicEnvelope;

  beforeAll(async () => {
    system = setupCLE();
    [user, attacker] = await Promise.all([generateUserKeyPair(), generateUserKeyPair()]);
    targetPartial = issuePartialPrivateKey(ID, CLE_CONTEXT, system);
    honest = await encryptCLE(MESSAGE, ID, CLE_CONTEXT, system.params, user.publicKey);
  });

  it('uses the exact bounded inner and outer sizes the RSA-OAEP envelope permits', async () => {
    expect(system.params.messageBytes).toBe(CLE_INNER_BYTES);
    expect(CLE_SERIALIZED_C1_BYTES).toBe(189);
    expect(honest.c2).toHaveLength(256);
    expect(honest.tag).toHaveLength(32);

    const c1 = new Uint8Array(
      await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, user.privateKey, honest.c2)
    );
    expect(c1).toHaveLength(CLE_SERIALIZED_C1_BYTES);
    expect(new TextDecoder().decode(c1.slice(0, 4))).toBe('CL01');
  });

  it('requires both the target partial key and target user secret to recover the message', async () => {
    await expect(
      decryptCLE(honest, ID, CLE_CONTEXT, system.params, targetPartial, user.privateKey)
    ).resolves.toEqual({ accepted: true, message: MESSAGE });
  });

  it('draws a fresh one-time MAC key and encryption randomness for every envelope', async () => {
    const next = await encryptCLE(MESSAGE, ID, CLE_CONTEXT, system.params, user.publicKey);
    expect(next.c2).not.toEqual(honest.c2);
    expect(next.tag).not.toEqual(honest.tag);
  });

  it('enforces the documented UTF-8 message bound without truncation', async () => {
    const exact = 'x'.repeat(CLE_MESSAGE_MAX_BYTES);
    const envelope = await encryptCLE(exact, ID, CLE_CONTEXT, system.params, user.publicKey);
    await expect(
      decryptCLE(envelope, ID, CLE_CONTEXT, system.params, targetPartial, user.privateKey)
    ).resolves.toEqual({ accepted: true, message: exact });
    await expect(
      encryptCLE(`${exact}x`, ID, CLE_CONTEXT, system.params, user.publicKey)
    ).rejects.toThrow(`at most ${CLE_MESSAGE_MAX_BYTES} UTF-8 bytes`);
    await expect(
      encryptCLE('🙂'.repeat(6), ID, CLE_CONTEXT, system.params, user.publicKey)
    ).rejects.toThrow(`at most ${CLE_MESSAGE_MAX_BYTES} UTF-8 bytes`);
  });

  it('rejects tag tampering using the recovered one-time key', async () => {
    const result = await decryptCLETeaching(
      replace(honest, { tag: altered(honest.tag, 9) }),
      ID,
      CLE_CONTEXT,
      system.params,
      targetPartial,
      user.privateKey
    );
    expect(result).toEqual({ accepted: false, stage: 'mac' });
  });

  it('rejects outer-ciphertext tampering rather than treating random corruption as CLE', async () => {
    const result = await decryptCLETeaching(
      replace(honest, { c2: altered(honest.c2, 17) }),
      ID,
      CLE_CONTEXT,
      system.params,
      targetPartial,
      user.privateKey
    );
    expect(result).toEqual({ accepted: false, stage: 'outer-pke' });
  });

  it('binds the identity and construction context', async () => {
    const wrongIdentity = await decryptCLE(
      honest,
      OTHER_ID,
      CLE_CONTEXT,
      system.params,
      targetPartial,
      user.privateKey
    );
    const wrongContext = await decryptCLE(
      honest,
      ID,
      `${CLE_CONTEXT}/other`,
      system.params,
      targetPartial,
      user.privateKey
    );
    expect(wrongIdentity).toEqual({ accepted: false });
    expect(wrongContext).toEqual({ accepted: false });
  });

  it('does not expose the teaching failure stage through the recipient API', async () => {
    const result = await decryptCLE(
      replace(honest, { tag: altered(honest.tag) }),
      ID,
      CLE_CONTEXT,
      system.params,
      targetPartial,
      user.privateKey
    );
    expect(result).toEqual({ accepted: false });
    expect(result).not.toHaveProperty('stage');
  });

  it('models a Type-I key-replacement adversary without handing it the target partial key', async () => {
    // A sender follows the replaced directory entry, so the attacker can undo
    // the outer RSA layer. The actor API has no partial-key input and makes an
    // explicit public group-element guess for the inner operation.
    const replacedKeyEnvelope = await encryptCLE(
      MESSAGE,
      ID,
      CLE_CONTEXT,
      system.params,
      attacker.publicKey
    );
    await expect(
      typeIAttempt(
        replacedKeyEnvelope,
        ID,
        CLE_CONTEXT,
        system.params,
        attacker.privateKey
      )
    ).resolves.toEqual({ accepted: false });

    // This also demonstrates the availability consequence: the honest user no
    // longer owns the outer key selected by the sender.
    await expect(
      decryptCLE(
        replacedKeyEnvelope,
        ID,
        CLE_CONTEXT,
        system.params,
        targetPartial,
        user.privateKey
      )
    ).resolves.toEqual({ accepted: false });

    // Combining BOTH forbidden capabilities is the control that succeeds.
    await expect(
      decryptCLE(
        replacedKeyEnvelope,
        ID,
        CLE_CONTEXT,
        system.params,
        targetPartial,
        attacker.privateKey
      )
    ).resolves.toEqual({ accepted: true, message: MESSAGE });
  });

  it('models a Type-II KGC adversary without handing it the target user secret', async () => {
    await expect(
      typeIIAttempt(
        honest,
        ID,
        CLE_CONTEXT,
        system.params,
        targetPartial
      )
    ).resolves.toEqual({ accepted: false });
  });

  it('does not accept either adversary class forbidden target capability as an input', () => {
    expect(typeIAttempt.length).toBe(5); // no target partial key / KGC master argument
    expect(typeIIAttempt.length).toBe(5); // no target user secret / replacement argument
  });

  it('rejects an unrelated user secret even when the target partial key is correct', async () => {
    await expect(
      decryptCLE(honest, ID, CLE_CONTEXT, system.params, targetPartial, attacker.privateKey)
    ).resolves.toEqual({ accepted: false });
  });
});

describe('executable PKI comparison', () => {
  let ca: CryptoKeyPair;
  let compromisedCa: CryptoKeyPair;
  let user: CryptoKeyPair;
  let attacker: CryptoKeyPair;
  let certificate: IdentityCertificate;

  beforeAll(async () => {
    [ca, compromisedCa, user, attacker] = await Promise.all([
      generateCertificateAuthority(),
      generateCertificateAuthority(),
      generateUserKeyPair(),
      generateUserKeyPair(),
    ]);
    certificate = await issueCertificate(ID, CLE_CONTEXT, user.publicKey, ca.privateKey);
  });

  it('verifies a real P-256 CA signature before using the certified RSA key', async () => {
    await expect(
      verifyCertificate(certificate, ID, CLE_CONTEXT, ca.publicKey)
    ).resolves.toBe(true);
    const encrypted = await encryptPKI(
      new TextEncoder().encode(MESSAGE),
      ID,
      CLE_CONTEXT,
      certificate,
      ca.publicKey
    );
    expect(encrypted.certificateAccepted).toBe(true);
    const plaintext = await decryptPKI(encrypted.ciphertext, user.privateKey);
    expect(new TextDecoder().decode(plaintext!)).toBe(MESSAGE);
  });

  it('rejects identity, context, key, and signature substitutions', async () => {
    const attackerCertificate = await issueCertificate(
      ID,
      CLE_CONTEXT,
      attacker.publicKey,
      compromisedCa.privateKey
    );
    const badSignature = { ...certificate, signature: altered(certificate.signature) };
    await expect(verifyCertificate(certificate, OTHER_ID, CLE_CONTEXT, ca.publicKey)).resolves.toBe(false);
    await expect(verifyCertificate(certificate, ID, `${CLE_CONTEXT}/other`, ca.publicKey)).resolves.toBe(false);
    await expect(verifyCertificate(attackerCertificate, ID, CLE_CONTEXT, ca.publicKey)).resolves.toBe(false);
    await expect(verifyCertificate(badSignature, ID, CLE_CONTEXT, ca.publicKey)).resolves.toBe(false);
  });

  it('shows exactly what CA compromise changes: future routing, not old RSA ciphertexts', async () => {
    const recorded = await encryptPKI(
      new TextEncoder().encode(MESSAGE),
      ID,
      CLE_CONTEXT,
      certificate,
      ca.publicKey
    );
    expect(await decryptPKI(recorded.ciphertext, attacker.privateKey)).toBeNull();

    const forged = await issueCertificate(
      ID,
      CLE_CONTEXT,
      attacker.publicKey,
      ca.privateKey
    );
    const future = await encryptPKI(
      new TextEncoder().encode('future message'),
      ID,
      CLE_CONTEXT,
      forged,
      ca.publicKey
    );
    const recovered = await decryptPKI(future.ciphertext, attacker.privateKey);
    expect(new TextDecoder().decode(recovered!)).toBe('future message');
  });
});
