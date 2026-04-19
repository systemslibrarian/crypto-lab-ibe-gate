import {
  type IBESystem,
  type IBECiphertext,
  type G1Point,
  setup,
  extract,
  encrypt,
  decrypt,
} from './ibe.ts';

/**
 * SCENARIO 1: Encrypted email to an identity that hasn't been
 * enrolled yet.
 *
 * Alice encrypts to bob@newcompany.com. Bob hasn't enrolled yet.
 * Later Bob enrolls, gets his private key, and decrypts.
 */
export interface EmailScenario {
  sender: string;
  recipient: string;
  message: string;
  ciphertext: IBECiphertext;
  decryptedSuccessfully: boolean;
  decryptedMessage: string;
}

export async function simulateEncryptedEmail(
  sender: string,
  recipient: string,
  message: string,
  system: IBESystem
): Promise<EmailScenario> {
  const msgBytes = new TextEncoder().encode(message.padEnd(system.params.messageBytes, '\0'));
  const padded = msgBytes.slice(0, system.params.messageBytes);

  const ciphertext = await encrypt(padded, recipient, system.params);

  // Bob enrolls later
  const bobKey: G1Point = extract(recipient, system.masterKey);

  const decrypted = await decrypt(ciphertext, bobKey, system.params);
  const decryptedMessage = new TextDecoder().decode(decrypted).replace(/\0+$/, '');

  return {
    sender,
    recipient,
    message,
    ciphertext,
    decryptedSuccessfully: decryptedMessage === message,
    decryptedMessage,
  };
}

/**
 * SCENARIO 2: Time-limited capability.
 *
 * Alice encrypts to "bob@example.com || date".
 * Bob can only decrypt on that specific date.
 */
export async function simulateTimeLimitedMessage(
  recipient: string,
  validDate: string,
  message: string,
  system: IBESystem
): Promise<{
  identity: string;
  ciphertext: IBECiphertext;
  decryptedSuccessfully: boolean;
  wrongDateFails: boolean;
}> {
  const identity = `${recipient} || ${validDate}`;
  const wrongIdentity = `${recipient} || 9999-01-01`;

  const msgBytes = new TextEncoder().encode(message.padEnd(system.params.messageBytes, '\0'));
  const padded = msgBytes.slice(0, system.params.messageBytes);

  const ciphertext = await encrypt(padded, identity, system.params);

  // Correct key
  const correctKey = extract(identity, system.masterKey);
  const decrypted = await decrypt(ciphertext, correctKey, system.params);
  const decryptedStr = new TextDecoder().decode(decrypted).replace(/\0+$/, '');

  // Wrong date key
  const wrongKey = extract(wrongIdentity, system.masterKey);
  const wrongDecrypted = await decrypt(ciphertext, wrongKey, system.params);
  const wrongStr = new TextDecoder().decode(wrongDecrypted).replace(/\0+$/, '');

  return {
    identity,
    ciphertext,
    decryptedSuccessfully: decryptedStr === message,
    wrongDateFails: wrongStr !== message,
  };
}

/**
 * SCENARIO 3: Role-based delegation.
 *
 * Alice encrypts to "CEO@acme.com". Whoever holds the CEO role can
 * obtain the private key from PKG. No re-encryption needed on role change.
 */
export async function simulateRoleDelegation(
  role: string,
  message: string,
  system: IBESystem
): Promise<{
  identity: string;
  ciphertext: IBECiphertext;
  currentHolderDecrypts: boolean;
}> {
  const msgBytes = new TextEncoder().encode(message.padEnd(system.params.messageBytes, '\0'));
  const padded = msgBytes.slice(0, system.params.messageBytes);

  const ciphertext = await encrypt(padded, role, system.params);

  // PKG issues key to whoever currently holds the role
  const roleKey = extract(role, system.masterKey);
  const decrypted = await decrypt(ciphertext, roleKey, system.params);
  const decryptedStr = new TextDecoder().decode(decrypted).replace(/\0+$/, '');

  return {
    identity: role,
    ciphertext,
    currentHolderDecrypts: decryptedStr === message,
  };
}

/**
 * SCENARIO 4: Key escrow (the dark side of IBE).
 *
 * The PKG holds master secret s and can derive ANY user's private key
 * at any time. This is architectural — not a bug, but a tradeoff.
 */
export async function demonstrateKeyEscrow(
  message: string,
  targetIdentity: string,
  system: IBESystem
): Promise<{
  pkgCanDecrypt: boolean;
  explanation: string;
}> {
  const msgBytes = new TextEncoder().encode(message.padEnd(system.params.messageBytes, '\0'));
  const padded = msgBytes.slice(0, system.params.messageBytes);

  const ciphertext = await encrypt(padded, targetIdentity, system.params);

  // PKG uses master secret to derive the target's private key
  const derivedKey = extract(targetIdentity, system.masterKey);
  const decrypted = await decrypt(ciphertext, derivedKey, system.params);
  const decryptedStr = new TextDecoder().decode(decrypted).replace(/\0+$/, '');

  return {
    pkgCanDecrypt: decryptedStr === message,
    explanation:
      `The PKG computed d_ID = s · H₁("${targetIdentity}") — the same key ` +
      `the user would receive. Because s is the master secret, the PKG can ` +
      `derive any user's private key and decrypt any message in the system. ` +
      `This is Identity-Based Encryption's fundamental escrow tradeoff.`,
  };
}

/** Convenience: initialize a fresh IBESystem for scenarios. */
export { setup };
