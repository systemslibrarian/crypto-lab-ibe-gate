import { describe, expect, it } from 'vitest';
import { gtEquals } from '../src/pairing.ts';
import {
  setupHIBE,
  keyGenHIBE,
  delegateHIBE,
  encryptHIBE,
  decryptHIBE,
  recoverHIBESecret,
  identityComponentScalar,
  isIdentityPrefix,
} from '../src/hibe.ts';

function msg32(seed = 11): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, i) => (seed + i * 17) & 0xff);
}

describe('asymmetric HIBE delegation core', () => {
  it('hashes textual components deterministically with level separation', () => {
    expect(identityComponentScalar('dept', 2)).toBe(identityComponentScalar('dept', 2));
    expect(identityComponentScalar('dept', 1)).not.toBe(identityComponentScalar('dept', 2));
    expect(identityComponentScalar('dept', 2)).not.toBe(identityComponentScalar('other', 2));
  });

  it('fresh PKG key generation decrypts depth-1, depth-2 and depth-3 identities', async () => {
    const sys = setupHIBE(3, 32);
    for (const id of [['org'], ['org', 'finance'], ['org', 'finance', 'alice']]) {
      const M = msg32(id.length);
      const ct = await encryptHIBE(M, id, sys.params);
      const key = keyGenHIBE(id, sys.masterKey, sys.params);
      expect(Array.from(await decryptHIBE(ct, key, sys.params))).toEqual(Array.from(M));
      expect(gtEquals(recoverHIBESecret(ct, key), ct._demoShared)).toBe(true);
    }
  });

  it('a parent key delegates a working child key without the master secret', async () => {
    const sys = setupHIBE(3, 32);
    const parent = keyGenHIBE(['org'], sys.masterKey, sys.params);
    const child = delegateHIBE(parent, 'finance', sys.params);
    const M = msg32(33);
    const ct = await encryptHIBE(M, ['org', 'finance'], sys.params);

    expect(child.origin).toBe('delegation');
    expect(child.identity).toEqual(['org', 'finance']);
    expect(Array.from(await decryptHIBE(ct, child, sys.params))).toEqual(Array.from(M));
    expect(gtEquals(recoverHIBESecret(ct, child), ct._demoShared)).toBe(true);
  });

  it('delegates recursively to a grandchild and preserves the identity prefix', async () => {
    const sys = setupHIBE(3, 32);
    const org = keyGenHIBE(['org'], sys.masterKey, sys.params);
    const finance = delegateHIBE(org, 'finance', sys.params);
    const alice = delegateHIBE(finance, 'alice', sys.params);
    const M = msg32(44);
    const ct = await encryptHIBE(M, ['org', 'finance', 'alice'], sys.params);

    expect(alice.identity).toEqual(['org', 'finance', 'alice']);
    expect(Array.from(await decryptHIBE(ct, alice, sys.params))).toEqual(Array.from(M));
  });

  it('fresh and delegated keys for the same identity both decrypt despite different randomized components', async () => {
    const sys = setupHIBE(3, 32);
    const org = keyGenHIBE(['org'], sys.masterKey, sys.params);
    const delegated = delegateHIBE(org, 'finance', sys.params);
    const fresh = keyGenHIBE(['org', 'finance'], sys.masterKey, sys.params);
    const M = msg32(55);
    const ct = await encryptHIBE(M, ['org', 'finance'], sys.params);

    expect(delegated.K1.equals(fresh.K1)).toBe(false);
    expect(Array.from(await decryptHIBE(ct, delegated, sys.params))).toEqual(Array.from(M));
    expect(Array.from(await decryptHIBE(ct, fresh, sys.params))).toEqual(Array.from(M));
  });

  it('a parent key is not a child decryption key', async () => {
    const sys = setupHIBE(3, 32);
    const org = keyGenHIBE(['org'], sys.masterKey, sys.params);
    const ct = await encryptHIBE(msg32(), ['org', 'finance'], sys.params);
    await expect(decryptHIBE(ct, org, sys.params)).rejects.toThrow(/does not match/);
  });

  it('a sibling key cannot decrypt another branch', async () => {
    const sys = setupHIBE(3, 32);
    const org = keyGenHIBE(['org'], sys.masterKey, sys.params);
    const finance = delegateHIBE(org, 'finance', sys.params);
    const hr = delegateHIBE(org, 'hr', sys.params);
    const ct = await encryptHIBE(msg32(), ['org', 'finance'], sys.params);

    expect(finance.identity).not.toEqual(hr.identity);
    await expect(decryptHIBE(ct, hr, sys.params)).rejects.toThrow(/does not match/);
  });

  it('compromising a delegated node exposes its descendant delegation path but not siblings', () => {
    const finance = ['org', 'finance'];
    expect(isIdentityPrefix(finance, ['org', 'finance', 'alice'])).toBe(true);
    expect(isIdentityPrefix(finance, ['org', 'finance', 'payroll', 'alice'])).toBe(true);
    expect(isIdentityPrefix(finance, ['org', 'hr', 'alice'])).toBe(false);
    expect(isIdentityPrefix(finance, ['other-org', 'finance'])).toBe(false);
  });

  it('refuses delegation past the configured maximum depth', () => {
    const sys = setupHIBE(2, 32);
    const org = keyGenHIBE(['org'], sys.masterKey, sys.params);
    const finance = delegateHIBE(org, 'finance', sys.params);
    expect(() => delegateHIBE(finance, 'alice', sys.params)).toThrow(/configured HIBE depth/);
  });

  it('PKG retains root escrow and can freshly extract any branch', async () => {
    const sys = setupHIBE(3, 32);
    const target = ['other-org', 'research', 'bob'];
    const M = msg32(77);
    const ct = await encryptHIBE(M, target, sys.params);
    const escrow = keyGenHIBE(target, sys.masterKey, sys.params);
    expect(Array.from(await decryptHIBE(ct, escrow, sys.params))).toEqual(Array.from(M));
  });
});
