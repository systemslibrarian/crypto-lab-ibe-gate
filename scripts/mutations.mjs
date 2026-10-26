import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const sourcePath = join(root, 'src', 'certificateless.ts');
const original = readFileSync(sourcePath, 'utf8');
const originalHash = createHash('sha256').update(original).digest('hex');

const mutations = [
  {
    name: 'remove the UTF-8 message bound',
    from: 'if (encoded.length > CLE_MESSAGE_MAX_BYTES) {',
    to: 'if (false) {',
  },
  {
    name: 'remove identity and context from the serialized binding',
    from: "return sha256(concat(frame(utf8('CLE-ID-DIGEST-v1')), frame(utf8(context)), frame(utf8(identity))));",
    to: "return sha256(frame(utf8('CLE-ID-DIGEST-v1')));",
  },
  {
    name: 'remove the outer public-key encryption layer',
    from: `const c2 = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, userPublicKey, webBytes(c1))
  );`,
    to: 'const c2 = c1;',
  },
  {
    name: 'accept every one-time MAC',
    from: "return crypto.subtle.verify('HMAC', key, webBytes(tag), webBytes(message));",
    to: 'return true;',
  },
  {
    name: 'leak the internal failure stage through the recipient API',
    from: `: { accepted: false };`,
    to: `: ({ accepted: false, stage: result.stage } as CLEDecryptResult);`,
  },
  {
    name: 'stop checking the certificate identity',
    from: `certificate.identity !== expectedIdentity ||`,
    to: `false ||`,
  },
  {
    name: 'stop checking the certificate context',
    from: `certificate.context !== expectedContext`,
    to: `false`,
  },
  {
    name: 'accept every certificate signature',
    from: `return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },`,
    to: `return true || crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },`,
  },
  {
    name: 'authenticate zeros instead of the transmitted outer ciphertext',
    from: `const tag = await hmac(macKey, c2);`,
    to: `const tag = await hmac(macKey, new Uint8Array(c2.length));`,
  },
  {
    name: 'issue a partial key without the construction context',
    from: `return extract(canonicalIdentity(identity, context), system.masterKey);`,
    to: `return extract(identity, system.masterKey);`,
  },
];

function runFocusedSuite() {
  return spawnSync(
    process.platform === 'win32' ? 'npm.cmd' : 'npm',
    ['test', '--', 'test/certificateless.test.ts'],
    { cwd: root, encoding: 'utf8' }
  );
}

function restore() {
  writeFileSync(sourcePath, original);
  const restored = readFileSync(sourcePath, 'utf8');
  const restoredHash = createHash('sha256').update(restored).digest('hex');
  if (restoredHash !== originalHash) throw new Error('source restoration hash mismatch');
}

try {
  const baseline = runFocusedSuite();
  if (baseline.status !== 0) {
    process.stderr.write(baseline.stdout ?? '');
    process.stderr.write(baseline.stderr ?? '');
    throw new Error('baseline: unmutated copy FAILED');
  }
  console.log('baseline: unmutated copy PASSES');

  let caught = 0;
  for (const mutation of mutations) {
    const occurrences = original.split(mutation.from).length - 1;
    if (occurrences !== 1) {
      throw new Error(`${mutation.name}: expected one source match, found ${occurrences}`);
    }
    writeFileSync(sourcePath, original.replace(mutation.from, mutation.to));
    const result = runFocusedSuite();
    restore();
    if (result.status === 0) {
      process.stderr.write(result.stdout ?? '');
      process.stderr.write(result.stderr ?? '');
      throw new Error(`SURVIVED: ${mutation.name}`);
    }
    caught += 1;
    console.log(`caught ${caught}/${mutations.length}: ${mutation.name}`);
  }

  const restoredBaseline = runFocusedSuite();
  if (restoredBaseline.status !== 0) {
    process.stderr.write(restoredBaseline.stdout ?? '');
    process.stderr.write(restoredBaseline.stderr ?? '');
    throw new Error('restored baseline FAILED');
  }
  console.log(`all ${caught} mutation(s) caught; restored baseline PASSES`);
} finally {
  restore();
}
