// Clean-baseline mutation gate for the HIBE delegation core (src/hibe.ts).
//
// scripts/mutations.mjs covers src/certificateless.ts; until 2026-10-27 nothing
// replayed a mutation of the HIBE core, although the unit suite discriminates
// (audit section 3). This runner follows the fleet pattern (Attestation Gate,
// Matsui Line, Residue Gate, Shelf Oracle): for every recipe it proves, in
// order,
//
//   1. the unmodified copy passes the WHOLE unit suite and builds,
//   2. the named owning test is green on the unmodified copy,
//   3. the patch produces a NON-EMPTY source change and the production bundle
//      hash moves (a mutation the build never picked up proves nothing),
//   4. the named owning test goes RED on a test failure -- a timeout, a crash,
//      a missing module or a type error is NOT a kill,
//   5. the source is restored byte for byte, the bundle hash returns to the
//      baseline, and the owning test is green again.
//
// Owners come from observed kills: each recipe was applied, typechecked and
// run against test/hibe.test.ts with the JSON reporter, and the owner is one
// of the tests that failed with an assertion.
//
// Run from the repository root: node scripts/hibe-mutations.mjs [mutation name]

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { stripVTControlCharacters } from 'node:util';
import process from 'node:process';

process.chdir(dirname(dirname(fileURLToPath(import.meta.url))));

const HIBE = 'src/hibe.ts';
const SPEC = 'test/hibe.test.ts';
const unit = (test) => ({ runner: 'vitest', spec: SPEC, test });

const mutations = [
  {
    name: 'the recovered secret is A2 without dividing by A1',
    file: HIBE,
    anchor: '  return gtDiv(A2, A1);',
    replacement: '  return A2;',
    ...unit('fresh PKG key generation decrypts depth-1, depth-2 and depth-3 identities'),
  },
  {
    name: 'the delegation re-randomisation sum drops the component deltas',
    file: HIBE,
    anchor: 'const deltaSum = [...deltas, rChild].reduce((a, b) => mod(a + b), 0n);',
    replacement: 'const deltaSum = rChild;',
    ...unit('fresh and delegated keys for the same identity both decrypt despite different randomized components'),
  },
  {
    name: 'a too-shallow key is no longer rejected before the pairing math',
    file: HIBE,
    anchor: '  if (ciphertext.E.length !== key.K3.length) {',
    replacement: '  if (ciphertext.E.length < key.K3.length) {',
    ...unit('a parent key is structurally too shallow to decrypt a child ciphertext until it delegates'),
  },
  {
    name: 'C3 loses its -s*tauP1 term',
    file: HIBE,
    anchor: '  const C3 = params.W1\n    .multiply(s)\n    .add(params.tauP1.multiply(mod(-s))) as G1Point;',
    replacement: '  const C3 = params.W1.multiply(s) as G1Point;',
    ...unit('PKG retains root escrow and can freshly extract any branch'),
  },
  {
    name: 'identity hashing loses its level separation',
    file: HIBE,
    anchor: '`CryptoLab-HIBE-RS-G-v1|level=${level}|${component}`',
    replacement: '`CryptoLab-HIBE-RS-G-v1|level=${level * 0}|${component}`',
    ...unit('hashes textual components deterministically with level separation'),
  },
  {
    name: 'delegation past the configured depth is accepted',
    file: HIBE,
    anchor: '  if (parent.identity.length >= params.maxDepth) {',
    replacement: '  if (parent.identity.length > params.maxDepth) {',
    ...unit('refuses delegation past the configured maximum depth'),
  },
  {
    name: 'a delegated child hashes its component at the parent level',
    file: HIBE,
    anchor: 'const childScalar = identityComponentScalar(childComponent, childLevel);',
    replacement: 'const childScalar = identityComponentScalar(childComponent, childLevel - 1);',
    ...unit('a parent key delegates a working child key without the master secret'),
  },
  {
    name: 'the prefix relation ignores the component values',
    file: HIBE,
    anchor: 'return prefix.length <= identity.length && prefix.every((x, i) => x === identity[i]);',
    replacement: 'return prefix.length <= identity.length;',
    ...unit('compromising a delegated node exposes its descendant delegation path but not siblings'),
  },
  {
    name: 'the sender-side element is computed for s + 1',
    file: HIBE,
    anchor: '  return gtPow(params.eggAlpha, s);',
    replacement: '  return gtPow(params.eggAlpha, mod(s + 1n));',
    ...unit('carries no sender-side secret in the ciphertext; the sender derives it from its own scalar'),
  },
];

const INFRASTRUCTURE = /No test files found|Cannot find module|Failed to load url|Unhandled Error|error TS\d+|Test timed out|Test timeout of/;

function run(command, args, timeout) {
  const child = spawnSync(command, args, {
    encoding: 'utf8',
    env: { ...process.env, CI: '1', NO_COLOR: '1' },
    maxBuffer: 32 * 1024 * 1024,
    timeout,
  });
  return {
    ok: child.status === 0 && !child.error && !child.signal,
    status: child.status,
    signal: child.signal,
    error: child.error,
    output: stripVTControlCharacters(`${child.stdout ?? ''}${child.stderr ?? ''}`),
  };
}

function requirePass(result, label) {
  if (!result.ok) {
    throw new Error(`${label} failed (status ${result.status}, signal ${result.signal ?? 'none'}):\n${result.output.slice(-4000)}`);
  }
}

/** `npm run build` typechecks (so a mutant that does not compile is refused here) and bundles. */
function build() {
  requirePass(run('npm', ['run', 'build'], 300_000), 'build');
}

/** Hash of every emitted asset. */
function bundleHash() {
  const dir = 'dist/assets';
  const files = readdirSync(dir).filter((file) => statSync(join(dir, file)).isFile()).sort();
  if (files.length === 0) throw new Error('build produced no assets');
  const hash = createHash('sha256');
  for (const file of files) hash.update(file).update(readFileSync(join(dir, file)));
  return hash.digest('hex');
}

const escapeRegex = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function owningTest(mutation) {
  return run('npx', ['vitest', 'run', mutation.spec, '-t', escapeRegex(mutation.test)], 300_000);
}

function requireNamedGreen(result, mutation, label) {
  requirePass(result, label);
  if (!/Tests\s+1 passed\b/.test(result.output) || /\d+ failed\b/.test(result.output)) {
    throw new Error(`${label} did not execute exactly one passing test:\n${result.output.slice(-3000)}`);
  }
}

function requireNamedRed(result, mutation) {
  if (result.ok) throw new Error(`${mutation.name}: mutation SURVIVED its owning test`);
  if (INFRASTRUCTURE.test(result.output)) {
    throw new Error(`${mutation.name}: an infrastructure failure or timeout is not a kill:\n${result.output.slice(-3000)}`);
  }
  if (!result.output.includes(mutation.test)) {
    throw new Error(`${mutation.name}: the failure did not name its owning test:\n${result.output.slice(-3000)}`);
  }
  if (!/Tests\s+1 failed\b/.test(result.output)) {
    throw new Error(`${mutation.name}: the owning test did not fail exactly once:\n${result.output.slice(-3000)}`);
  }
  // A kill is a test FAILURE: an expect() assertion, or the code under test
  // throwing into the test body. Both are reported as failed tests; what is
  // excluded is everything the INFRASTRUCTURE pattern names above.
}

const requested = process.argv[2];
const selected = requested ? mutations.filter((mutation) => mutation.name === requested) : mutations;
if (selected.length === 0) throw new Error(`unknown mutation: ${requested}`);

const files = [...new Set(selected.map((mutation) => mutation.file))];
if (run('git', ['diff', '--quiet', 'HEAD', '--', ...files], 60_000).status !== 0) {
  throw new Error('commit the mutated source files before replaying mutations; the harness restores from disk, not from git');
}

build();
const baseline = bundleHash();
// The WHOLE unit suite: a baseline scoped to the mutated file would stay green
// while a mutation broke something elsewhere, and the restore control at the
// end would agree with it.
requirePass(run('npx', ['vitest', 'run'], 600_000), 'unmutated unit baseline');
console.log('baseline: unmutated copy PASSES');

const evidence = [];
for (const [index, mutation] of selected.entries()) {
  const original = readFileSync(mutation.file, 'utf8');
  if (original.split(mutation.anchor).length !== 2) {
    throw new Error(`${mutation.name}: the anchor must occur exactly once in ${mutation.file}`);
  }
  requireNamedGreen(owningTest(mutation), mutation, `${mutation.name}: named baseline`);
  let record;
  try {
    const changed = original.replace(mutation.anchor, mutation.replacement);
    if (changed === original) throw new Error(`${mutation.name}: the patch changed nothing`);
    writeFileSync(mutation.file, changed);
    const diff = run('git', ['diff', '--no-ext-diff', '--', mutation.file], 60_000);
    if (diff.output.trim() === '') throw new Error(`${mutation.name}: the source diff was empty`);
    build();
    const mutant = bundleHash();
    if (mutant === baseline) throw new Error(`${mutation.name}: the production bundle did not change`);
    const red = owningTest(mutation);
    requireNamedRed(red, mutation);
    record = {
      name: mutation.name,
      file: mutation.file,
      runner: mutation.runner,
      spec: mutation.spec,
      owningTest: mutation.test,
      baselineGreen: true,
      sourceDiffNonEmpty: true,
      baselineBundle: baseline,
      mutantBundle: mutant,
      bundleMoved: true,
      owningTestRed: true,
      failureExcerpt: red.output.split('\n').filter((line) => /expect|Error|✗|×|FAIL/.test(line)).slice(0, 6),
    };
    console.log(`caught ${index + 1}/${selected.length}: ${mutation.name} -> ${mutation.test}`);
  } finally {
    writeFileSync(mutation.file, original);
    if (readFileSync(mutation.file, 'utf8') !== original) {
      throw new Error(`${mutation.name}: source was not restored byte for byte`);
    }
    build();
    if (bundleHash() !== baseline) throw new Error(`${mutation.name}: restored bundle differs from the baseline`);
  }
  requireNamedGreen(owningTest(mutation), mutation, `${mutation.name}: restored baseline`);
  record.restoredGreen = true;
  evidence.push(record);
  writeFileSync('mutation-evidence.json', `${JSON.stringify(evidence, null, 2)}\n`);
}

requirePass(run('npx', ['vitest', 'run'], 600_000), 'restored unit baseline');
console.log(`all ${evidence.length} of ${selected.length} mutation(s) caught; sources and production bundle restored byte for byte`);
