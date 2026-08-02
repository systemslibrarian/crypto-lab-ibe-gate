import { expect, test, type Page } from '@playwright/test';

/**
 * Functional gate — "tested rather than merely visited".
 *
 * The a11y spec drives every exhibit but asserts nothing about what they SAY.
 * This spec asserts the load-bearing states of the rendered page: the headline
 * verdicts, the counters, and every failure/tamper path the UI offers.
 *
 * House rule followed throughout: wherever a verdict has an underlying
 * computation on screen, we check the verdict AGAINST that computation rather
 * than against a hardcoded string. So the byte-grid rows are XORed in the test
 * and compared to each other, the two G_T fingerprints are compared to each
 * other, and the "0 mismatches" counter is compared to the actual number of
 * diff-coloured cells the same run rendered.
 */

const MSG_BYTES = 32;

/** What the page's fixed 32-byte message space will actually encrypt. */
function fitted(msg: string): string {
  const enc = new TextEncoder().encode(msg);
  const buf = new Uint8Array(MSG_BYTES);
  buf.set(enc.slice(0, MSG_BYTES));
  return new TextDecoder().decode(buf).replace(/\0+$/, '');
}

/** Freeze animation so nothing we read is mid-reveal. */
async function stillPage(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}`,
  });
}

async function boot(page: Page): Promise<void> {
  await page.goto('.');
  await stillPage(page);
}

/** Read one terminal's rendered text, once its run has finished. */
async function term(page: Page, id: string): Promise<string> {
  await expect(page.locator(`#${id} .spinner`)).toHaveCount(0, {
    timeout: 30000,
  });
  return (await page.locator(`#${id}`).innerText()).replace(/\u00a0/g, ' ');
}

/**
 * Recover the three real byte rows out of an XOR visualiser. Each cell carries
 * its true value in aria-label ("byte 7: 0x1f"), so this reads the same bytes
 * the page claims to be showing.
 */
async function readXor(
  page: Page,
  vizId: string
): Promise<{ top: number[]; mask: number[]; result: number[] }> {
  await expect(page.locator(`#${vizId} .byte-grid`)).toHaveCount(3, {
    timeout: 30000,
  });
  const rows = await page.locator(`#${vizId} .byte-grid`).evaluateAll((grids) =>
    grids.map((g) =>
      Array.from(g.querySelectorAll('.byte-cell')).map((c) => {
        const m = /0x([0-9a-f]{2})$/.exec(c.getAttribute('aria-label') ?? '');
        return m ? parseInt(m[1], 16) : NaN;
      })
    )
  );
  expect(rows, `${vizId} should render three byte rows`).toHaveLength(3);
  return { top: rows[0], mask: rows[1], result: rows[2] };
}

function xorRows(a: number[], b: number[]): number[] {
  return a.map((v, i) => v ^ b[i]);
}

function bytesToText(b: number[]): string {
  return new TextDecoder().decode(Uint8Array.from(b)).replace(/\0+$/, '');
}

/**
 * Pull the hex value printed after "=" on the first line carrying `label`.
 * Lines that merely mention the label without printing a value (headers, the
 * "M = V ⊕ H₂(e(d_ID, U))" formula line) are skipped.
 */
function fingerprint(text: string, label: string): string {
  for (const line of text.split('\n')) {
    if (!line.includes(label)) continue;
    const m = /=\s*([0-9a-f]{8,})/.exec(line);
    if (m) return m[1];
  }
  throw new Error(`no hex value printed for "${label}" in:\n${text}`);
}

async function runSetup(page: Page): Promise<void> {
  await page.click('#btn-setup');
  await expect(page.locator('#term-setup')).toContainText(
    'System parameters published'
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Exhibit 1 — Setup ceremony
// ─────────────────────────────────────────────────────────────────────────────

test('setup publishes public parameters and never prints the master secret', async ({
  page,
}) => {
  await boot(page);
  await expect(page.locator('#term-setup')).toContainText('Waiting to run setup');

  // Every other exhibit is gated on setup having run.
  for (const id of [
    '#btn-encrypt',
    '#btn-wrongkey-run',
    '#btn-timelimit-run',
    '#btn-escrow-run',
  ]) {
    await expect(page.locator(id)).toBeDisabled();
  }

  await runSetup(page);

  const out = await term(page, 'term-setup');
  expect(out).toContain('PRIVATE KEY GENERATOR — SETUP CEREMONY');
  // P_pub is published; s is redacted, not printed.
  expect(out).toMatch(/P_pub = [0-9a-f]{24}/);
  await expect(page.locator('#term-setup .censor')).toHaveCount(1);
  expect(out).toContain('s — HIDDEN');
  expect(out).toContain('Master key: NEVER leaves the PKG');
  // The censor bar must not be hiding a value that is printed anyway.
  expect(out).not.toMatch(/Master secret s:\s*[0-9a-f]{8}/);

  // Setup now unlocks the rest of the lab.
  for (const id of [
    '#btn-encrypt',
    '#btn-wrongkey-run',
    '#btn-timelimit-run',
    '#btn-escrow-run',
  ]) {
    await expect(page.locator(id)).toBeEnabled();
  }
});

test('setup draws a fresh master secret each run', async ({ page }) => {
  await boot(page);
  await runSetup(page);
  const first = fingerprint(await term(page, 'term-setup'), 'P_pub');
  await page.click('#btn-setup');
  await expect(page.locator('#term-setup')).toContainText('System parameters');
  await expect
    .poll(async () => fingerprint(await term(page, 'term-setup'), 'P_pub'))
    .not.toBe(first);
});

// ─────────────────────────────────────────────────────────────────────────────
// Exhibit 1 — Bilinearity
// ─────────────────────────────────────────────────────────────────────────────

test('bilinearity verdict matches the two G_T values it printed', async ({
  page,
}) => {
  await boot(page);
  await page.click('#btn-bilinear');
  await expect(page.locator('#term-bilinear')).toContainText('BILINEARITY TEST');

  const out = await term(page, 'term-bilinear');
  const left = fingerprint(out, 'e(a·P, b·Q)');
  const right = fingerprint(out, 'e(P, Q)^(a·b)');

  // The verdict is only allowed to say IDENTICAL if the printed sides agree.
  expect(left).toBe(right);
  expect(out).toContain('✓ IDENTICAL — all 576 bytes match');
  expect(out).not.toContain('MISMATCH');

  // Both scalars are real and distinct, not a fixed pair.
  const a = /a = ([0-9a-f]{8,})/.exec(out);
  const b = /b = ([0-9a-f]{8,})/.exec(out);
  expect(a && b).toBeTruthy();
  expect(a![1]).not.toBe(b![1]);
});

test('bilinearity draws fresh scalars per run', async ({ page }) => {
  await boot(page);
  await page.click('#btn-bilinear');
  await expect(page.locator('#term-bilinear')).toContainText('IDENTICAL');
  const first = /a = ([0-9a-f]{8,})/.exec(await term(page, 'term-bilinear'))![1];
  await page.click('#btn-bilinear');
  await expect
    .poll(
      async () =>
        /a = ([0-9a-f]{8,})/.exec(await term(page, 'term-bilinear'))![1]
    )
    .not.toBe(first);
});

// ─────────────────────────────────────────────────────────────────────────────
// Exhibit 2 — Encrypt to a stranger, enroll, decrypt
// ─────────────────────────────────────────────────────────────────────────────

test('encrypt → enroll → decrypt recovers the message and proves the pairing identity', async ({
  page,
}) => {
  await boot(page);
  await runSetup(page);
  await page.click('#tab-encrypt');

  const identity = 'stranger@nowhere.test';
  const message = 'meet at dawn';
  await page.fill('#enc-identity', identity);
  await page.fill('#enc-message', message);

  // The PKI contrast box must echo the identity actually typed.
  await expect(page.locator('.pki-recipient').first()).toHaveText(identity);

  await page.click('#btn-encrypt');
  await expect(page.locator('#term-encrypt')).toContainText(
    `ALICE ENCRYPTS TO "${identity}"`
  );

  // The encrypt visualiser must be self-consistent: M ⊕ mask = V, on the real
  // bytes the page rendered.
  const enc = await readXor(page, 'xor-encrypt');
  expect(enc.top).toHaveLength(MSG_BYTES);
  expect(enc.mask).toHaveLength(MSG_BYTES);
  expect(enc.result).toHaveLength(MSG_BYTES);
  expect(bytesToText(enc.top)).toBe(message);
  expect(xorRows(enc.top, enc.mask)).toEqual(enc.result);
  // A real mask, not a zero mask that would leave V === M.
  expect(enc.result).not.toEqual(enc.top);

  // Enrollment issues d_ID for the identity the ciphertext was sealed to.
  await page.click('#btn-enroll');
  const enroll = await term(page, 'term-enroll');
  expect(enroll).toContain(`d_ID = s · H₁("${identity}")`);
  expect(enroll).toContain('✓ Private key delivered to Bob securely.');
  expect(enroll).toMatch(/d_ID = [0-9a-f]{24}/);

  await page.click('#btn-decrypt2');
  const dec = await term(page, 'term-decrypt2');

  // Headline verdict, checked against the message this run encrypted.
  expect(dec).toContain(`✓ "${fitted(message)}"`);

  // Decrypt visualiser: V ⊕ maskBob = M, and its V row is the very ciphertext
  // the encrypt step produced.
  const dv = await readXor(page, 'xor-decrypt');
  expect(dv.top).toEqual(enc.result);
  expect(xorRows(dv.top, dv.mask)).toEqual(dv.result);
  expect(bytesToText(dv.result)).toBe(fitted(message));
  // Bob reconstructed Alice's exact mask without ever seeing r.
  expect(dv.mask).toEqual(enc.mask);

  // The pairing-identity proof: the two printed G_T fingerprints must agree
  // before the page is allowed to claim they do.
  const senderGt = fingerprint(dec, 'Sender computed');
  const recipientGt = fingerprint(dec, 'Bob computes');
  expect(senderGt).toBe(recipientGt);
  expect(dec).toContain('✓ Fingerprints match');
  expect(dec).not.toContain('✗ Mismatch');
});

test('the 576-byte G_T inspector counter agrees with the bytes it rendered', async ({
  page,
}) => {
  await boot(page);
  await runSetup(page);
  await page.click('#tab-encrypt');
  await page.fill('#enc-message', 'inspector run');
  await page.click('#btn-encrypt');
  await page.click('#btn-enroll');
  await page.click('#btn-decrypt2');

  const inspector = page.locator('#term-decrypt2 details.gt-inspect');
  await expect(inspector.locator('summary')).toHaveText(
    'Show full 576 bytes and verify every one'
  );
  await inspector.locator('summary').click();

  const summary = await inspector.locator('.gt-diff-summary').innerText();
  // Claimed count.
  expect(summary).toContain('Scanned all 576 bytes');
  expect(summary).toContain('0 mismatches');

  // Actual count, from the dump the same run produced.
  const dump = inspector.locator('.gt-hex-dump');
  await expect(dump.locator('.gd-diff')).toHaveCount(0);
  await expect(dump.locator('.gd-match')).toHaveCount(576);

  // And the dump really is 576 bytes of hex, not a truncated stand-in.
  const hexText = (await dump.innerText()).replace(/\s/g, '');
  expect(hexText).toHaveLength(576 * 2);
  expect(hexText).toMatch(/^[0-9a-f]+$/);
});

test('over-long input is truncated to the message space and says so', async ({
  page,
}) => {
  await boot(page);
  await runSetup(page);
  await page.click('#tab-encrypt');

  const long = 'Q2 financials strictly confidential and then some more text';
  const kept = fitted(long);
  expect(kept).not.toBe(long); // guard: this input must actually overflow

  await page.fill('#enc-message', long);
  await page.click('#btn-encrypt');
  const enc = await term(page, 'term-encrypt');
  expect(enc).toContain(
    "BasicIdent's message space here is exactly 32 bytes"
  );
  expect(enc).toContain(`"${kept}"`);

  await page.click('#btn-enroll');
  await page.click('#btn-decrypt2');
  const dec = await term(page, 'term-decrypt2');
  // Truncation must not be reported as a decryption failure.
  expect(dec).toContain(`✓ "${kept}"`);
  expect(dec).not.toContain('✗');
});

// ─────────────────────────────────────────────────────────────────────────────
// Exhibit 3 — Wrong key = garbage (failure path)
// ─────────────────────────────────────────────────────────────────────────────

test('a wrong-identity key produces garbage while the right key recovers M', async ({
  page,
}) => {
  await boot(page);
  await runSetup(page);
  await page.click('#tab-wrongkey');

  const secret = 'launch codes 42';
  await page.fill('#wk-message', secret);
  await page.click('#btn-wrongkey-run');
  await expect(page.locator('#term-wk-alice')).toContainText('d_ID');
  await expect(page.locator('#term-wk-eve')).toContainText('d_Eve');

  const alice = await readXor(page, 'xor-wk-alice');
  const eve = await readXor(page, 'xor-wk-eve');

  // Same ciphertext into both panes — the only thing that differs is the key.
  expect(eve.top).toEqual(alice.top);
  // Different key ⇒ different pairing ⇒ different mask.
  expect(eve.mask).not.toEqual(alice.mask);

  // Both panes are internally consistent V ⊕ mask = result.
  expect(xorRows(alice.top, alice.mask)).toEqual(alice.result);
  expect(xorRows(eve.top, eve.mask)).toEqual(eve.result);

  // Alice recovers the plaintext; Eve provably does not.
  expect(bytesToText(alice.result)).toBe(secret);
  expect(eve.result).not.toEqual(alice.result);
  expect(bytesToText(eve.result)).not.toBe(secret);

  const aliceOut = await term(page, 'term-wk-alice');
  const eveOut = await term(page, 'term-wk-eve');
  expect(aliceOut).toContain(`✓ "${secret}"`);
  expect(eveOut).toContain('✗');
  expect(eveOut).not.toContain(secret);
  // Eve's failure is explained, not merely flagged.
  expect(eveOut).toContain('Different mask → V ⊕ mask ≠ M');

  // The failure hex the page prints must be the bytes it actually rendered.
  const eveHex = /✗ ([0-9a-f]{40})/.exec(eveOut);
  expect(eveHex, `expected Eve's recovered bytes in: ${eveOut}`).toBeTruthy();
  const first20 = eve.result
    .slice(0, 20)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  expect(eveHex![1]).toBe(first20);
});

// ─────────────────────────────────────────────────────────────────────────────
// Exhibit 4 — Time-limited capabilities: all three PKG issuance policies
// ─────────────────────────────────────────────────────────────────────────────

test('PKG policy ISSUE: on-date key is issued and the message is recovered', async ({
  page,
}) => {
  await boot(page);
  await runSetup(page);
  await page.click('#tab-timelimit');

  const email = 'bob@example.com';
  const msg = 'embargoed until dawn';
  await page.fill('#tl-email', email);
  await page.fill('#tl-message', msg);
  const date = await page.inputValue('#tl-date');
  await page.check('input[name="pkg-gate"][value="issue"]');
  await page.click('#btn-timelimit-run');

  const out = await term(page, 'term-timelimit');
  // The identity string is the sealed one, built from what the user typed.
  expect(out).toContain(`IDENTITY STRING: "${email} || ${date}"`);
  expect(out).toContain('PKG POLICY: ISSUE (on-date, authorised)');
  expect(out).toContain(`d_ID = s · H₁("${email} || ${date}")`);
  expect(out).toContain(`✓ "${fitted(msg)}"`);
  expect(out).not.toContain('Decryption failed');
});

test('PKG policy REFUSE: no key issued, the fallback key yields garbage', async ({
  page,
}) => {
  await boot(page);
  await runSetup(page);
  await page.click('#tab-timelimit');

  const email = 'bob@example.com';
  const msg = 'embargoed until dawn';
  await page.fill('#tl-email', email);
  await page.fill('#tl-message', msg);
  await page.check('input[name="pkg-gate"][value="refuse"]');
  await page.click('#btn-timelimit-run');

  const out = await term(page, 'term-timelimit');
  expect(out).toContain('PKG POLICY: REFUSE OFF-DATE KEY');
  expect(out).toContain('NOT ISSUED');
  // The page runs the only key Bob does hold, and it fails.
  expect(out).toContain(`d = s·H₁("${email}")`);
  expect(out).toContain('✓ Garbage.');
  expect(out).toContain('a different G_T element, so the mask is wrong');
  expect(out).not.toContain('treat it as a bug in this demo');
  // The plaintext must not appear anywhere in a refused run.
  expect(out).not.toContain(fitted(msg));
  // The attempted recovery is shown as real bytes.
  expect(out).toMatch(/M′ = V ⊕ H₂\(e\(d, U\)\) = [0-9a-f]{40}/);
  // …and it says what actually enforced the lock.
  expect(out).toContain("the PKG's refusal, not the string");
});

test('PKG policy COLLUDE: the off-date key decrypts early — the string never stopped it', async ({
  page,
}) => {
  await boot(page);
  await runSetup(page);
  await page.click('#tab-timelimit');

  const msg = 'embargoed until dawn';
  await page.fill('#tl-message', msg);
  await page.check('input[name="pkg-gate"][value="collude"]');
  await page.click('#btn-timelimit-run');

  const out = await term(page, 'term-timelimit');
  expect(out).toContain('COMPROMISED PKG: ISSUE OFF-DATE ANYWAY');
  expect(out).toContain(`⚠ "${fitted(msg)}" — released early`);
  expect(out).not.toContain('Decryption failed');
  expect(out).toContain('only ever a promise by the key issuer');
});

test('the three PKG policies reach three different verdicts on one ciphertext scheme', async ({
  page,
}) => {
  await boot(page);
  await runSetup(page);
  await page.click('#tab-timelimit');
  await page.fill('#tl-message', 'one message three policies');

  const verdicts: string[] = [];
  for (const gate of ['issue', 'refuse', 'collude']) {
    await page.check(`input[name="pkg-gate"][value="${gate}"]`);
    await page.click('#btn-timelimit-run');
    await expect(page.locator('#term-timelimit')).toContainText('PKG', {
      timeout: 15000,
    });
    const out = await term(page, 'term-timelimit');
    const line = out
      .split('\n')
      .find((l) => /PKG POLICY|COMPROMISED PKG/.test(l));
    expect(line, `no verdict line for gate=${gate}`).toBeTruthy();
    verdicts.push(line!.trim());
  }
  expect(new Set(verdicts).size).toBe(3);
});

// ─────────────────────────────────────────────────────────────────────────────
// Exhibit 5 — Key escrow
// ─────────────────────────────────────────────────────────────────────────────

test('the PKG decrypts a third party message using only the master secret', async ({
  page,
}) => {
  await boot(page);
  await runSetup(page);
  await page.click('#tab-escrow');

  const target = 'ceo@megacorp.com';
  const secret = 'oust the CFO Thursday';
  await page.fill('#escrow-identity', target);
  await page.fill('#escrow-message', secret);
  await page.click('#btn-escrow-run');

  const out = await term(page, 'term-escrow');
  expect(out).toContain('PKG EXERCISES MASTER KEY');
  expect(out).toContain(`Target identity: "${target}"`);
  // The headline verdict, tied to the message this run encrypted.
  expect(out).toContain(`⚠ PKG successfully decrypted: "${fitted(secret)}"`);
  expect(out).not.toContain('PKG could not decrypt');
  expect(out).toContain('d_ID = s · Q_ID');
});

// ─────────────────────────────────────────────────────────────────────────────
// Protocol map — the README promises the diagram tracks the running step
// ─────────────────────────────────────────────────────────────────────────────

test('the protocol map lights the arrow for the step that just ran', async ({
  page,
}) => {
  await boot(page);
  const caption = page.locator('#flow-caption');

  await runSetup(page);
  await expect(caption).toContainText('Setup.');
  await expect(page.locator('#flow-svg [data-arrow="pub"].lit')).toHaveCount(1);
  // The G_T node only glows when a pairing arrow is live — not during setup.
  await expect(page.locator('#flow-gt.lit')).toHaveCount(0);

  await page.click('#tab-encrypt');
  await page.click('#btn-encrypt');
  await expect(caption).toContainText('Encrypt.');
  await expect(page.locator('#flow-svg [data-arrow="u"].lit')).toHaveCount(1);
  await expect(page.locator('#flow-svg [data-arrow="pub"].lit')).toHaveCount(0);
  await expect(page.locator('#flow-gt.lit')).toHaveCount(1);

  await page.click('#btn-enroll');
  await expect(caption).toContainText('Extract.');
  await expect(page.locator('#flow-svg [data-arrow="dID"].lit')).toHaveCount(1);

  await page.click('#btn-decrypt2');
  await expect(caption).toContainText('Decrypt.');
  await expect(page.locator('#flow-svg [data-arrow="pairA"].lit')).toHaveCount(1);
  await expect(page.locator('#flow-svg [data-arrow="pairB"].lit')).toHaveCount(1);
});
