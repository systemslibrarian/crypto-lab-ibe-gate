import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * All five exhibits are driven in the order the lab enforces: every downstream
 * tab is scanned first in its locked "Run Setup first" state, then bilinearity
 * and the setup ceremony are run, a message is encrypted to an identity that
 * has never enrolled, the recipient enrols and decrypts, all 576 bytes of the
 * shared G_T element are inspected, the wrong key is tried against the same
 * ciphertext, all three PKG issuance policies are run, and finally the PKG
 * decrypts a message it was never sent. Every resulting state is scanned in
 * both themes at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why no panel is ever
 * force-revealed, why each scan asserts its content first, and why `violations`
 * is not the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expectBaselineNotStale();
  });
}
