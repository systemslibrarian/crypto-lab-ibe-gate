import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * All seven exhibits are driven in the order the lab enforces: the four
 * BasicIdent-dependent tabs are first scanned in their locked state, then
 * bilinearity and Setup run, a never-enrolled identity receives and decrypts a
 * ciphertext, all 576 shared-G_T bytes are inspected, the wrong key runs, all
 * three issuance policies run, and the PKG escrow, independent HIBE, and
 * PKI/IBE/CLE comparison paths run. Every resulting state is scanned in the
 * lab's single dark theme at desktop and phone width.
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
