import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the crypto vectors; this
 * gates them on accessibility the same way. Scans the full page with every
 * collapsible/tab panel revealed, in both themes.
 *
 * This lab has no <details>; its five exhibits are class-toggled tab panels
 * (.panel / .panel.active, display:none). We force every panel visible so axe
 * sees all content at once, and neutralise animations so nothing is mid-fade.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Drive the protocol so axe also scans the dynamically-injected teaching
// visuals (byte-grid XOR, the full-576-byte GT inspector, public/secret
// chips, the PKG issuance-gate output). Without this, the gate would only
// cover the static shell and never see the content learners actually read.
async function runExhibits(page: Page): Promise<void> {
  await page.click('#btn-setup');
  await page.click('#btn-bilinear');
  await page.click('#tab-encrypt');
  await page.click('#btn-encrypt');
  await page.click('#btn-enroll');
  await page.click('#btn-decrypt2');
  // open the full-byte inspector inside the decrypt output
  await page.click('#term-decrypt2 details.gt-inspect summary').catch(() => {});
  await page.click('#tab-wrongkey');
  await page.click('#btn-wrongkey-run');
  await page.click('#tab-timelimit');
  await page.check('input[name="pkg-gate"][value="refuse"]');
  await page.click('#btn-timelimit-run');
  await page.click('#tab-escrow');
  await page.click('#btn-escrow-run');
  // Let the async pairing computations settle before scanning.
  await page.waitForTimeout(1500);
}

async function revealAll(page: Page): Promise<void> {
  // Kill animations/transitions/opacity so nothing is transiently hidden.
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation:none!important;
      transition:none!important;
      opacity:1!important;
    }`,
  });
  await page.evaluate(() => {
    // Expand any <details> (defensive; none today).
    for (const d of document.querySelectorAll('details')) {
      (d as HTMLDetailsElement).open = true;
    }
    // Reveal every class-toggled tab panel.
    for (const p of document.querySelectorAll('.panel')) {
      p.classList.add('active');
      p.removeAttribute('aria-hidden');
    }
    // Un-hide anything hidden via [hidden] or inline display:none.
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) {
      el.removeAttribute('hidden');
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await runExhibits(page);
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await runExhibits(page);
  await revealAll(page);
  await scan(page);
});
