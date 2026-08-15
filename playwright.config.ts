import { defineConfig } from '@playwright/test';

/**
 * Accessibility + functional gate. Tests run against the production build
 * served by `vite preview`, so what passes here is what actually ships to
 * Pages. The build runs as part of the webServer command, so a run always
 * tests the current source rather than whatever bundle is sitting in dist/.
 *
 * The port is fixed by default so CI stays deterministic, and must be unique
 * across the crypto-lab fleet: `reuseExistingServer` adopts whatever already
 * listens on it, so a shared port lets this suite scan a sibling lab's page
 * and report its findings as ours. 4223 collided with
 * crypto-lab-harvest-vault. E2E_PORT stays as a local escape hatch, but it
 * was never the fix — what has to be unique is the committed default.
 */
const PORT = Number(process.env.E2E_PORT ?? 4677);
const TARGET = `http://localhost:${PORT}/crypto-lab-ibe-gate/`;

export default defineConfig({
  testDir: 'e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  webServer: {
    // Build first: `vite preview` only serves the existing dist/, so without
    // this a broken build leaves the last good bundle in place and the suite
    // passes green against source that no longer compiles.
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: TARGET,
    reuseExistingServer: !process.env.CI,
  },
  use: {
    baseURL: TARGET,
    colorScheme: 'dark',
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
