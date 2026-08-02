import { defineConfig } from '@playwright/test';

/**
 * Accessibility + functional gate. Tests run against the production build
 * served by `vite preview`, so what passes here is what actually ships to
 * Pages. Run `npm run build` first (CI does).
 *
 * The port is fixed by default so CI stays deterministic; E2E_PORT lets a
 * local run step around a port another lab's preview server already holds.
 */
const PORT = Number(process.env.E2E_PORT ?? 4223);
const TARGET = `http://localhost:${PORT}/crypto-lab-ibe-gate/`;

export default defineConfig({
  testDir: 'e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  webServer: {
    command: `npm run preview -- --port ${PORT} --strictPort`,
    url: TARGET,
    reuseExistingServer: !process.env.CI,
  },
  use: {
    baseURL: TARGET,
    colorScheme: 'dark',
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
