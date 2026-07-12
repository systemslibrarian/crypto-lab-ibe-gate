import { defineConfig } from 'vitest/config';

/**
 * Unit-test config for the Boneh-Franklin IBE crypto core.
 * The Playwright a11y suite lives in e2e/ and is NOT a Vitest suite — it is
 * excluded here so `npm test` only runs the crypto vectors/round-trips.
 */
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
