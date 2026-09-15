import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  resolve: {
    // apps/web API routes import via the Next '@/…' path alias.
    alias: { '@': fileURLToPath(new URL('./apps/web/src', import.meta.url)) },
  },
  test: {
    environment: 'node',
    include: [
      'packages/*/test/**/*.test.ts',
      'apps/*/test/**/*.test.ts',
      '!packages/*/test/**/*.integration.test.ts',
      '!apps/*/test/**/*.integration.test.ts',
    ],
  },
});
