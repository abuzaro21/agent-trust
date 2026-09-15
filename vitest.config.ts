import { defineConfig } from 'vitest/config';

export default defineConfig({
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
