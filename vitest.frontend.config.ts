import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

const webSrc = fileURLToPath(new URL('./apps/web/src', import.meta.url));

/** Frontend/web-app tests: API route adapters + presentation helpers. */
export default defineConfig({
  resolve: {
    alias: { '@': webSrc },
  },
  test: {
    environment: 'node',
    include: ['apps/web/test/**/*.test.ts'],
  },
});
