#!/usr/bin/env node
/**
 * Root-script runner for the Next.js dashboard (dev / build / start).
 *
 * Why this exists: on Windows the pnpm shim cannot re-invoke pnpm from a
 * script (`pnpm --filter …` inside `pnpm run` fails), and inside pnpm's
 * isolated node_modules the `next` package may live in the app-local
 * tree OR be hoisted to the root depending on install state. This script
 * resolves the CLI from both layouts, preferring the app-local one.
 */
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const command = process.argv[2] ?? 'dev';
const extraArgs = process.argv.slice(3);

const candidates = [
  join(root, 'apps/web/node_modules/next/dist/bin/next'),
  join(root, 'node_modules/next/dist/bin/next'),
];
if (candidates.every((c) => !existsSync(c))) {
  // pnpm isolated store: .pnpm/next@*/node_modules/next/...
  try {
    const resolved = createRequire(join(root, 'apps/web/package.json')).resolve(
      'next/package.json',
    );
    candidates.unshift(join(dirname(resolved), 'dist', 'bin', 'next'));
  } catch {
    // fall through to the static candidates
  }
}
const nextBin = candidates.find((p) => existsSync(p));
if (nextBin === undefined) {
  console.error(`next CLI not found (root=${root}) — tried:`);
  for (const c of candidates) console.error('  ' + c);
  process.exit(1);
}

const result = spawnSync(process.execPath, [nextBin, command, ...extraArgs], {
  stdio: 'inherit',
  cwd: join(root, 'apps/web'),
});
process.exit(result.status ?? 1);
