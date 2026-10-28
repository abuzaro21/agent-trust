import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const lines = readFileSync(join(__dirname, '../../../.dockerignore'), 'utf8')
  .split(/\r?\n/)
  .map((l) => l.trim())
  .filter((l) => l !== '' && !l.startsWith('#'));

describe('.dockerignore keeps secrets out of the build context', () => {
  it.each(['.local', '**/.env', '**/.env.*', '**/*.pem', '**/*.key', '**/*.p12', '**/*.pfx', '**/keys', '**/secrets'])(
    'excludes %s',
    (pattern) => {
      expect(lines).toContain(pattern);
    },
  );

  it('does not exclude the hash-pinned policy artifact the image needs', () => {
    expect(lines.some((l) => l.startsWith('artifacts/policy') || l === 'artifacts' || l === 'artifacts/**')).toBe(false);
  });
});
