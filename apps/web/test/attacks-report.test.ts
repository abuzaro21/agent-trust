import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => ({ dir: '', runAttackSuite: vi.fn() }));

vi.mock('@/server/world', () => ({
  get ATTACKS_DIR() {
    return h.dir;
  },
}));
vi.mock('@agent-trust/attacks', () => ({ runAttackSuite: h.runAttackSuite }));

import { GET } from '../src/app/api/attacks/report/route';

describe('GET /api/attacks/report never executes the suite', () => {
  beforeEach(() => {
    h.dir = mkdtempSync(join(tmpdir(), 'at-attacks-'));
    h.runAttackSuite.mockReset();
  });
  afterEach(() => rmSync(h.dir, { recursive: true, force: true }));

  it('serves the generated artifact, and ?run=1 is ignored', async () => {
    mkdirSync(h.dir, { recursive: true });
    writeFileSync(join(h.dir, 'attack-report.json'), JSON.stringify({ summary: { total: 60, passed: 60 } }));
    const withRun = GET as unknown as (r: Request) => Promise<Response>;
    const res = await withRun(new Request('http://localhost/api/attacks/report?run=1'));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ summary: { total: 60, passed: 60 } });
    expect(h.runAttackSuite).not.toHaveBeenCalled();
  });

  it('missing artifact fails safely with 503 and runs nothing', async () => {
    const res = await GET();
    expect(res.status).toBe(503);
    expect((await res.json()).error).toBe('ATTACK_REPORT_UNAVAILABLE');
    expect(h.runAttackSuite).not.toHaveBeenCalled();
  });

  it('a corrupt artifact fails safely with 503 and runs nothing', async () => {
    writeFileSync(join(h.dir, 'attack-report.json'), '{not json');
    const res = await GET();
    expect(res.status).toBe(503);
    expect(h.runAttackSuite).not.toHaveBeenCalled();
  });
});
