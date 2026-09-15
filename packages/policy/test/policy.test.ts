import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import {
  loadOpaWasmPolicyEngine,
  type OpaWasmPolicyEngine,
} from '../src/index.js';
import {
  CASE_A_ALLOW,
  CASE_B_DENY,
  canonicalPolicyInput,
  readPolicyArtifacts,
  type VerifiedFactsFixture,
} from './fixture.js';

const WASM_PATH = join(__dirname, '../../../artifacts/policy/policy.wasm').replaceAll('\\', '/');
const MANIFEST_PATH = join(__dirname, '../../../artifacts/policy/manifest.json').replaceAll('\\', '/');

describe('OpaWasmPolicyEngine — canonical scenario (8M parity / 8I integrity)', () => {
  let engine: OpaWasmPolicyEngine;

  beforeAll(async () => {
    const result = await loadOpaWasmPolicyEngine(WASM_PATH, MANIFEST_PATH);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('engine failed to load');
    engine = result.engine as OpaWasmPolicyEngine;
  });

  it('Case A: fully verified agent, 120 SAR within 500 SAR authority → ALLOW', async () => {
    const decision = await engine.evaluate(canonicalPolicyInput(CASE_A_ALLOW));
    expect(decision.effect).toBe('ALLOW');
    expect(decision.reasonCodes[0]).toBe('IDENTITY_VERIFIED');
    expect(decision.policy.id).toBe('agent-trust-refund');
    expect(decision.policy.version).toBe('1.1.0');
    expect(decision.policy.hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('Case B: same verified agent, 5000 SAR over authority → DENY AUTHORITY_LIMIT_EXCEEDED', async () => {
    const decision = await engine.evaluate(canonicalPolicyInput(CASE_B_DENY));
    expect(decision.effect).toBe('DENY');
    expect(decision.reasonCodes).toEqual(['AUTHORITY_LIMIT_EXCEEDED']);
    expect(decision.policy.id).toBe('agent-trust-refund');
    expect(decision.policy.version).toBe('1.1.0');
  });

  it('manifest hash matches the on-disk wasm (8I)', async () => {
    const { wasm, manifest } = await readPolicyArtifacts();
    const actual = `sha256:${createHash('sha256').update(wasm).digest('hex')}`;
    expect(actual).toBe(manifest.sha256);
  });

  it('determinism: same input evaluated repeatedly gives identical decisions (8F/8N)', async () => {
    const input = canonicalPolicyInput(CASE_A_ALLOW);
    const results = await Promise.all(
      Array.from({ length: 25 }, () => engine.evaluate(input)),
    );
    for (const r of results) {
      expect(r).toEqual(results[0]);
    }
  });
});

describe('failure simulation (8Q) — every path denies', () => {
  let tmp: string;
  let wasm: Buffer;
  let manifest: import('../src/index.js').PolicyManifest;

  beforeAll(async () => {
    tmp = await mkdtemp(join(tmpdir(), 'policy-failure-'));
    const artifacts = await readPolicyArtifacts();
    wasm = artifacts.wasm;
    manifest = artifacts.manifest;
  });

  afterAll(async () => {
    await rm(tmp, { recursive: true, force: true });
  });

  it('missing policy.wasm → POLICY_ENGINE_UNAVAILABLE', async () => {
    const result = await loadOpaWasmPolicyEngine(join(tmp, 'nope.wasm'), MANIFEST_PATH);
    expect(result).toMatchObject({ ok: false, reasonCode: 'POLICY_ENGINE_UNAVAILABLE' });
  });

  it('corrupted wasm with matching (stale) manifest → POLICY_BUNDLE_INVALID', async () => {
    const dir = join(tmp, 'corrupt');
    await mkdir(dir);
    const corrupted = new Uint8Array(wasm);
    corrupted[100] = corrupted[100]! ^ 0xff; // flip one byte
    await writeFile(join(dir, 'policy.wasm'), corrupted);
    await writeFile(join(dir, 'manifest.json'), JSON.stringify(manifest));
    const result = await loadOpaWasmPolicyEngine(
      join(dir, 'policy.wasm').replaceAll('\\', '/'),
      join(dir, 'manifest.json').replaceAll('\\', '/'),
    );
    expect(result).toMatchObject({ ok: false, reasonCode: 'POLICY_BUNDLE_INVALID' });
  });

  it('hash mismatch (tampered manifest) → POLICY_BUNDLE_INVALID', async () => {
    const dir = join(tmp, 'mismatch');
    await mkdir(dir);
    await writeFile(join(dir, 'policy.wasm'), wasm);
    await writeFile(
      join(dir, 'manifest.json'),
      JSON.stringify({ ...manifest, sha256: `sha256:${'0'.repeat(64)}` }),
    );
    const result = await loadOpaWasmPolicyEngine(
      join(dir, 'policy.wasm').replaceAll('\\', '/'),
      join(dir, 'manifest.json').replaceAll('\\', '/'),
    );
    expect(result).toMatchObject({ ok: false, reasonCode: 'POLICY_BUNDLE_INVALID' });
  });

  it('invalid manifest (not JSON) → POLICY_BUNDLE_INVALID', async () => {
    const dir = join(tmp, 'badmanifest');
    await mkdir(dir);
    await writeFile(join(dir, 'policy.wasm'), wasm);
    await writeFile(join(dir, 'manifest.json'), 'not json at all');
    const result = await loadOpaWasmPolicyEngine(
      join(dir, 'policy.wasm').replaceAll('\\', '/'),
      join(dir, 'manifest.json').replaceAll('\\', '/'),
    );
    expect(result).toMatchObject({ ok: false, reasonCode: 'POLICY_BUNDLE_INVALID' });
  });

  it('valid wasm but garbage bytes claiming to be wasm → POLICY_BUNDLE_INVALID (instantiation fails)', async () => {
    const dir = join(tmp, 'notwasm');
    await mkdir(dir);
    await writeFile(join(dir, 'policy.wasm'), Buffer.from('definitely not wasm'));
    await writeFile(
      join(dir, 'manifest.json'),
      JSON.stringify({ ...manifest, sha256: `sha256:${createHash('sha256').update('definitely not wasm').digest('hex')}` }),
    );
    const result = await loadOpaWasmPolicyEngine(
      join(dir, 'policy.wasm').replaceAll('\\', '/'),
      join(dir, 'manifest.json').replaceAll('\\', '/'),
    );
    expect(result).toMatchObject({ ok: false, reasonCode: 'POLICY_BUNDLE_INVALID' });
  });
});

describe('policy-input security boundary (8O) — missing facts fail closed', () => {
  let engine: OpaWasmPolicyEngine;

  beforeAll(async () => {
    const result = await loadOpaWasmPolicyEngine(WASM_PATH, MANIFEST_PATH);
    if (!result.ok) throw new Error('engine failed to load');
    engine = result.engine as OpaWasmPolicyEngine;
  });

  type Facts = VerifiedFactsFixture;

  const strip = (input: Facts, ...paths: string[]): Record<string, unknown> => {
    const clone = structuredClone(input) as unknown as Record<string, unknown>;
    let obj = clone;
    for (let i = 0; i < paths.length - 1; i++) {
      obj = obj[paths[i]!] as Record<string, unknown>;
    }
    delete obj[paths[paths.length - 1]!];
    return clone;
  };

  const falsify = (input: Facts, path: string[], value: unknown): Record<string, unknown> => {
    const clone = structuredClone(input) as unknown as Record<string, unknown>;
    let obj = clone;
    for (let i = 0; i < path.length - 1; i++) {
      obj = obj[path[i]!] as Record<string, unknown>;
    }
    obj[path[path.length - 1]!] = value;
    return clone;
  };

  it.each([
    ['missing identity.proofVerified', (i: Facts) => strip(i, 'identity')],
    ['identity.proofVerified = false', (i: Facts) => falsify(i, ['identity', 'proofVerified'], false)],
    ['missing replay', (i: Facts) => strip(i, 'replay')],
    ['replay.claimed = false', (i: Facts) => falsify(i, ['replay', 'claimed'], false)],
    ['missing credential trust fact', (i: Facts) => strip(i, 'credential', 'issuerTrusted')],
    ['issuerTrusted = false', (i: Facts) => falsify(i, ['credential', 'issuerTrusted'], false)],
    ['missing status', (i: Facts) => strip(i, 'status')],
    ['quarantined = true', (i: Facts) => falsify(i, ['status', 'quarantined'], true)],
    ['missing authority', (i: Facts) => strip(i, 'authority')],
    ['extra top-level junk', (i: Facts) => ({ ...i, reputationScore: 87 })],
  ])('%s → DENY REQUEST_MALFORMED', async (_name, mutate) => {
    const decision = await engine.evaluate(mutate(canonicalPolicyInput(CASE_A_ALLOW)));
    expect(decision.effect).toBe('DENY');
    expect(decision.reasonCodes).toEqual(['REQUEST_MALFORMED']);
  });

  it('reputation-score-shaped input can never influence the decision (no scalar trust)', async () => {
    const withScore = {
      ...canonicalPolicyInput(CASE_B_DENY),
      context: { ...canonicalPolicyInput(CASE_B_DENY).context, trustScore: 99 },
    };
    const decision = await engine.evaluate(withScore);
    expect(decision.effect).toBe('DENY');
    expect(decision.reasonCodes).toEqual(['REQUEST_MALFORMED']);
  });
});
