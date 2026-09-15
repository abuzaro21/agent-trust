import { beforeAll, describe, expect, it } from 'vitest';
import { join } from 'node:path';

import { loadOpaWasmPolicyEngine, type OpaWasmPolicyEngine } from '../src/index.js';
import { canonicalPolicyInput } from './fixture.js';

const WASM_PATH = join(__dirname, '../../../artifacts/policy/policy.wasm').replaceAll('\\', '/');
const MANIFEST_PATH = join(__dirname, '../../../artifacts/policy/manifest.json').replaceAll('\\', '/');

/**
 * 8P — non-gating performance observation. The point proven here is
 * architectural: the policy is loaded/instantiated ONCE (beforeAll) and
 * each evaluation is a pure Wasm call — no recompilation per request.
 * Numbers are reported, never asserted (CI hosts vary).
 */
describe('policy evaluation benchmark (8P, observational)', () => {
  let engine: OpaWasmPolicyEngine;

  beforeAll(async () => {
    const result = await loadOpaWasmPolicyEngine(WASM_PATH, MANIFEST_PATH);
    if (!result.ok) throw new Error(`engine failed to load: ${result.detail}`);
    engine = result.engine as OpaWasmPolicyEngine;
  });

  it('measures median/p95 over 200 evaluations after warm-up (no timing assertion)', async () => {
    // Warm-up (JIT, caches).
    for (let i = 0; i < 20; i++) {
      await engine.evaluate(canonicalPolicyInput({ amount: 100 + i, currency: 'SAR' }));
    }
    const samples: number[] = [];
    for (let i = 0; i < 200; i++) {
      const input = canonicalPolicyInput({ amount: 1 + (i % 1000), currency: 'SAR' });
      const start = performance.now();
      await engine.evaluate(input);
      samples.push(performance.now() - start);
    }
    samples.sort((a, b) => a - b);
    const median = samples[Math.floor(samples.length / 2)]!;
    const p95 = samples[Math.floor(samples.length * 0.95)]!;
    // eslint-disable-next-line no-console
    console.log(
      `[policy-benchmark] n=200 load-once median=${median.toFixed(3)}ms p95=${p95.toFixed(3)}ms`,
    );
    // Sanity only: an evaluation must never take multiple seconds.
    expect(samples[samples.length - 1]).toBeLessThan(1_000);
  }, 120_000);
});
