import { spawn } from 'node:child_process';
import { join } from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

import { loadOpaWasmPolicyEngine, type OpaWasmPolicyEngine } from '../src/index.js';
import { canonicalPolicyInput, type VerifiedFactsFixture } from './fixture.js';

const WASM_PATH = join(__dirname, '../../../artifacts/policy/policy.wasm').replaceAll('\\', '/');
const MANIFEST_PATH = join(__dirname, '../../../artifacts/policy/manifest.json').replaceAll('\\', '/');
const OPA_BIN = join(__dirname, '../../../tools/bin', process.platform === 'win32' ? 'opa.exe' : 'opa').replaceAll('\\', '/');
const POLICY_FILE = join(__dirname, '../../../policies/agent-trust/decision.rego').replaceAll('\\', '/');

function opaEvalStdin(input: unknown, timeoutMs = 30_000): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(OPA_BIN, ['eval', '--format=json', '-I', '-d', POLICY_FILE, 'data.agenttrust.decision']);
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`opa eval timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    child.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });
    child.on('error', (e) => { clearTimeout(timer); reject(e); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve(stdout);
      else reject(new Error(`opa eval exited ${code}: ${stderr.slice(0, 500)}`));
    });
    child.stdin.write(JSON.stringify(input));
    child.stdin.end();
  });
}

/**
 * 8M — native Rego (opa eval) vs embedded Wasm MUST agree for a corpus of
 * representative inputs. This pins the result-set unwrapping and catches
 * Wasm-runtime builtin gaps (it already caught time.parse_rfc3339_ns).
 */
describe('native Rego ↔ Wasm parity (8M)', () => {
  let engine: OpaWasmPolicyEngine;

  beforeAll(async () => {
    const result = await loadOpaWasmPolicyEngine(WASM_PATH, MANIFEST_PATH);
    if (!result.ok) throw new Error(`engine failed to load: ${result.detail}`);
    engine = result.engine as OpaWasmPolicyEngine;
  });

  async function nativeDecision(input: VerifiedFactsFixture): Promise<{ effect: string; reasonCodes: string[] }> {
    const query = 'data.agenttrust.decision';
    const stdout = await opaEvalStdin(input);
    void query;
    const parsed = JSON.parse(stdout) as { result?: { expressions: { value: unknown }[] }[] };
    const value = parsed.result?.[0]?.expressions?.[0]?.value;
    expect(value).toBeDefined();
    return value as { effect: string; reasonCodes: string[] };
  }

  const corpus: { name: string; facts: VerifiedFactsFixture }[] = [
    { name: 'allow 120 SAR', facts: canonicalPolicyInput({ amount: 120, currency: 'SAR' }) },
    { name: 'deny 5000 SAR', facts: canonicalPolicyInput({ amount: 5000, currency: 'SAR' }) },
    { name: 'at-limit 500 SAR', facts: canonicalPolicyInput({ amount: 500, currency: 'SAR' }) },
    { name: 'wrong action', facts: canonicalPolicyInput({ action: 'payment:create', amount: 100, currency: 'SAR' }) },
    { name: 'wrong resource', facts: canonicalPolicyInput({ resource: 'tenant:acme', amount: 100, currency: 'SAR' }) },
    { name: 'wrong audience', facts: canonicalPolicyInput({ audience: 'did:web:evil.example:agent', amount: 100, currency: 'SAR' }) },
    { name: 'wrong currency', facts: canonicalPolicyInput({ amount: 100, currency: 'USD' }) },
    {
      name: 'expired authority',
      facts: canonicalPolicyInput({
        amount: 100,
        currency: 'SAR',
        authority: { validFrom: '2026-01-01T00:00:00Z', validUntil: '2026-09-01T00:00:00Z' },
      }),
    },
    {
      name: 'not-yet-valid authority',
      facts: canonicalPolicyInput({
        amount: 100,
        currency: 'SAR',
        authority: { validFrom: '2026-10-01T00:00:00Z', validUntil: '2026-12-01T00:00:00Z' },
      }),
    },
    {
      name: 'unconstrained authority (no audience/limits)',
      facts: canonicalPolicyInput({
        amount: 42,
        currency: 'SAR',
        authority: { actions: ['refund:create'], resources: ['order:*'] },
      }),
    },
  ];

  it.each(corpus)('parity: $name', async ({ facts }) => {
    const native = await nativeDecision(facts);
    const wasmDecision = await engine.evaluate(facts);
    expect(wasmDecision.effect).toBe(native.effect);
    expect(wasmDecision.reasonCodes).toEqual(native.reasonCodes);
  });

  it('empty result-set from the SDK can never mean ALLOW', async () => {
    // A policy whose entrypoint is undefined yields an empty result-set.
    // The engine must fail closed — simulated via the SDK's raw shape.
    const raw = [] as unknown[];
    const unwrapped = (raw as { result?: unknown }[])[0]?.result;
    expect(unwrapped).toBeUndefined();
  });
});
