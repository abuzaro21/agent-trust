import type { AttackScenario } from './types.js';
import { buildAttackWorld } from './world.js';

/**
 * Step 13H — Replay attacks. R2 uses the gateway path with 100 concurrent
 * identical requests; the in-memory store is the same atomic CLAIM-ONCE
 * seam Redis implements (Redis concurrency has its own integration tests).
 */

export const REPLAY_001: AttackScenario = {
  id: 'REPLAY-001',
  category: 'REPLAY',
  kind: 'ATTACK',
  title: 'Exact replay: identical signed bytes submitted twice',
  expected: { outcome: 'first ALLOW + SUCCEEDED; second REPLAY_DETECTED', reasonCode: 'REPLAY_DETECTED' },
  async run() {
    const w = await buildAttackWorld();
    const request = await w.task({ taskId: 'atk_replay' });
    const first = await w.gateway.handleTask(request);
    const second = await w.gateway.handleTask(request);
    return {
      outcome:
        first.outcome === 'AUTHORIZED' && second.effect === 'DENY'
          ? 'first ALLOW+SUCCEEDED; replay DENIED'
          : `first=${first.outcome} second=${second.outcome}`,
      reasonCodes: second.reasonCodes,
      invariants: { successfulRefunds: w.executor.successfulRefundCount, executorCalls: w.executor.callCount.total },
    };
  },
};

export const REPLAY_002: AttackScenario = {
  id: 'REPLAY-002',
  category: 'REPLAY',
  kind: 'ATTACK',
  title: 'Concurrent replay race: 100 identical valid requests at once',
  expected: { outcome: 'exactly 1 claim wins; 99 denied; 1 logical refund' },
  async run() {
    const w = await buildAttackWorld();
    const request = await w.task({ taskId: 'atk_race' });
    const results = await Promise.all(Array.from({ length: 100 }, () => w.gateway.handleTask(request)));
    const authorized = results.filter((r) => r.outcome === 'AUTHORIZED');
    const denied = results.filter((r) => r.outcome !== 'AUTHORIZED');
    const replayDenied = denied.filter((r) => r.reasonCodes.includes('REPLAY_DETECTED'));
    return {
      outcome: `authorized=${authorized.length} denied=${denied.length} (replay-denied=${replayDenied.length})`,
      reasonCodes: denied[0]?.reasonCodes ?? [],
      invariants: { successfulRefunds: w.executor.successfulRefundCount, executorCalls: w.executor.callCount.total },
    };
  },
};

export const REPLAY_003: AttackScenario = {
  id: 'REPLAY-003',
  category: 'REPLAY',
  kind: 'FAILURE_DEMO',
  title: 'Replay store unavailable — protected write fails closed',
  expected: { outcome: 'DENY, executor never runs', reasonCode: 'REPLAY_PROTECTION_UNAVAILABLE' },
  async run() {
    const w = await buildAttackWorld();
    // Break the store AFTER construction (infrastructure outage).
    // Exactly the contract RedisReplayStore throws on an outage.
    const { ReplayStoreUnavailableError } = await import('@agent-trust/replay');
    const brokenStore = {
      claim: async () => {
        throw new ReplayStoreUnavailableError(new Error('ECONNREFUSED 127.0.0.1:6379'));
      },
    };
    const { ReplayProtector } = await import('@agent-trust/replay');
    const broken = new ReplayProtector(brokenStore as never);
    const gateway = new (await import('../../gateway/src/gateway.js')).TrustGateway({ ...w.gatewayDeps, replayProtector: broken });
    const result = await gateway.handleTask(await w.task({ taskId: 'atk_replay_outage' }));
    return {
      outcome: result.effect === 'DENY' ? `DENY (stage replay=${result.stages.replay})` : result.outcome,
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n },
    };
  },
};

export const REPLAY_004: AttackScenario = {
  id: 'REPLAY-004',
  category: 'REPLAY',
  kind: 'ATTACK',
  title: 'Replay-poisoning: attacker burns a future jti; legitimate proof must still work',
  expected: { outcome: 'attacker denied pre-replay; legitimate request with same jti succeeds' },
  async run() {
    const w = await buildAttackWorld();
    // Legitimate request, but we FIRST send a garbage-signature request
    // carrying the SAME jti. Crypto-first ordering means the attacker's
    // request dies at PoP BEFORE the replay claim — no poisoning.
    const legit = await w.task({ taskId: 'atk_poison_legit' });
    const poisoned = structuredClone(legit) as typeof legit;
    // Corrupt the signature bytes, keep the jti.
    poisoned.proof.signature = poisoned.proof.signature.slice(0, -4) + 'AAAA';
    const attack = await w.gateway.handleTask(poisoned);
    const legitResult = await w.gateway.handleTask(legit);
    return {
      outcome: `attacker=${attack.outcome}; legitimate=${legitResult.outcome}`,
      reasonCodes: attack.reasonCodes,
      invariants: {
        executorCalls: w.executor.callCount.total,
        legitAuthorized: legitResult.outcome === 'AUTHORIZED',
        successfulRefunds: w.executor.successfulRefundCount,
      },
    };
  },
};

export const REPLAY_SCENARIOS = [REPLAY_001, REPLAY_002, REPLAY_003, REPLAY_004];

// ------------------------------------------------------------- policy

export const POLICY_001: AttackScenario = {
  id: 'POLICY-001',
  category: 'POLICY',
  kind: 'ATTACK',
  title: 'Corrupted policy Wasm — refused at load, fail closed',
  expected: { outcome: 'bundle rejected at load' },
  async run() {
    const w = await buildAttackWorld();
    const { mkdtemp, writeFile } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const dir = await mkdtemp(join(tmpdir(), 'atk-policy-'));
    await writeFile(join(dir, 'policy.wasm'), Buffer.from('this is not wasm'));
    await writeFile(join(dir, 'manifest.json'), JSON.stringify({ sha256: 'sha256:' + '0'.repeat(64), regoSha256: 'sha256:' + '0'.repeat(64), policyId: 'x', version: '0' }));
    const { loadOpaWasmPolicyEngine } = await import('@agent-trust/policy');
    const result = await loadOpaWasmPolicyEngine(join(dir, 'policy.wasm'), join(dir, 'manifest.json'));
    return {
      outcome: !result.ok ? 'corrupted bundle rejected at load (fail closed)' : 'UNEXPECTED: corrupted bundle loaded',
      reasonCodes: result.ok ? [] : [result.reasonCode],
      invariants: { executorCalls: w.executor.callCount.total },
    };
  },
};

export const POLICY_002: AttackScenario = {
  id: 'POLICY-002',
  category: 'POLICY',
  kind: 'ATTACK',
  title: 'Manifest hash mismatch — artifact integrity gate',
  expected: { outcome: 'load refused', reasonCode: 'POLICY_BUNDLE_INVALID' },
  async run() {
    const { mkdtemp, writeFile, copyFile } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join, dirname } = await import('node:path');
    const { fileURLToPath } = await import('node:url');
    const wasmSrc = join(dirname(fileURLToPath(import.meta.url)), '../../../artifacts/policy/policy.wasm');
    const dir = await mkdtemp(join(tmpdir(), 'atk-policy-'));
    await copyFile(wasmSrc, join(dir, 'policy.wasm'));
    // Tampered manifest: valid JSON, WRONG sha256.
    await writeFile(
      join(dir, 'manifest.json'),
      JSON.stringify({ sha256: 'sha256:' + '1'.repeat(64), regoSha256: 'sha256:' + '2'.repeat(64), policyId: 'p', version: '1' }),
    );
    const { loadOpaWasmPolicyEngine } = await import('@agent-trust/policy');
    const result = await loadOpaWasmPolicyEngine(join(dir, 'policy.wasm'), join(dir, 'manifest.json'));
    return {
      outcome: !result.ok ? 'manifest hash mismatch refused at load' : 'UNEXPECTED: mismatched manifest accepted',
      reasonCodes: result.ok ? [] : [result.reasonCode],
      invariants: {},
    };
  },
};

export const POLICY_003: AttackScenario = {
  id: 'POLICY-003',
  category: 'INFRASTRUCTURE' as const,
  kind: 'FAILURE_DEMO',
  title: 'Policy engine outage mid-pipeline — fail closed, executor untouched',
  expected: { outcome: 'DENY, no side effect', reasonCode: 'POLICY_EVALUATION_ERROR' },
  async run() {
    const w = await buildAttackWorld();
    const brokenPolicy = {
      evaluate: async () => {
        throw new Error('wasm runtime crashed');
      },
    };
    const gateway = new (await import('../../gateway/src/gateway.js')).TrustGateway({ ...w.gatewayDeps, policyEngine: brokenPolicy });
    const result = await gateway.handleTask(await w.task({ taskId: 'atk_policy_outage' }));
    return {
      outcome: result.effect === 'DENY' ? `DENY (stage policy=${result.stages.policy})` : result.outcome,
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total },
    };
  },
};

export const POLICY_004: AttackScenario = {
  id: 'POLICY-004',
  category: 'POLICY',
  kind: 'ATTACK',
  title: 'Reputation-score injection: trustScore in the policy input is schema-rejected',
  expected: { outcome: 'VerifiedFacts schema rejects score fields; decision unaffected' },
  async run() {
    const w = await buildAttackWorld();
    const { createValidator, SCHEMA_ID_VERIFIED_FACTS } = await import('@agent-trust/schemas');
    const validator = createValidator();
    // Try injecting a score into a copied VerifiedFacts-shaped object.
    const legit = await w.gateway.handleTask(await w.task({ taskId: 'atk_score_legit' }));
    void legit;
    const { loadOpaWasmPolicyEngine } = await import('@agent-trust/policy');
    void loadOpaWasmPolicyEngine;
    const factsSchemaId = SCHEMA_ID_VERIFIED_FACTS;
    const injection = {
      actor: { did: 'did:web:evil.example:agent' },
      request: { action: 'refund:create', resource: 'order:ORD-918', audience: 'did:web:trust.example.com:agents:refund' },
      identity: { proofVerified: true },
      credential: { verified: true, issuer: 'did:web:evil.example:agent', issuerTrusted: true, types: [] },
      authority: { actions: ['refund:create'], resources: ['order:*'] },
      status: { credentialActive: true, quarantined: false },
      replay: { checked: true, claimed: true },
      context: { now: '2026-09-15T12:00:00Z' },
      trustScore: 100, // ← attacker-injected reputation field
    };
    const rejected = !validator.validate(factsSchemaId, injection).valid;
    // And the policy engine itself: feed the injected object directly.
    const decision = await w.gatewayDeps.policyEngine.evaluate(injection);
    // Even if some engine accepted it, the score plays no role in the Rego:
    // the injected authority still denies on amount/scope.
    return {
      outcome: rejected
        ? `schema rejected trustScore injection; policy over injected facts → ${decision.effect}`
        : `schema ACCEPTED injection (see bugs); policy → ${decision.effect}`,
      reasonCodes: decision.reasonCodes,
      invariants: { schemaRejectedScore: rejected },
    };
  },
};

export const POLICY_SCENARIOS = [POLICY_001, POLICY_002, POLICY_003, POLICY_004];
