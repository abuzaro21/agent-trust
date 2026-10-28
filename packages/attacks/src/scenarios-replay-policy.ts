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
  expected: { verdict: 'DENIED', outcome: 'first ALLOW + SUCCEEDED; second REPLAY_DETECTED', reasonCode: 'REPLAY_DETECTED' },
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
      verdict: first.outcome === 'AUTHORIZED' && second.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: second.reasonCodes,
      invariants: {
        firstAuthorized: first.outcome === 'AUTHORIZED',
        secondDenied: second.effect === 'DENY',
        successfulRefunds: w.executor.successfulRefundCount,
        executorCalls: w.executor.callCount.total,
      },
    };
  },
};

export const REPLAY_002: AttackScenario = {
  id: 'REPLAY-002',
  category: 'REPLAY',
  kind: 'ATTACK',
  title: 'Concurrent replay race: 100 identical valid requests at once',
  expected: { verdict: 'CONTAINED', outcome: 'exactly 1 claim wins; 99 denied; 1 logical refund', reasonCode: 'REPLAY_DETECTED' },
  async run() {
    const w = await buildAttackWorld();
    const request = await w.task({ taskId: 'atk_race' });
    const results = await Promise.all(Array.from({ length: 100 }, () => w.gateway.handleTask(request)));
    const authorized = results.filter((r) => r.outcome === 'AUTHORIZED');
    const denied = results.filter((r) => r.outcome !== 'AUTHORIZED');
    const replayDenied = denied.filter((r) => r.reasonCodes.includes('REPLAY_DETECTED'));
    return {
      outcome: `authorized=${authorized.length} denied=${denied.length} (replay-denied=${replayDenied.length})`,
      verdict: authorized.length === 1 && denied.length === 99 ? 'CONTAINED' : 'BREACHED',
      reasonCodes: replayDenied[0]?.reasonCodes ?? [],
      invariants: {
        authorizedCount: authorized.length,
        deniedCount: denied.length,
        replayDeniedCount: replayDenied.length,
        successfulRefunds: w.executor.successfulRefundCount,
        executorCalls: w.executor.callCount.total,
      },
    };
  },
};

export const REPLAY_003: AttackScenario = {
  id: 'REPLAY-003',
  category: 'REPLAY',
  kind: 'FAILURE_DEMO',
  title: 'Replay store unavailable — protected write fails closed',
  expected: { verdict: 'FAILED_SAFE', outcome: 'DENY, executor never runs', reasonCode: 'REPLAY_PROTECTION_UNAVAILABLE' },
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
      verdict: result.effect === 'DENY' ? 'FAILED_SAFE' : 'BREACHED',
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
  expected: { verdict: 'CONTAINED', outcome: 'attacker denied pre-replay; legitimate request with same jti succeeds', reasonCode: 'IDENTITY_PROOF_INVALID' },
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
      verdict: attack.effect === 'DENY' && legitResult.outcome === 'AUTHORIZED' ? 'CONTAINED' : 'BREACHED',
      reasonCodes: attack.reasonCodes,
      invariants: {
        attackerDenied: attack.effect === 'DENY',
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
  expected: { verdict: 'REFUSED', outcome: 'a corrupted bundle never becomes a usable policy engine', reasonCode: 'POLICY_BUNDLE_INVALID' },
  async run() {
    const { mkdtemp, writeFile, readFile, copyFile } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const { ATTACK_WASM_PATH, ATTACK_MANIFEST_PATH } = await import('./world.js');
    const { loadOpaWasmPolicyEngine, loadBundle, sha256OfBytes } = await import('@agent-trust/policy');
    const genuineManifest = JSON.parse(await readFile(ATTACK_MANIFEST_PATH, 'utf8')) as Record<string, unknown>;
    const genuineWasm = await readFile(ATTACK_WASM_PATH);

    // Control: the genuine, untouched artifact loads and yields an engine.
    const control = await loadOpaWasmPolicyEngine(ATTACK_WASM_PATH, ATTACK_MANIFEST_PATH);

    // (a) Realistic corruption: one flipped byte, genuine manifest => the pinned digest no longer matches.
    const dirA = await mkdtemp(join(tmpdir(), 'atk-policy-'));
    const flipped = Buffer.from(genuineWasm);
    flipped[flipped.length - 1] = flipped[flipped.length - 1]! ^ 0xff;
    await writeFile(join(dirA, 'policy.wasm'), flipped);
    await copyFile(ATTACK_MANIFEST_PATH, join(dirA, 'manifest.json'));
    const flippedBundle = await loadBundle(join(dirA, 'policy.wasm'), join(dirA, 'manifest.json'));
    const flippedLoad = await loadOpaWasmPolicyEngine(join(dirA, 'policy.wasm'), join(dirA, 'manifest.json'));

    // (b) A self-consistent but invalid module: garbage bytes whose digest MATCHES a well-formed manifest.
    //     The digest gate passes, so only instantiation can (and must) refuse it.
    const dirB = await mkdtemp(join(tmpdir(), 'atk-policy-'));
    const garbage = Buffer.from('this is not wasm');
    await writeFile(join(dirB, 'policy.wasm'), garbage);
    await writeFile(join(dirB, 'manifest.json'), JSON.stringify({ ...genuineManifest, sha256: sha256OfBytes(garbage) }));
    const garbageBundle = await loadBundle(join(dirB, 'policy.wasm'), join(dirB, 'manifest.json'));
    const garbageLoad = await loadOpaWasmPolicyEngine(join(dirB, 'policy.wasm'), join(dirB, 'manifest.json'));

    const refused = !flippedLoad.ok && !garbageLoad.ok;
    return {
      outcome: refused ? 'corrupted bundle refused at load: digest gate (flipped byte) and instantiation (self-consistent garbage) both fail closed' : 'UNEXPECTED: a corrupted bundle produced an engine',
      verdict: refused ? 'REFUSED' : 'BREACHED',
      reasonCodes: flippedLoad.ok ? [] : [flippedLoad.reasonCode],
      invariants: {
        controlLoadsEngine: control.ok === true && typeof (control as { engine?: unknown }).engine === 'object',
        flippedByteStage: flippedBundle.ok ? 'accepted' : flippedBundle.reason,
        flippedByteEngineObtainable: 'engine' in flippedLoad,
        garbageWithMatchingDigestPassesDigestGate: garbageBundle.ok === true,
        garbageRefusedAtInstantiation: !garbageLoad.ok && garbageLoad.reasonCode === 'POLICY_BUNDLE_INVALID' && garbageLoad.detail.startsWith('instantiation failed'),
        garbageEngineObtainable: 'engine' in garbageLoad,
      },
    };
  },
};

export const POLICY_002: AttackScenario = {
  id: 'POLICY-002',
  category: 'POLICY',
  kind: 'ATTACK',
  title: 'Manifest hash mismatch — artifact integrity gate',
  expected: { verdict: 'REFUSED', outcome: 'a well-formed manifest pinning the WRONG digest is refused at the digest gate and yields no engine', reasonCode: 'POLICY_BUNDLE_INVALID' },
  async run() {
    const { mkdtemp, writeFile, copyFile, readFile } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const { ATTACK_WASM_PATH, ATTACK_MANIFEST_PATH } = await import('./world.js');
    const { loadOpaWasmPolicyEngine, loadBundle } = await import('@agent-trust/policy');
    const genuine = JSON.parse(await readFile(ATTACK_MANIFEST_PATH, 'utf8')) as Record<string, unknown>;

    // Control: the genuine manifest + wasm load and yield an engine (so a refusal below is caused by the digest, not by a missing file).
    const control = await loadOpaWasmPolicyEngine(ATTACK_WASM_PATH, ATTACK_MANIFEST_PATH);

    // Tampered manifest: EVERY genuine field kept (id, entrypoint, compiledBy, ...) so the shape is valid; only the pinned digest is wrong.
    const dir = await mkdtemp(join(tmpdir(), 'atk-policy-'));
    await copyFile(ATTACK_WASM_PATH, join(dir, 'policy.wasm'));
    await writeFile(join(dir, 'manifest.json'), JSON.stringify({ ...genuine, sha256: 'sha256:' + '1'.repeat(64) }));
    const bundle = await loadBundle(join(dir, 'policy.wasm'), join(dir, 'manifest.json'));
    const result = await loadOpaWasmPolicyEngine(join(dir, 'policy.wasm'), join(dir, 'manifest.json'));
    return {
      outcome: !result.ok ? 'manifest hash mismatch refused at the digest gate; no engine produced' : 'UNEXPECTED: mismatched manifest accepted',
      verdict: !result.ok ? 'REFUSED' : 'BREACHED',
      reasonCodes: result.ok ? [] : [result.reasonCode],
      invariants: {
        controlLoadsEngine: control.ok === true && typeof (control as { engine?: unknown }).engine === 'object',
        refusalStage: bundle.ok ? 'accepted' : bundle.reason,
        engineObtainable: 'engine' in result,
      },
    };
  },
};

export const POLICY_003: AttackScenario = {
  id: 'POLICY-003',
  category: 'INFRASTRUCTURE' as const,
  kind: 'FAILURE_DEMO',
  title: 'Policy engine outage mid-pipeline — fail closed, executor untouched',
  expected: { verdict: 'FAILED_SAFE', outcome: 'DENY, no side effect', reasonCode: 'POLICY_EVALUATION_ERROR' },
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
      verdict: result.effect === 'DENY' ? 'FAILED_SAFE' : 'BREACHED',
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
  expected: { verdict: 'REFUSED', outcome: 'VerifiedFacts schema rejects score fields; the engine denies the injected input', reasonCode: 'REQUEST_MALFORMED' },
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
      credential: { verified: true, issuer: 'did:web:evil.example:agent', issuerTrusted: true, types: ['AgentDelegationCredential'] },
      authority: { actions: ['refund:create'], resources: ['order:*'] },
      status: { credentialActive: true, quarantined: false },
      replay: { checked: true, claimed: true },
      context: { now: '2026-09-15T12:00:00Z' },
      trustScore: 100, // ← attacker-injected reputation field
    };
    const rejected = !validator.validate(factsSchemaId, injection).valid;
    // Control: the SAME facts WITHOUT the score field are schema-valid, so the rejection above is caused by the score field alone.
    const { trustScore: _score, ...withoutScore } = injection;
    void _score;
    const controlValidWithoutScore = validator.validate(factsSchemaId, withoutScore).valid;
    // And the policy engine itself: feed the injected object directly.
    const decision = await w.gatewayDeps.policyEngine.evaluate(injection);
    // Even if some engine accepted it, the score plays no role in the Rego:
    // the injected authority still denies on amount/scope.
    return {
      outcome: rejected
        ? `schema rejected trustScore injection; policy over injected facts → ${decision.effect}`
        : `schema ACCEPTED injection (see bugs); policy → ${decision.effect}`,
      verdict: rejected && decision.effect === 'DENY' ? 'REFUSED' : 'BREACHED',
      reasonCodes: decision.reasonCodes,
      invariants: { schemaRejectedScore: rejected, controlValidWithoutScore, engineDecisionEffect: decision.effect },
    };
  },
};

export const POLICY_SCENARIOS = [POLICY_001, POLICY_002, POLICY_003, POLICY_004];
