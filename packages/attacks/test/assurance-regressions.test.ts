import { copyFile, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { loadBundle, loadOpaWasmPolicyEngine } from '@agent-trust/policy';
import { SCHEMA_ID_VERIFIED_FACTS, createValidator } from '@agent-trust/schemas';
import { verifyCheckpointSignature } from '@agent-trust/audit';

import {
  ATTACK_MANIFEST_PATH,
  ATTACK_REGISTRY,
  ATTACK_WASM_PATH,
  INVARIANT_CHECKS,
  buildAttackWorld,
  judge,
  runAttackSuite,
  type AttackObserved,
} from '../src/index.js';
import { anchorCheckpoint } from '../src/world.js';

/**
 * Regression tests for the weaknesses found by the root-cause audit. Each
 * block states the ORIGINAL weak behaviour and proves it is now rejected.
 */

const scenario = (id: string) => ATTACK_REGISTRY.find((s) => s.id === id)!;
const observe = async (id: string) => (await runAttackSuite({ only: [id] })).scenarios[0]!.observed;

describe('STATUS-004 — the executor/policy counters are now asserted (was: unconditional pass)', () => {
  it('the real observation records zero executor calls, zero policy calls and a failed credential stage', async () => {
    const o = await observe('STATUS-004');
    expect(o.invariants).toMatchObject({ executorCalls: 0, policyCalls: 0, credentialStage: 'FAIL' });
    expect(o.reasonCodes).toContain('CREDENTIAL_STATUS_UNAVAILABLE');
    expect(judge(scenario('STATUS-004'), o, INVARIANT_CHECKS['STATUS-004']).status).toBe('PASS');
  });

  it('NEGATIVE CONTROL: one executor call makes it FAIL', async () => {
    const o = await observe('STATUS-004');
    const bad: AttackObserved = { ...o, invariants: { ...o.invariants, executorCalls: 1 } };
    const j = judge(scenario('STATUS-004'), bad, INVARIANT_CHECKS['STATUS-004']);
    expect(j.status).toBe('FAIL');
    expect(j.failures.join()).toMatch(/executorCalls=1/);
  });

  it('NEGATIVE CONTROL: a policy evaluation, a passed credential stage, or missing counters make it FAIL', async () => {
    const o = await observe('STATUS-004');
    const check = INVARIANT_CHECKS['STATUS-004']!;
    expect(check({ ...o, invariants: { ...o.invariants, policyCalls: 1 } }).ok).toBe(false);
    expect(check({ ...o, invariants: { ...o.invariants, credentialStage: 'PASS' } }).ok).toBe(false);
    expect(check({ ...o, invariants: {} }).ok).toBe(false);
    expect(check({ ...o, invariants: { executorCalls: 0 } }).ok).toBe(false);
  });
});

describe('POLICY-002 — manifest digest mismatch now reaches the digest gate (was: shape-invalid manifest, wrong gate)', () => {
  it('the original fixture {sha256, regoSha256, policyId, version} is refused by the SHAPE gate, not the digest gate', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'reg-policy-'));
    await copyFile(ATTACK_WASM_PATH, join(dir, 'policy.wasm'));
    await writeFile(join(dir, 'manifest.json'), JSON.stringify({ sha256: 'sha256:' + '0'.repeat(64), regoSha256: 'x', policyId: 'p', version: '1' }));
    const r = await loadBundle(join(dir, 'policy.wasm'), join(dir, 'manifest.json'));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe('manifest_invalid'); // so it could never have exercised "hash mismatch"
  });

  it('the genuine artifact loads (control) and a one-field tamper is refused at the digest gate with no engine', async () => {
    const control = await loadOpaWasmPolicyEngine(ATTACK_WASM_PATH, ATTACK_MANIFEST_PATH);
    expect(control.ok).toBe(true);
    const genuine = JSON.parse(await readFile(ATTACK_MANIFEST_PATH, 'utf8')) as Record<string, unknown>;
    const dir = await mkdtemp(join(tmpdir(), 'reg-policy-'));
    await copyFile(ATTACK_WASM_PATH, join(dir, 'policy.wasm'));
    await writeFile(join(dir, 'manifest.json'), JSON.stringify({ ...genuine, sha256: 'sha256:' + '1'.repeat(64) }));
    const bundle = await loadBundle(join(dir, 'policy.wasm'), join(dir, 'manifest.json'));
    expect(bundle.ok).toBe(false);
    if (!bundle.ok) expect(bundle.reason).toBe('hash_mismatch');
    const engine = await loadOpaWasmPolicyEngine(join(dir, 'policy.wasm'), join(dir, 'manifest.json'));
    expect(engine.ok).toBe(false);
    expect('engine' in engine).toBe(false);
    if (!engine.ok) expect(engine.reasonCode).toBe('POLICY_BUNDLE_INVALID');
  });

  it('the scenario records the loader-boundary evidence and passes', async () => {
    const o = await observe('POLICY-002');
    expect(o.invariants).toEqual({ controlLoadsEngine: true, refusalStage: 'hash_mismatch', engineObtainable: false });
    expect(judge(scenario('POLICY-002'), o, INVARIANT_CHECKS['POLICY-002']).status).toBe('PASS');
  });

  it('NEGATIVE CONTROLS: an engine obtained from a bad manifest, the wrong refusal stage, or a dead control all FAIL', async () => {
    const o = await observe('POLICY-002');
    const check = INVARIANT_CHECKS['POLICY-002']!;
    expect(check({ ...o, invariants: { ...o.invariants, engineObtainable: true } }).ok).toBe(false);
    expect(check({ ...o, invariants: { ...o.invariants, refusalStage: 'manifest_invalid' } }).ok).toBe(false);
    expect(check({ ...o, invariants: { ...o.invariants, refusalStage: 'accepted' } }).ok).toBe(false);
    expect(check({ ...o, invariants: { ...o.invariants, controlLoadsEngine: false } }).ok).toBe(false);
    expect(check({ ...o, invariants: {} }).ok).toBe(false);
    // And through the full oracle, a breached observation with a reassuring sentence still fails.
    expect(judge(scenario('POLICY-002'), { ...o, verdict: 'BREACHED', outcome: 'manifest hash mismatch refused' }, check).status).toBe('FAIL');
  });
});

describe('POLICY-001 — a corrupted module is refused at BOTH the digest gate and instantiation (was: shape-invalid manifest)', () => {
  it('records both refusal stages plus a loading control, and passes', async () => {
    const o = await observe('POLICY-001');
    expect(o.invariants).toEqual({
      controlLoadsEngine: true,
      flippedByteStage: 'hash_mismatch',
      flippedByteEngineObtainable: false,
      garbageWithMatchingDigestPassesDigestGate: true,
      garbageRefusedAtInstantiation: true,
      garbageEngineObtainable: false,
    });
    expect(o.reasonCodes).toContain('POLICY_BUNDLE_INVALID');
  });

  it('NEGATIVE CONTROL: if either corrupted artifact yielded an engine, the checker FAILS', async () => {
    const o = await observe('POLICY-001');
    const check = INVARIANT_CHECKS['POLICY-001']!;
    expect(check({ ...o, invariants: { ...o.invariants, flippedByteEngineObtainable: true } }).ok).toBe(false);
    expect(check({ ...o, invariants: { ...o.invariants, garbageEngineObtainable: true } }).ok).toBe(false);
    expect(check({ ...o, invariants: { ...o.invariants, garbageRefusedAtInstantiation: false } }).ok).toBe(false);
  });
});

describe('AUDIT — the checkpoint fixture is valid, so the checkpoint half actually tests tampering', () => {
  it('the original checkpoint id "ckpt_au" (7 chars) violates the payload schema (minLength 8) and was rejected for THAT reason', async () => {
    const w = await buildAttackWorld();
    await w.gateway.handleTask(await w.task({ amount: 120, taskId: 'reg_ok' }));
    const weak = await anchorCheckpoint(w, 'ckpt_au');
    const v = await verifyCheckpointSignature({ checkpoint: weak, didResolver: w.gatewayDeps.didResolver });
    expect(v.valid).toBe(false);
    if (!v.valid) expect(v.detail).toBe('payload schema invalid');
    const sound = await anchorCheckpoint(w, 'ckpt_audit_tamper');
    expect((await verifyCheckpointSignature({ checkpoint: sound, didResolver: w.gatewayDeps.didResolver })).valid).toBe(true);
  });

  it('AUDIT-007 / AUDIT-008 now fail for the SPECIFIC anchoring reasons (head mismatch / truncation)', async () => {
    expect((await observe('AUDIT-007')).reasonCodes).toEqual(['AUDIT_CHECKPOINT_MISMATCH']);
    expect((await observe('AUDIT-008')).reasonCodes).toEqual(['AUDIT_SEQUENCE_INVALID']);
  });

  it('NEGATIVE CONTROL: a tamper scenario whose untouched control history did not verify FAILS', async () => {
    for (const id of ['AUDIT-001', 'AUDIT-007', 'AUDIT-008']) {
      const o = await observe(id);
      expect(INVARIANT_CHECKS[id]!({ ...o, invariants: { ...o.invariants, controlIntact: false } }).ok, id).toBe(false);
      expect(INVARIANT_CHECKS[id]!({ ...o, invariants: { ...o.invariants, controlConsumerHistoryVerified: false } }).ok, id).toBe(false);
    }
  });

  it('NEGATIVE CONTROL: a consumer that still trusts the tampered history FAILS AUDIT-001..008', async () => {
    for (let n = 1; n <= 8; n++) {
      const id = `AUDIT-00${n}`;
      const o = await observe(id);
      expect(INVARIANT_CHECKS[id]!({ ...o, invariants: { ...o.invariants, consumerHistoryVerified: true } }).ok, id).toBe(false);
    }
  });
});

describe('POLICY-004 — the injected-score fixture is rejected because of the score and nothing else', () => {
  const facts = {
    actor: { did: 'did:web:evil.example:agent' },
    request: { action: 'refund:create', resource: 'order:ORD-918', audience: 'did:web:trust.example.com:agents:refund' },
    identity: { proofVerified: true },
    status: { credentialActive: true, quarantined: false },
    replay: { checked: true, claimed: true },
    authority: { actions: ['refund:create'], resources: ['order:*'] },
    context: { now: '2026-09-15T12:00:00Z' },
  };
  const validator = createValidator();

  it('the ORIGINAL fixture (empty credential.types) was schema-invalid even without a score', () => {
    const original = { ...facts, credential: { verified: true, issuer: 'did:web:evil.example:agent', issuerTrusted: true, types: [] } };
    expect(validator.validate(SCHEMA_ID_VERIFIED_FACTS, original).valid).toBe(false);
  });

  it('the corrected fixture is valid without the score, and invalid ONLY for the extra property with it', () => {
    const credential = { verified: true, issuer: 'did:web:evil.example:agent', issuerTrusted: true, types: ['AgentDelegationCredential'] };
    expect(validator.validate(SCHEMA_ID_VERIFIED_FACTS, { ...facts, credential }).valid).toBe(true);
    const withScore = validator.validate(SCHEMA_ID_VERIFIED_FACTS, { ...facts, credential, trustScore: 100 });
    expect(withScore.valid).toBe(false);
    if (!withScore.valid) expect(withScore.errors).toEqual(['/ must NOT have additional properties']);
  });

  it('NEGATIVE CONTROL: a scenario whose control did not validate (rejection for the wrong reason) FAILS', async () => {
    const o = await observe('POLICY-004');
    expect(INVARIANT_CHECKS['POLICY-004']!({ ...o, invariants: { ...o.invariants, controlValidWithoutScore: false } }).ok).toBe(false);
    expect(INVARIANT_CHECKS['POLICY-004']!({ ...o, invariants: { ...o.invariants, schemaRejectedScore: false } }).ok).toBe(false);
  });
});

describe('REPLAY-002 — typed counts replace the outcome-text regex', () => {
  it('records numeric counts, and the oracle no longer reads the outcome string', async () => {
    const o = await observe('REPLAY-002');
    expect(o.invariants).toMatchObject({ authorizedCount: 1, deniedCount: 99, replayDeniedCount: 99, successfulRefunds: 1, executorCalls: 1 });
    // A doctored sentence that LOOKS right cannot rescue a wrong typed count...
    const lying: AttackObserved = { ...o, outcome: 'authorized=1 denied=99', invariants: { ...o.invariants, authorizedCount: 2 } };
    expect(judge(scenario('REPLAY-002'), lying, INVARIANT_CHECKS['REPLAY-002']).status).toBe('FAIL');
    // ...and a doctored sentence that looks wrong cannot fail a correct typed result (the text is display-only).
    const odd: AttackObserved = { ...o, outcome: 'one winner, ninety-nine losers' };
    expect(judge(scenario('REPLAY-002'), odd, INVARIANT_CHECKS['REPLAY-002']).status).toBe('PASS');
  });
});

describe('the previously-vacuous delegation scenarios now carry a real positive control', () => {
  it('AUTHORITY-005/006 record the walker verdict AND that the legitimate chain is accepted', async () => {
    expect((await observe('AUTHORITY-005')).invariants).toEqual({ walkerRejected: true, controlAttenuatedChainAccepted: true });
    expect((await observe('AUTHORITY-006')).invariants).toEqual({ walkerRejected: true, notStrictlyLessRejected: true, controlWithinBudgetChainAccepted: true });
  });

  it('NEGATIVE CONTROL: a walker that accepts the attack, or rejects the legitimate chain, FAILS', async () => {
    for (const [id, control] of [['AUTHORITY-005', 'controlAttenuatedChainAccepted'], ['AUTHORITY-006', 'controlWithinBudgetChainAccepted']] as const) {
      const o = await observe(id);
      expect(INVARIANT_CHECKS[id]!({ ...o, invariants: { ...o.invariants, walkerRejected: false } }).ok, id).toBe(false);
      expect(INVARIANT_CHECKS[id]!({ ...o, invariants: { ...o.invariants, [control]: false } }).ok, id).toBe(false);
    }
  });
});

describe('mutation-found gaps, now closed (each facet isolates ONE defence)', () => {
  it('AUDIT-009 rejects four distinct checkpoint forgeries, each at its own gate', async () => {
    const o = await observe('AUDIT-009');
    expect(o.invariants).toMatchObject({
      controlPinnedGenuineVerifies: true,
      wrongSignerReasons: ['AUDIT_SIGNER_UNTRUSTED'],
      badSignatureReasons: ['AUDIT_CHECKPOINT_INVALID'],
      editedPayloadReasons: ['AUDIT_CHECKPOINT_INVALID'],
      otherStreamReasons: ['AUDIT_CHECKPOINT_MISMATCH'],
    });
  });

  it('NEGATIVE CONTROL: accepting any one forgery (e.g. a bad signature) makes AUDIT-009 FAIL', async () => {
    const o = await observe('AUDIT-009');
    const check = INVARIANT_CHECKS['AUDIT-009']!;
    for (const key of ['wrongSignerReasons', 'badSignatureReasons', 'editedPayloadReasons', 'otherStreamReasons']) {
      expect(check({ ...o, invariants: { ...o.invariants, [key]: ['ACCEPTED'] } }).ok, key).toBe(false);
    }
    expect(check({ ...o, invariants: { ...o.invariants, controlPinnedGenuineVerifies: false } }).ok).toBe(false);
  });

  it('AUDIT-005: the forged receipt carries a CORRECT own hash, so only the previousHash link can reject it', async () => {
    const o = await observe('AUDIT-005');
    expect(o.reasonCodes).toEqual(['AUDIT_CHAIN_INVALID']);
    expect(o.invariants).toMatchObject({ chainValid: false, consumerHistoryVerified: false });
  });

  it('AUTHORITY-006 covers BOTH depth branches (no budget, and budget but not strictly less)', async () => {
    const o = await observe('AUTHORITY-006');
    expect(o.invariants).toMatchObject({ walkerRejected: true, notStrictlyLessRejected: true });
    expect(INVARIANT_CHECKS['AUTHORITY-006']!({ ...o, invariants: { ...o.invariants, notStrictlyLessRejected: false } }).ok).toBe(false);
  });

  it('DIDWEB-009 isolates the kid-ownership check from the controller check', async () => {
    const o = await observe('DIDWEB-009');
    expect(o.invariants).toMatchObject({ foreignIdAndControllerRefused: true, foreignIdOwnControllerRefused: true, ownIdForeignControllerRefused: true });
    for (const key of ['foreignIdAndControllerRefused', 'foreignIdOwnControllerRefused', 'ownIdForeignControllerRefused']) {
      expect(INVARIANT_CHECKS['DIDWEB-009']!({ ...o, invariants: { ...o.invariants, [key]: false } }).ok, key).toBe(false);
    }
  });

  it('DIDWEB-006 requires the redirect itself to be the recorded cause', async () => {
    const o = await observe('DIDWEB-006');
    expect(o.invariants.redirectRefusedByPolicy).toBe(true);
    expect(INVARIANT_CHECKS['DIDWEB-006']!({ ...o, invariants: { ...o.invariants, redirectRefusedByPolicy: false } }).ok).toBe(false);
  });

  it('ATTEST-001 proves issuer-AND-type scoped trust: a trusted issuer is not trusted for another type', async () => {
    const o = await observe('ATTEST-001');
    expect(o.invariants.rejectedReasons).toEqual(['ATTESTATION_TYPE_UNSUPPORTED', 'UNTRUSTED_ISSUER']);
    expect(INVARIANT_CHECKS['ATTEST-001']!({ ...o, invariants: { ...o.invariants, rejectedReasons: ['UNTRUSTED_ISSUER'] } }).ok).toBe(false);
  });
});

describe('audit-review findings (second independent audit), now closed', () => {
  it('DIDWEB-007 drives the REAL transport: declared length and streamed bytes are both capped, a below-limit body is served', async () => {
    const o = await observe('DIDWEB-007');
    expect(o.invariants).toMatchObject({ declaredLengthCap: 'TOO_LARGE', streamedBytesCap: 'TOO_LARGE', belowLimitControl: 'OK', controlResolves: true });
    const check = INVARIANT_CHECKS['DIDWEB-007']!;
    for (const key of ['declaredLengthCap', 'streamedBytesCap']) {
      expect(check({ ...o, invariants: { ...o.invariants, [key]: 'OK' } }).ok, key).toBe(false); // the cap was not enforced
    }
    expect(check({ ...o, invariants: { ...o.invariants, belowLimitControl: 'TOO_LARGE' } }).ok).toBe(false);
  });

  it('DIDWEB-005 proves pinning: ONE lookup, and the connection primitive receives the validated (first) address', async () => {
    const o = await observe('DIDWEB-005');
    expect(o.invariants).toMatchObject({ lookupsForOneRequest: 1, connectedAddresses: ['93.184.216.34'], connectAttempts: 0, transportErrorCode: 'POLICY' });
    const check = INVARIANT_CHECKS['DIDWEB-005']!;
    expect(check({ ...o, invariants: { ...o.invariants, lookupsForOneRequest: 2 } }).ok).toBe(false); // a second lookup = rebinding window
    expect(check({ ...o, invariants: { ...o.invariants, connectedAddresses: ['10.0.0.5'] } }).ok).toBe(false); // connected to the rebound address
  });

  it('INFRA-002 requires BOTH receipts to exist and be linked (undefined === undefined no longer passes)', async () => {
    const o = await observe('INFRA-002');
    expect(o.invariants).toMatchObject({ decisionReceiptEffect: 'ALLOW', outcomeState: 'FAILED', decisionAndOutcomeChained: true });
    const check = INVARIANT_CHECKS['INFRA-002']!;
    expect(check({ ...o, invariants: { ...o.invariants, decisionReceiptEffect: null } }).ok).toBe(false);
    expect(check({ ...o, invariants: { ...o.invariants, decisionAndOutcomeChained: false } }).ok).toBe(false);
    expect(o.reasonCodes).toContain('WITHIN_SCOPE');
  });

  it('AUDIT-001..008: the consumer must SUPPRESS history, not merely flag verified=false', async () => {
    for (let n = 1; n <= 8; n++) {
      const id = `AUDIT-00${n}`;
      const o = await observe(id);
      expect(o.invariants, id).toMatchObject({ consumerHistoryVerified: false, consumerHistoryEmpty: true, controlConsumerHistoryVerified: true });
      expect(INVARIANT_CHECKS[id]!({ ...o, invariants: { ...o.invariants, consumerHistoryEmpty: false } }).ok, id).toBe(false);
    }
  });

  it('typed transport cause is pinned for the SSRF scenarios (DID-Core / transport errors, not just "some error")', async () => {
    for (const id of ['DIDWEB-002', 'DIDWEB-003', 'DIDWEB-004', 'DIDWEB-005']) {
      const o = await observe(id);
      expect(o.invariants.transportErrorCode, id).toBe('POLICY');
      expect(INVARIANT_CHECKS[id]!({ ...o, invariants: { ...o.invariants, transportErrorCode: 'NETWORK' } }).ok, id).toBe(false);
    }
    for (const [id, err] of [['DIDWEB-001', 'invalidDid'], ['DIDWEB-006', 'internalError'], ['DIDWEB-007', 'internalError'], ['DIDWEB-008', 'invalidDid'], ['DIDWEB-009', 'invalidDid']] as const) {
      const o = await observe(id);
      expect(o.invariants.resolutionError, id).toBe(err);
      expect(INVARIANT_CHECKS[id]!({ ...o, invariants: { ...o.invariants, resolutionError: 'notFound' } }).ok, id).toBe(false);
    }
  });
});

describe('STATUS-003 reaches BOTH verifier quarantine stages independently (final audit finding)', () => {
  it('records a passing control and a quarantine denial from each stage', async () => {
    const o = await observe('STATUS-003');
    expect(o.invariants).toMatchObject({
      verifierControlBeforeQuarantine: ['ACCEPTED'],
      verifiedSubjectStageReasons: ['AGENT_QUARANTINED'],
      earlyActorStageReasons: ['AGENT_QUARANTINED'],
    });
  });

  it('NEGATIVE CONTROL: if either stage stopped denying (accepting, or the WRONG_SUBJECT precedence change), STATUS-003 FAILS', async () => {
    const o = await observe('STATUS-003');
    const check = INVARIANT_CHECKS['STATUS-003']!;
    expect(check({ ...o, invariants: { ...o.invariants, verifiedSubjectStageReasons: ['ACCEPTED'] } }).ok).toBe(false); // stage 7b removed
    expect(check({ ...o, invariants: { ...o.invariants, earlyActorStageReasons: ['WRONG_SUBJECT'] } }).ok).toBe(false); // stage 2b removed
    expect(check({ ...o, invariants: { ...o.invariants, verifierControlBeforeQuarantine: ['AGENT_QUARANTINED'] } }).ok).toBe(false); // dead control
  });
});

describe('CREDENTIAL-002 pins the verifier kid/issuer binding independently of the resolver (final audit follow-up)', () => {
  it('a permissive resolver that lists the attacker key still cannot make the forged credential acceptable', async () => {
    const o = await observe('CREDENTIAL-002');
    expect(o.invariants).toMatchObject({ permissiveResolverControl: ['ACCEPTED'], permissiveResolverForgedReasons: ['VC_ISSUER_KEY_MISMATCH'] });
    const check = INVARIANT_CHECKS['CREDENTIAL-002']!;
    expect(check({ ...o, invariants: { ...o.invariants, permissiveResolverForgedReasons: ['ACCEPTED'] } }).ok).toBe(false);
    expect(check({ ...o, invariants: { ...o.invariants, permissiveResolverControl: ['VC_SIGNATURE_INVALID'] } }).ok).toBe(false);
  });
});
