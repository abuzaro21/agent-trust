import { describe, expect, it } from 'vitest';
import fc from 'fast-check';

import { createTaskRequest } from '../../gateway/src/request.js';

import {
  AGENT_DID,
  ANCHOR_DID,
  AUDITOR_DID,
  NOW_UNIX,
  REFUND_AGENT_DID,
  buildWorld,
  issueAttestation,
  issueDelegation,
} from './fixture.js';

/**
 * Step 11G — property tests. The load-bearing property: Sybil vouches are
 * MONOTONICALLY NON-INFLUENTIAL. Adding attestation credentials from
 * untrusted issuers never moves any trusted-evidence field of the profile.
 * Plus: context filtering is a pure marker (never removes evidence), and
 * history aggregation is consistent with the receipts it summarized.
 */

describe('TrustProfile property tests (11G)', () => {
  it('P1. Sybil monotonic non-influence: N untrusted vouches change nothing trusted', async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 0, max: 40 }), async (n) => {
        const world = await buildWorld();
        const { jws } = await issueAttestation(world); // auditor attestation, trust granted below
        world.attestationTrust.trust(AUDITOR_DID, 'CAPABILITY_ENDORSEMENT');
        world.attestationStore.add(AGENT_DID, jws);
        const baseline = await world.profileService.build(AGENT_DID, { now: NOW_UNIX });

        for (let i = 0; i < n; i++) {
          const sybilJws = (await issueAttestation(world, { issuer: 'evil' })).jws;
          world.attestationStore.add(AGENT_DID, sybilJws);
        }
        const after = await world.profileService.build(AGENT_DID, { now: NOW_UNIX });

        // The trusted side is IDENTICAL; only the rejected list grew.
        expect(after.attestations.trusted).toEqual(baseline.attestations.trusted);
        expect(after.authority).toEqual(baseline.authority);
        expect(after.attestations.rejected).toHaveLength(n);
      }),
      { numRuns: 12, timeout: 240_000 },
    );
  });

  it('P2. context filtering only flips the applicable marker — evidence is never dropped', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.constantFrom('refund:create', 'user:delete', 'order:read'), { minLength: 0, maxLength: 4 }),
        async (actions) => {
          const world = await buildWorld();
          const seen = new Set<string>();
          for (const action of actions) {
            if (seen.has(action)) continue;
            seen.add(action);
            world.agentCredentialStore.add(AGENT_DID, (await issueDelegation(world, { actions: [action] })).jws);
          }
          const unfiltered = await world.profileService.build(AGENT_DID, { now: NOW_UNIX });
          const filtered = await world.profileService.build(AGENT_DID, {
            now: NOW_UNIX,
            context: { action: 'refund:create' },
          });
          // Same evidence entries in both; only `applicable` may differ.
          expect(filtered.authority.active).toHaveLength(unfiltered.authority.active.length);
          for (let i = 0; i < filtered.authority.active.length; i++) {
            const f = filtered.authority.active[i]!;
            const u = unfiltered.authority.active[i]!;
            expect(f.credentialId).toBe(u.credentialId);
            expect(f.applicable).toBe(u.actions.includes('refund:create'));
          }
        },
      ),
      { numRuns: 10, timeout: 240_000 },
    );
  });

  it('P3. history aggregation: allow+deny counts equal attributed decision receipts', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.nat(2).chain((allow) => fc.nat(2).map((deny) => ({ allow, deny }))),
        async ({ allow, deny }) => {
          const world = await buildWorld();
          let task = 0;
          for (let i = 0; i < allow; i++) {
            await runTask(world, `task_p_a${++task}`, 120);
          }
          for (let i = 0; i < deny; i++) {
            await runTask(world, `task_p_d${++task}`, 5000); // over limit → DENY
          }
          world.checkpoint = await world.checkpointService.issue({
            checkpointId: 'ckpt_prop',
            streamId: 'acme-demo',
            receipts: await world.auditLog.readStream('acme-demo'),
            issuedAt: '2026-09-15T12:00:00Z',
          });
          // The service binds the checkpoint at construction — rebind.
          const { TrustProfileService } = await import('../src/index.js');
          world.profileService = new TrustProfileService({
            didResolver: world.resolver,
            verifier: world.verifier,
            attestationStore: world.attestationStore,
            agentCredentialStore: world.agentCredentialStore,
            attestationTrust: world.attestationTrust,
            auditLog: world.auditLog,
            auditCheckpoint: world.checkpoint,
            auditStreamId: 'acme-demo',
            checkpointSignerDid: ANCHOR_DID,
          });
          const profile = await world.profileService.build(AGENT_DID, { now: NOW_UNIX });
          if (!profile.history.integrity.verified) throw new Error('integrity should hold');
          const entry = profile.history.byAction['refund:create'];
          if (allow + deny === 0) {
            expect(entry).toBeUndefined();
          } else {
            expect(entry!.decisions.allow).toBe(allow);
            expect(entry!.decisions.deny).toBe(deny);
          }
        },
      ),
      { numRuns: 8, timeout: 240_000 },
    );
  });

  it('P4. determinism with injected clock: identical evidence → identical canonical profile', async () => {
    await fc.assert(
      fc.asyncProperty(fc.nat(5), async (vouchCount) => {
        const world = await buildWorld();
        world.attestationTrust.trust(AUDITOR_DID, 'CAPABILITY_ENDORSEMENT');
        for (let i = 0; i < vouchCount; i++) {
          world.attestationStore.add(AGENT_DID, (await issueAttestation(world)).jws);
        }
        world.agentCredentialStore.add(AGENT_DID, (await issueDelegation(world)).jws);
        const a = await world.profileService.build(AGENT_DID, { now: NOW_UNIX });
        const b = await world.profileService.build(AGENT_DID, { now: NOW_UNIX });
        expect(a).toEqual(b);
      }),
      { numRuns: 8, timeout: 240_000 },
    );
  });

  it('R1. gateway regression: trusted attestations + NO delegation credential → still DENY', async () => {
    const world = await buildWorld();
    world.attestationTrust.trust(AUDITOR_DID, 'CAPABILITY_ENDORSEMENT').trust(AUDITOR_DID, 'OPERATIONAL_APPROVAL');
    world.attestationStore.add(AGENT_DID, (await issueAttestation(world)).jws);
    world.attestationStore.add(
      AGENT_DID,
      (await issueAttestation(world, { type: 'OPERATIONAL_APPROVAL', statement: 'APPROVED' })).jws,
    );
    // The request presents ONLY attestation credentials — nothing else exists.
    const attestationJwsList = await world.attestationStore.listForSubject(AGENT_DID);
    expect(attestationJwsList).toHaveLength(2);
    const request = await createTaskRequest({
      signer: world.agentSigner,
      taskId: 'task_attest_no_delegation',
      actor: AGENT_DID,
      audience: REFUND_AGENT_DID,
      action: 'refund:create',
      resource: 'order:ORD-918',
      parameters: { amount: 120, currency: 'SAR' },
      credentials: attestationJwsList,
      now: world.clock.now,
    });
    const result = await world.gateway.handleTask(request);
    expect(result.effect).toBe('DENY');
    expect(world.executor.callCount.total).toBe(0);
  });
});

async function runTask(world: Awaited<ReturnType<typeof buildWorld>>, taskId: string, amount: number): Promise<void> {
  const request = await createTaskRequest({
    signer: world.agentSigner,
    taskId,
    actor: AGENT_DID,
    audience: REFUND_AGENT_DID,
    action: 'refund:create',
    resource: 'order:ORD-918',
    parameters: { amount, currency: 'SAR' },
    credentials: [(await issueDelegation(world)).jws],
    now: world.clock.now,
  });
  await world.gateway.handleTask(request);
}

void ANCHOR_DID;
void NOW_UNIX;
