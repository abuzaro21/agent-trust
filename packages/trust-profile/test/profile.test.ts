import { describe, expect, it } from 'vitest';

import { LocalSigner, withDid, canonicalJson } from '@agent-trust/crypto';
import { CredentialIssuer } from '@agent-trust/vc';
import { didDocumentForJwk } from '@agent-trust/did';

import { createTaskRequest } from '../../gateway/src/request.js';
import { TrustProfileService } from '../src/index.js';

import {
  AGENT_DID,
  ANCHOR_DID,
  AUDITOR_DID,
  EVIL_DID,
  NOW_UNIX,
  ORG_DID,
  REFUND_AGENT_DID,
  buildWorld,
  issueAttestation,
  issueDelegation,
  type World,
} from './fixture.js';

/**
 * Step 11E2 — the 15 mandatory TrustProfile behaviors. Every case states
 * what evidence the profile must surface, what it must refuse to surface,
 * and (where relevant) that the profile is a REPORT — it never feeds the
 * policy engine and never creates authority. Each test builds its OWN
 * world: profile reads must never depend on unrelated mutations.
 */

describe('TrustProfileService — mandatory profile cases (11E2)', () => {
  it('1. resolves identity: resolved=true with verification method count and canonical timestamp', async () => {
    const world = await buildWorld();
    const profile = await world.profileService.build(AGENT_DID, { now: NOW_UNIX });
    expect(profile.identity).toEqual({ resolved: true, verificationMethodCount: 1 });
    expect(profile.agent).toEqual({ did: AGENT_DID });
    expect(profile.generatedAt).toBe('2026-09-15T12:00:00Z');
  });

  it('2. unresolved DID → resolved=false, sections stay empty evidence', async () => {
    const world = await buildWorld();
    const profile = await world.profileService.build('did:web:ghost.example:agent', { now: NOW_UNIX });
    expect(profile.identity).toEqual({ resolved: false });
    expect(profile.authority.active).toEqual([]);
    expect(profile.attestations.trusted).toEqual([]);
  });

  it('3. active delegation → one authority entry with evidence digest, no score fields', async () => {
    const world = await buildWorld();
    const { jws } = await issueDelegation(world);
    world.agentCredentialStore.add(AGENT_DID, jws);
    const profile = await world.profileService.build(AGENT_DID, { now: NOW_UNIX });
    expect(profile.authority.active).toHaveLength(1);
    const entry = profile.authority.active[0]!;
    expect(entry.actions).toEqual(['refund:create']);
    expect(entry.issuer).toBe(ORG_DID);
    expect(entry.applicable).toBe(true);
    expect(entry.evidenceDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(profile.credentials.active).toBe(1);
    // Structural no-score proof: the read model has nowhere to put one.
    expect(JSON.stringify(profile)).not.toMatch(/score|rating|stars/i);
  });

  it('4. revoked delegation is removed from active authority and reported as revoked', async () => {
    const world = await buildWorld();
    const { jws, statusIndex } = await issueDelegation(world);
    world.agentCredentialStore.add(AGENT_DID, jws);
    await world.statusManager.revoke(world.revListId, statusIndex);
    const profile = await world.profileService.build(AGENT_DID, { now: NOW_UNIX });
    expect(profile.authority.active).toEqual([]);
    expect(profile.credentials.revoked).toBe(1);
    expect(profile.credentials.active).toBe(0);
  });

  it('5. expired delegation is not active authority', async () => {
    const world = await buildWorld();
    const { jws } = await issueDelegation(world, { validUntil: NOW_UNIX - 10 });
    world.agentCredentialStore.add(AGENT_DID, jws);
    const profile = await world.profileService.build(AGENT_DID, { now: NOW_UNIX });
    expect(profile.authority.active).toEqual([]);
  });

  it('6. context filtering marks non-matching authority applicable=false (presentation only)', async () => {
    const world = await buildWorld();
    const { jws } = await issueDelegation(world, { actions: ['refund:create'] });
    world.agentCredentialStore.add(AGENT_DID, jws);
    const profile = await world.profileService.build(AGENT_DID, {
      now: NOW_UNIX,
      context: { action: 'user:delete', resource: 'order:ORD-918' },
    });
    expect(profile.context).toEqual({ action: 'user:delete', resource: 'order:ORD-918' });
    expect(profile.authority.active).toHaveLength(1);
    expect(profile.authority.active[0]!.applicable).toBe(false);
  });

  it('7. trusted attestation appears in attestations.trusted with typed fields', async () => {
    const world = await buildWorld();
    world.attestationTrust.trust(AUDITOR_DID, 'CAPABILITY_ENDORSEMENT');
    const { jws } = await issueAttestation(world);
    world.attestationStore.add(AGENT_DID, jws);
    const profile = await world.profileService.build(AGENT_DID, { now: NOW_UNIX });
    expect(profile.attestations.trusted).toHaveLength(1);
    const att = profile.attestations.trusted[0]!;
    expect(att.issuer).toBe(AUDITOR_DID);
    expect(att.type).toBe('CAPABILITY_ENDORSEMENT');
    expect(att.statement).toBe('ENDORSED');
    expect(att.domain).toBe('refunds');
    expect(profile.attestations.rejected).toEqual([]);
  });

  it('8. trust is scoped by issuer+TYPE: wrong-type trust still rejects (ATTESTATION_TYPE_UNSUPPORTED)', async () => {
    const world = await buildWorld();
    // trusted for SECURITY_REVIEW only — CAPABILITY_ENDORSEMENT is not
    world.attestationTrust.trust(AUDITOR_DID, 'SECURITY_REVIEW');
    const { jws } = await issueAttestation(world);
    world.attestationStore.add(AGENT_DID, jws);
    const profile = await world.profileService.build(AGENT_DID, { now: NOW_UNIX });
    expect(profile.attestations.trusted).toEqual([]);
    expect(profile.attestations.rejected).toHaveLength(1);
    expect(profile.attestations.rejected[0]!.issuer).toBe(AUDITOR_DID);
    expect(profile.attestations.rejected[0]!.reasonCodes).toEqual(['ATTESTATION_TYPE_UNSUPPORTED']);
  });

  it('9. revoked attestation disappears (standard credentialStatus, full pipeline)', async () => {
    const world = await buildWorld();
    world.attestationTrust.trust(AUDITOR_DID, 'CAPABILITY_ENDORSEMENT');
    const { jws, statusIndex } = await issueAttestation(world);
    world.attestationStore.add(AGENT_DID, jws);
    await world.statusManager.revoke(world.audListId, statusIndex);
    const profile = await world.profileService.build(AGENT_DID, { now: NOW_UNIX });
    expect(profile.attestations.trusted).toEqual([]);
    expect(profile.attestations.rejected).toEqual([{ reasonCodes: ['CREDENTIAL_REVOKED'] }]);
  });

  it('10. attestation cannot create authority: profile with ONLY attestations has zero authority', async () => {
    const world = await buildWorld();
    world.attestationTrust.trust(AUDITOR_DID, 'CAPABILITY_ENDORSEMENT').trust(AUDITOR_DID, 'OPERATIONAL_APPROVAL');
    const a1 = await issueAttestation(world, { type: 'CAPABILITY_ENDORSEMENT', statement: 'APPROVED' });
    const a2 = await issueAttestation(world, { type: 'OPERATIONAL_APPROVAL', statement: 'APPROVED' });
    world.attestationStore.add(AGENT_DID, a1.jws);
    world.attestationStore.add(AGENT_DID, a2.jws);
    const profile = await world.profileService.build(AGENT_DID, { now: NOW_UNIX });
    // Two trusted attestations — and STILL no authority, no applicable evidence.
    expect(profile.attestations.trusted).toHaveLength(2);
    expect(profile.authority.active).toEqual([]);
    expect(profile.credentials.active).toBe(2); // attestation credentials are active credentials, NOT authority
  });

  it('11. Sybil resistance: 100 vouches for an agent → 0 trusted, 100 rejected', async () => {
    const world = await buildWorld();
    world.attestationTrust.trust('did:web:nobody.example:anchor', 'CAPABILITY_ENDORSEMENT'); // trust exists in the world, just not for Sybils
    for (let i = 0; i < 100; i++) {
      const did = `did:web:sybil${i}.example:agent`;
      const signer = withDid(LocalSigner.generate(), did);
      world.resolverCore.register(didDocumentForJwk(did, await signer.publicKey()));
      const sybilIssuer = new CredentialIssuer(signer, { issuerDid: did });
      const { jws } = await sybilIssuer.issueAttestation({
        subjectDid: AGENT_DID,
        attestation: { type: 'CAPABILITY_ENDORSEMENT', domain: 'refunds', statement: 'ENDORSED' },
        validFrom: NOW_UNIX - 3600,
        validUntil: NOW_UNIX + 86_400,
      });
      world.attestationStore.add(AGENT_DID, jws);
    }
    const profile = await world.profileService.build(AGENT_DID, { now: NOW_UNIX });
    expect(profile.attestations.trusted).toEqual([]);
    expect(profile.attestations.rejected).toHaveLength(100);
    // No aggregate number a Sybil army could inflate exists anywhere:
    expect(Object.keys(profile.attestations)).toEqual(['trusted', 'rejected']);
    expect(JSON.stringify(profile)).not.toMatch(/score|rating|stars/i);
  });

  it('12. history aggregates verified receipts: allow/deny/execution counts and reason codes', async () => {
    const h = await buildHistoryWorld();
    const profile = await h.world.profileService.build(AGENT_DID, { now: NOW_UNIX });
    if (!profile.history.integrity.verified) throw new Error('history should verify');
    expect(profile.history.integrity.verifiedThroughSequence).toBe(h.receiptCount);
    expect(profile.history.integrity.checkpointId).toBe('ckpt_profile_0001');
    const entry = profile.history.byAction['refund:create']!;
    expect(entry.decisions.allow).toBe(3);
    expect(entry.decisions.deny).toBe(1);
    expect(entry.execution.succeeded).toBe(2);
    expect(entry.execution.failed).toBe(1);
    expect(entry.reasonCodes['AUTHORITY_LIMIT_EXCEEDED']).toBe(1);
    expect(entry.lastObservedAt).toBe('2026-09-15T12:00:00Z');
  });

  it('13. spoofed actor cannot pollute the victim history (attribution regression)', async () => {
    const h = await buildHistoryWorld();
    // Evil signs with its OWN key but claims the victim's DID.
    const request = await createTaskRequest({
      signer: h.world.evilSigner,
      taskId: 'task_spoof',
      actor: AGENT_DID,
      audience: REFUND_AGENT_DID,
      action: 'refund:create',
      resource: 'order:ORD-918',
      parameters: { amount: 120, currency: 'SAR' },
      credentials: [(await issueDelegation(h.world)).jws],
      now: h.world.clock.now,
    });
    const result = await h.world.gateway.handleTask(request);
    expect(result.effect).toBe('DENY');
    await h.rebindCheckpoint();

    const victimProfile = await h.world.profileService.build(AGENT_DID, { now: NOW_UNIX });
    // exactly the baseline: the spoof attempt adds NOTHING to the victim
    expect(victimProfile.history.byAction['refund:create']!.decisions).toEqual({ allow: 3, deny: 1 });
    const attackerProfile = await h.world.profileService.build(EVIL_DID, { now: NOW_UNIX });
    expect(attackerProfile.history.byAction).toEqual({});
  });

  it('14. tampered chain → history section fails closed, other sections unaffected', async () => {
    const h = await buildHistoryWorld();
    // Full-database attacker: serve a chain where one receipt body was
    // rewritten (amount 120 → 1) while its stored eventHash stayed put.
    const receipts = await h.world.auditLog.readStream('acme-demo');
    const tampered = structuredClone(receipts);
    (tampered[0]!.body.request as { parameters?: { amount?: number } }).parameters = { amount: 1 };
    const stubLog = {
      append: async () => {
        throw new Error('not used');
      },
      readStream: async () => tampered,
      getHead: async () => null,
    };
    const { TrustProfileService } = await import('../src/index.js');
    const svc = new TrustProfileService({
      didResolver: h.world.resolver,
      verifier: h.world.verifier,
      attestationStore: h.world.attestationStore,
      agentCredentialStore: h.world.agentCredentialStore,
      attestationTrust: h.world.attestationTrust,
      auditLog: stubLog,
      auditCheckpoint: h.world.checkpoint,
      auditStreamId: 'acme-demo',
      checkpointSignerDid: ANCHOR_DID,
    });
    const profile = await svc.build(AGENT_DID, { now: NOW_UNIX });
    expect(profile.history.integrity.verified).toBe(false);
    expect(profile.history.byAction).toEqual({});
    // identity/authority/attestations are independent evidence sections
    expect(profile.identity.resolved).toBe(true);
  });

  it('15. truncation against a signed checkpoint → history fails closed; profile is deterministic', async () => {
    const h = await buildHistoryWorld();
    const receipts = await h.world.auditLog.readStream('acme-demo');
    const truncated = receipts.slice(0, -1); // drop the last outcome receipt
    const stubLog = {
      append: async () => {
        throw new Error('not used');
      },
      readStream: async () => truncated,
      getHead: async () =>
        truncated.length > 0
          ? {
              streamId: 'acme-demo',
              sequence: truncated.length,
              headHash: truncated[truncated.length - 1]!.eventHash,
            }
          : null,
    };
    const svc = new TrustProfileService({
      didResolver: h.world.resolver,
      verifier: h.world.verifier,
      attestationStore: h.world.attestationStore,
      agentCredentialStore: h.world.agentCredentialStore,
      attestationTrust: h.world.attestationTrust,
      auditLog: stubLog,
      auditCheckpoint: h.world.checkpoint,
      auditStreamId: 'acme-demo',
      checkpointSignerDid: ANCHOR_DID,
    });
    const profile = await svc.build(AGENT_DID, { now: NOW_UNIX });
    expect(profile.history.integrity.verified).toBe(false);
    expect(profile.history.byAction).toEqual({});

    // Determinism: same evidence + frozen clock → byte-identical profile.
    const a = await h.world.profileService.build(AGENT_DID, { now: NOW_UNIX });
    const b = await h.world.profileService.build(AGENT_DID, { now: NOW_UNIX });
    expect(canonicalJson(a)).toBe(canonicalJson(b));
  });
});

/** World with 4 real gateway receipts for AGENT_DID: 3 ALLOW (2 SUCCEEDED, 1 FAILED), 1 DENY. */
async function buildHistoryWorld() {
  const world = await buildWorld({ failTaskIds: ['task_h4'] });

  async function task(taskId: string, amount: number) {
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
    return world.gateway.handleTask(request);
  }

  await task('task_h1', 120); // ALLOW + SUCCEEDED
  await task('task_h2', 5000); // DENY AUTHORITY_LIMIT_EXCEEDED (executor untouched)
  await task('task_h3', 130); // ALLOW + SUCCEEDED
  await task('task_h4', 140); // ALLOW + FAILED (executor simulates provider rejection)

  const rebindCheckpoint = async (): Promise<void> => {
    world.checkpoint = await world.checkpointService.issue({
      checkpointId: 'ckpt_profile_0001',
      streamId: 'acme-demo',
      receipts: await world.auditLog.readStream('acme-demo'),
      issuedAt: '2026-09-15T12:00:00Z',
    });
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
  };
  await rebindCheckpoint();

  const receipts = await world.auditLog.readStream('acme-demo');
  return { world, receiptCount: receipts.length, rebindCheckpoint };
}

type _W = World;
