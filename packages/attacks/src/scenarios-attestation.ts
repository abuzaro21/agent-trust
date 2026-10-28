import type { AttackScenario } from './types.js';
import { NOW, buildAttackWorld, issueAttestation, anchorCheckpoint, STREAM } from './world.js';
import { TrustProfileService } from '@agent-trust/trust-profile';
import { CredentialIssuer } from '@agent-trust/vc';

/**
 * Step 13K — Attestation attacks. Core claim under test: vouches are
 * EVIDENCE, never authority. Every scenario checks BOTH the attestation
 * outcome and the victim's unchanged authority.
 */

function profileService(w: Awaited<ReturnType<typeof buildAttackWorld>>, cp: Awaited<ReturnType<typeof anchorCheckpoint>>) {
  return new TrustProfileService({
    didResolver: w.gatewayDeps.didResolver,
    verifier: w.gatewayDeps.verifier,
    attestationStore: w.attestationStore,
    agentCredentialStore: w.agentCredentialStore,
    attestationTrust: w.attestationTrust,
    auditLog: w.auditLog,
    auditCheckpoint: cp,
    auditStreamId: STREAM,
    checkpointSignerDid: 'did:web:trust.example.com:audit',
  });
}

export const ATTEST_001: AttackScenario = {
  id: 'ATTEST-001',
  category: 'ATTESTATION',
  kind: 'ATTACK',
  title: 'Fake vouch from an untrusted issuer (signature may be valid)',
  expected: { verdict: 'REFUSED', outcome: 'attestation rejected; authority unchanged', reasonCode: 'UNTRUSTED_ISSUER' },
  async run() {
    const w = await buildAttackWorld();
    // Control: a vouch from a TRUSTED issuer is accepted in the very same profile, so the rejection of the
    // evil vouch is about its issuer and not about a broken fixture.
    w.attestationTrust.trust('did:web:audit.acme.example:auditor', 'CAPABILITY_ENDORSEMENT');
    const good = await issueAttestation(w);
    w.attestationStore.add('did:web:trust.example.com:agents:support', good.jws);
    const { jws } = await issueAttestation(w, { issuer: 'evil' });
    w.attestationStore.add('did:web:trust.example.com:agents:support', jws);
    // Trust is scoped by issuer AND type: the trusted auditor is NOT trusted for OPERATIONAL_APPROVAL.
    const scoped = await issueAttestation(w, { type: 'OPERATIONAL_APPROVAL' });
    w.attestationStore.add('did:web:trust.example.com:agents:support', scoped.jws);
    w.agentCredentialStore.add('did:web:trust.example.com:agents:support', w.delegationJws);
    const cp = await anchorCheckpoint(w);
    const profile = await profileService(w, cp).build('did:web:trust.example.com:agents:support', { now: NOW });
    return {
      outcome:
        profile.attestations.trusted.length === 1 && profile.attestations.rejected.length === 2
          ? `untrusted-issuer and out-of-scope vouches rejected (${profile.attestations.rejected.flatMap((r) => r.reasonCodes).join(',')}); trusted control accepted; authority unchanged`
          : 'UNEXPECTED trust change',
      verdict: profile.attestations.rejected.length === 2 && profile.attestations.trusted.length === 1 ? 'REFUSED' : 'BREACHED',
      reasonCodes: profile.attestations.rejected.flatMap((r) => r.reasonCodes),
      invariants: {
        victimAuthorityCount: profile.authority.active.length,
        controlTrustedAttestations: profile.attestations.trusted.length,
        rejectedReasons: profile.attestations.rejected.flatMap((r) => r.reasonCodes).sort(),
      },
    };
  },
};

export const ATTEST_002: AttackScenario = {
  id: 'ATTEST-002',
  category: 'ATTESTATION',
  kind: 'ATTACK',
  title: '100 Sybil vouches — count is not trust',
  expected: { verdict: 'CONTAINED', outcome: 'trusted attestations = 0; authority unchanged; policy unchanged', reasonCode: 'AUTHORITY_LIMIT_EXCEEDED' },
  async run() {
    const w = await buildAttackWorld();
    // Grant SOME trust in the world (just not to the Sybils).
    w.attestationTrust.trust('did:web:nobody.example:anchor', 'CAPABILITY_ENDORSEMENT');
    const { LocalSigner, withDid: wd } = await import('@agent-trust/crypto');
    const { didDocumentForJwk } = await import('@agent-trust/did');
    for (let i = 0; i < 100; i++) {
      const did = `did:web:sybil${i}.example:agent`;
      const signer = wd(LocalSigner.generate(), did);
      w.resolverCore.register(didDocumentForJwk(did, await signer.publicKey()));
      const sybilIssuer = new CredentialIssuer(signer, { issuerDid: did });
      const { jws } = await sybilIssuer.issueAttestation({
        subjectDid: 'did:web:trust.example.com:agents:support',
        attestation: { type: 'CAPABILITY_ENDORSEMENT', domain: 'refunds', statement: 'ENDORSED' },
        validFrom: NOW - 3600,
        validUntil: NOW + 86_400,
      });
      w.attestationStore.add('did:web:trust.example.com:agents:support', jws);
    }
    w.agentCredentialStore.add('did:web:trust.example.com:agents:support', w.delegationJws);
    const cp = await anchorCheckpoint(w);
    const profile = await profileService(w, cp).build('did:web:trust.example.com:agents:support', { now: NOW });
    // Policy behavior unchanged: same 5000 SAR request still denies, same
    // 120 SAR request still allows.
    const over = await w.gateway.handleTask(await w.task({ amount: 5000, taskId: 'atk_sybil_over' }));
    return {
      outcome: `trusted=${profile.attestations.trusted.length} rejected=${profile.attestations.rejected.length}; 5000 SAR → ${over.effect}`,
      verdict: profile.attestations.trusted.length === 0 && over.effect === 'DENY' ? 'CONTAINED' : 'BREACHED',
      reasonCodes: over.reasonCodes,
      invariants: {
        policyDeniedOverLimit: over.effect === 'DENY',
        victimAuthorityCount: profile.authority.active.length,
        victimTrustedAttestations: profile.attestations.trusted.length,
        sybilRejected: profile.attestations.rejected.length,
      },
    };
  },
};

export const ATTEST_003: AttackScenario = {
  id: 'ATTEST-003',
  category: 'ATTESTATION',
  kind: 'ATTACK',
  title: 'Trusted attestations but NO delegation credential — gateway must still deny',
  expected: { verdict: 'DENIED', outcome: 'DENY — vouch ≠ authority', reasonCode: 'REQUEST_MALFORMED' },
  async run() {
    const w = await buildAttackWorld();
    w.attestationTrust
      .trust('did:web:audit.acme.example:auditor', 'CAPABILITY_ENDORSEMENT')
      .trust('did:web:audit.acme.example:auditor', 'OPERATIONAL_APPROVAL');
    const a1 = await issueAttestation(w);
    const a2 = await issueAttestation(w, { type: 'OPERATIONAL_APPROVAL' });
    w.attestationStore.add('did:web:trust.example.com:agents:support', a1.jws);
    w.attestationStore.add('did:web:trust.example.com:agents:support', a2.jws);
    // Present ONLY attestation credentials — no delegation exists.
    const result = await w.gateway.handleTask(await w.task({ taskId: 'atk_vouch_noauth', credentials: [a1.jws, a2.jws] }));
    const cp = await anchorCheckpoint(w);
    const profile = await profileService(w, cp).build('did:web:trust.example.com:agents:support', { now: NOW });
    return {
      outcome: `gateway=${result.effect} with ${profile.attestations.trusted.length} trusted attestations and NO delegation`,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, victimTrustedAttestations: profile.attestations.trusted.length },
    };
  },
};

export const ATTEST_004: AttackScenario = {
  id: 'ATTEST-004',
  category: 'ATTESTATION',
  kind: 'ATTACK',
  title: 'Revoked attestation disappears from trusted evidence',
  expected: { verdict: 'CONTAINED', outcome: 'revoked vouch leaves the trusted list (standard credentialStatus)', reasonCode: 'CREDENTIAL_REVOKED' },
  async run() {
    const w = await buildAttackWorld();
    w.attestationTrust.trust('did:web:audit.acme.example:auditor', 'CAPABILITY_ENDORSEMENT');
    const before = await issueAttestation(w);
    w.attestationStore.add('did:web:trust.example.com:agents:support', before.jws);
    const cp0 = await anchorCheckpoint(w);
    const p0 = await profileService(w, cp0).build('did:web:trust.example.com:agents:support', { now: NOW });
    const trustedBefore = p0.attestations.trusted.length;
    await w.statusManager.revoke(w.audListId, before.statusIndex);
    const cp1 = await anchorCheckpoint(w);
    const p1 = await profileService(w, cp1).build('did:web:trust.example.com:agents:support', { now: NOW });
    return {
      outcome: trustedBefore === 1 && p1.attestations.trusted.length === 0
        ? `trusted ${trustedBefore} → ${p1.attestations.trusted.length} after revocation (${p1.attestations.rejected[0]?.reasonCodes.join(',')})`
        : 'UNEXPECTED',
      verdict: trustedBefore === 1 && p1.attestations.trusted.length === 0 ? 'CONTAINED' : 'BREACHED',
      reasonCodes: p1.attestations.rejected[0]?.reasonCodes ?? [],
      invariants: { trustedBefore, victimTrustedAttestations: p1.attestations.trusted.length },
    };
  },
};

export const ATTEST_005: AttackScenario = {
  id: 'ATTEST-005',
  category: 'ATTESTATION',
  kind: 'ATTACK',
  title: 'Attestation for the wrong subject cannot attach to the victim',
  expected: { verdict: 'REFUSED', outcome: 'WRONG_SUBJECT — rejected, victim unaffected', reasonCode: 'WRONG_SUBJECT' },
  async run() {
    const w = await buildAttackWorld();
    w.attestationTrust.trust('did:web:audit.acme.example:auditor', 'CAPABILITY_ENDORSEMENT');
    // Control: a correctly addressed vouch from the same trusted issuer is accepted in the same profile.
    const good = await issueAttestation(w);
    w.attestationStore.add('did:web:trust.example.com:agents:support', good.jws);
    const { jws } = await issueAttestation(w, { subject: 'did:web:evil.example:agent' });
    w.attestationStore.add('did:web:trust.example.com:agents:support', jws);
    const cp = await anchorCheckpoint(w);
    const profile = await profileService(w, cp).build('did:web:trust.example.com:agents:support', { now: NOW });
    return {
      outcome:
        profile.attestations.trusted.length === 1 && profile.attestations.rejected.length === 1
          ? `wrong-subject vouch rejected (${profile.attestations.rejected[0]?.reasonCodes.join(',')}); correctly addressed control accepted`
          : 'UNEXPECTED',
      verdict: profile.attestations.trusted.length === 1 && profile.attestations.rejected.length === 1 ? 'REFUSED' : 'BREACHED',
      reasonCodes: profile.attestations.rejected[0]?.reasonCodes ?? [],
      invariants: { controlTrustedAttestations: profile.attestations.trusted.length, wrongSubjectRejected: profile.attestations.rejected.length },
    };
  },
};

export const ATTEST_SCENARIOS = [ATTEST_001, ATTEST_002, ATTEST_003, ATTEST_004, ATTEST_005];
