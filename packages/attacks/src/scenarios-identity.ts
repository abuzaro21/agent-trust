import type { AttackScenario } from './types.js';
import { NOW, buildAttackWorld, issueAttestation, anchorCheckpoint } from './world.js';
import { LocalSigner, withDid } from '@agent-trust/crypto';
import { CredentialIssuer, CredentialVerifier, signCompactJws } from '@agent-trust/vc';
import { BitstringStatusChecker } from '@agent-trust/status';
import { TrustProfileService } from '@agent-trust/trust-profile';

/**
 * Step 13D — Identity attacks. The invariant pattern: deny early, prove
 * the policy and executor never ran, prove the victim's history and
 * profile are untouched.
 */

export const IDENTITY_001: AttackScenario = {
  id: 'IDENTITY-001',
  category: 'IDENTITY',
  kind: 'ATTACK',
  title: 'Spoofed agent: EvilAgent claims SupportAgent DID, signs with its own key',
  expected: { verdict: 'DENIED', outcome: 'DENY at identity stage, before policy', reasonCode: 'IDENTITY_PROOF_INVALID' },
  async run() {
    const w = await buildAttackWorld();
    const receiptsBefore = (await w.auditLog.readStream('attack-demo')).filter((r) => r.body.actor.did === 'did:web:trust.example.com:agents:support').length;
    const result = await w.gateway.handleTask(await w.task({ signer: w.evilSigner, taskId: 'atk_spoof' }));
    const receiptsAfter = (await w.auditLog.readStream('attack-demo')).filter((r) => r.body.actor.did === 'did:web:trust.example.com:agents:support').length;
    // Victim profile unchanged (Step 13N): profile history identical.
    const cp = await anchorCheckpoint(w, 'ckpt_spoof');
    const profile = await new TrustProfileService({
      didResolver: w.gatewayDeps.didResolver,
      verifier: w.gatewayDeps.verifier,
      attestationStore: w.attestationStore,
      agentCredentialStore: w.agentCredentialStore,
      attestationTrust: w.attestationTrust,
      auditLog: w.auditLog,
      auditCheckpoint: cp,
      auditStreamId: 'attack-demo',
      checkpointSignerDid: ANCHOR,
    }).build('did:web:trust.example.com:agents:support', { now: NOW });
    return {
      outcome: result.effect === 'DENY' ? `DENY (stage identity=${result.stages.identity})` : result.outcome,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: {
        executorCalls: w.executor.callCount.total,
        policyCalls: w.policyCalls.n,
        victimReceiptsAdded: receiptsAfter - receiptsBefore,
        victimHistoryDecisions: profile.history.byAction['refund:create']?.decisions ?? { allow: 0, deny: 0 },
      },
    };
  },
};

const ANCHOR = 'did:web:trust.example.com:audit';

export const IDENTITY_002: AttackScenario = {
  id: 'IDENTITY-002',
  category: 'IDENTITY',
  kind: 'ATTACK',
  title: 'Wrong kid: valid proof references a verification method owned by another DID',
  expected: { verdict: 'DENIED', outcome: 'DENY at identity stage', reasonCode: 'IDENTITY_PROOF_INVALID' },
  async run() {
    const w = await buildAttackWorld();
    const request = await w.task({ taskId: 'atk_wrongkid' });
    // Point the proof's kid at the EVIL agent's key — a different DID.
    const evil = new CredentialIssuer(w.evilSigner, { issuerDid: 'did:web:evil.example:agent' });
    void evil;
    const evilJwk = await w.evilSigner.publicKey();
    const { jwkThumbprint } = await import('@agent-trust/crypto');
    (request as { proof: { kid: string } }).proof.kid = `did:web:evil.example:agent#${jwkThumbprint(evilJwk)}`;
    const result = await w.gateway.handleTask(request);
    return {
      outcome: result.effect === 'DENY' ? `DENY (stage identity=${result.stages.identity})` : result.outcome,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n },
    };
  },
};

export const IDENTITY_003: AttackScenario = {
  id: 'IDENTITY-003',
  category: 'IDENTITY',
  kind: 'ATTACK',
  title: 'Signed-body tamper: 120 SAR signed, 5000 SAR on the wire',
  expected: { verdict: 'DENIED', outcome: 'DENY at identity stage — policy never sees attacker values', reasonCode: 'IDENTITY_PROOF_INVALID' },
  async run() {
    const w = await buildAttackWorld();
    const request = await w.task({ amount: 120, taskId: 'atk_tamper' });
    (request as { parameters: { amount: number } }).parameters.amount = 5000;
    const result = await w.gateway.handleTask(request);
    return {
      outcome: result.effect === 'DENY' ? `DENY (stage identity=${result.stages.identity})` : result.outcome,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n },
    };
  },
};

export const IDENTITY_004: AttackScenario = {
  id: 'IDENTITY-004',
  category: 'IDENTITY',
  kind: 'ATTACK',
  title: 'Wrong audience: a correctly-signed proof aimed at a different service',
  expected: { verdict: 'DENIED', outcome: 'DENY at policy (audience scope)', reasonCode: 'AUDIENCE_MISMATCH' },
  async run() {
    const w = await buildAttackWorld();
    // Properly SIGNED for a different audience — identity is valid, the
    // delegation's audience scope denies. (Editing audience AFTER signing
    // would fail at PoP first — that is IDENTITY-003's tamper proof.)
    const evilAudienceRequest = await w.task({ taskId: 'atk_audience', audience: 'did:web:evil.example:agent' });
    const result = await w.gateway.handleTask(evilAudienceRequest);
    // Positive control: the SAME agent, the LEGITIMATE audience still works.
    const legit = await w.gateway.handleTask(await w.task({ taskId: 'atk_audience_ok' }));
    return {
      outcome: result.effect === 'DENY' ? `DENY at policy (stage=${result.stages.policy}); positive control: ${legit.outcome}` : result.outcome,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: {
        // The ATTACKER caused zero executions; only the positive control ran.
        executorCalls: w.executor.callCount.total - (legit.outcome === 'AUTHORIZED' ? 1 : 0),
        positiveControlAuthorized: legit.outcome === 'AUTHORIZED',
      },
    };
  },
};

export const IDENTITY_SCENARIOS = [IDENTITY_001, IDENTITY_002, IDENTITY_003, IDENTITY_004];

// ------------------------------------------------------------- credentials

export const CREDENTIAL_001: AttackScenario = {
  id: 'CREDENTIAL-001',
  category: 'CREDENTIAL',
  kind: 'ATTACK',
  title: 'Tampered VC: payload edited after signing',
  expected: { verdict: 'DENIED', outcome: 'DENY at credential stage', reasonCode: 'VC_SIGNATURE_INVALID' },
  async run() {
    const w = await buildAttackWorld();
    // Tamper the VC FIRST (payload edited after signing), THEN sign the
    // task over the tampered credential — the task signature stays valid
    // so identity passes and the credential check is what fails.
    const parts = w.delegationJws.split('.');
    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as {
      vc: { credentialSubject: { authority: { limits: { amount: number } } } };
    };
    payload.vc.credentialSubject.authority.limits.amount = 100_000;
    const tamperedJws = `${parts[0]}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${parts[2]}`;
    const request = await w.task({ taskId: 'atk_vctamper', credentials: [tamperedJws] });
    const result = await w.gateway.handleTask(request);
    return {
      outcome: result.effect === 'DENY' ? `DENY (stage credential=${result.stages.credential})` : result.outcome,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n },
    };
  },
};

export const CREDENTIAL_002: AttackScenario = {
  id: 'CREDENTIAL-002',
  category: 'CREDENTIAL',
  kind: 'ATTACK',
  title: 'Wrong issuer key: VC signed by a key the issuer DID does not own',
  expected: { verdict: 'DENIED', outcome: 'DENY — signature/issuer binding fails', reasonCode: 'VC_ISSUER_KEY_MISMATCH' },
  async run() {
    const w = await buildAttackWorld();
    // Evil mints a delegation CLAIMING the org as issuer but signing with
    // its own key — the kid does not resolve inside the org's document.
    const forgedIssuer = new CredentialIssuer(w.evilSigner, { issuerDid: 'did:web:trust.example.com:org' });
    const { jws } = await forgedIssuer.issueDelegation({
      subjectDid: 'did:web:trust.example.com:agents:support',
      authority: { actions: ['refund:create'], resources: ['order:*'], audience: ['did:web:trust.example.com:agents:refund'], limits: { amount: 999_999, currency: 'SAR' }, delegationDepth: 0 },
      validFrom: NOW - 3600,
      validUntil: NOW + 86_400,
    });
    const result = await w.gateway.handleTask(await w.task({ taskId: 'atk_wrongkey', credentials: [jws] }));

    // Defence in depth: the verifier binds the signing kid to the claimed issuer ITSELF, not only through the resolver.
    // A buggy or permissive resolver whose issuer document wrongly lists the attacker's key must still not make the
    // forged credential acceptable. (The real resolvers reject such a document; this isolates the verifier's own check.)
    const ORG = 'did:web:trust.example.com:org';
    const evilKid = await w.evilSigner.keyId();
    const evilJwk = await w.evilSigner.publicKey();
    const real = w.gatewayDeps.didResolver;
    const permissive = {
      supports: (d: string) => real.supports(d),
      resolve: async (d: string) => {
        const r = await real.resolve(d);
        if (d !== ORG || r.didDocument === null) return r;
        const extra = { id: evilKid, type: 'JsonWebKey2020', controller: ORG, publicKeyJwk: evilJwk };
        return { ...r, didDocument: { ...r.didDocument, verificationMethod: [...(r.didDocument.verificationMethod ?? []), extra] } };
      },
    };
    const lenient = new CredentialVerifier({ didResolver: permissive, trustStore: w.trustStore, statusChecker: new BitstringStatusChecker({ kind: 'store', store: w.statusStore }) });
    const codes = (v: { valid: boolean; reasonCodes?: string[] }): string[] => (v.valid ? ['ACCEPTED'] : (v.reasonCodes ?? []));
    const permissiveControl = await lenient.verify(w.delegationJws, { now: NOW });
    // The issuer library stamps the CLAIMED issuer's DID into the kid, so hand-craft the header: same claims, but the JWS
    // names the attacker's own kid. Only the verifier's own kid/issuer comparison stands between this and acceptance.
    const claims = JSON.parse(Buffer.from(jws.split('.')[1]!, 'base64url').toString('utf8')) as Record<string, unknown>;
    const handCrafted = await signCompactJws(w.evilSigner, claims);
    const permissiveForged = await lenient.verify(handCrafted, { now: NOW });
    return {
      outcome: result.effect === 'DENY' ? `DENY (stage credential=${result.stages.credential})` : result.outcome,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: {
        executorCalls: w.executor.callCount.total,
        policyCalls: w.policyCalls.n,
        permissiveResolverControl: codes(permissiveControl),
        permissiveResolverForgedReasons: codes(permissiveForged),
      },
    };
  },
};

export const CREDENTIAL_003: AttackScenario = {
  id: 'CREDENTIAL-003',
  category: 'CREDENTIAL',
  kind: 'ATTACK',
  title: 'Valid signature, untrusted issuer (crypto-valid ≠ trusted)',
  expected: { verdict: 'DENIED', outcome: 'DENY — issuer trust is a separate decision', reasonCode: 'UNTRUSTED_ISSUER' },
  async run() {
    const w = await buildAttackWorld();
    // Evil signs its own well-formed delegation under its OWN did:web
    // identity, which is not in the issuer-trust registry at all.
    const selfIssuer = new CredentialIssuer(w.evilSigner, { issuerDid: 'did:web:evil.example:agent' });
    const { jws } = await selfIssuer.issueDelegation({
      subjectDid: 'did:web:trust.example.com:agents:support',
      authority: { actions: ['refund:create'], resources: ['order:*'], audience: ['did:web:trust.example.com:agents:refund'], limits: { amount: 999_999, currency: 'SAR' }, delegationDepth: 0 },
      validFrom: NOW - 3600,
      validUntil: NOW + 86_400,
    });
    const result = await w.gateway.handleTask(await w.task({ taskId: 'atk_untrusted', credentials: [jws] }));
    return {
      outcome: result.effect === 'DENY' ? `DENY (stage credential=${result.stages.credential})` : result.outcome,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n },
    };
  },
};

export const CREDENTIAL_004: AttackScenario = {
  id: 'CREDENTIAL-004',
  category: 'CREDENTIAL',
  kind: 'ATTACK',
  title: 'Expired credential',
  expected: { verdict: 'DENIED', outcome: 'DENY', reasonCode: 'VC_EXPIRED' },
  async run() {
    const w = await buildAttackWorld();
    const index = await w.nextRevIndex();
    const { jws } = await w.issuer.issueDelegation({
      subjectDid: 'did:web:trust.example.com:agents:support',
      authority: { actions: ['refund:create'], resources: ['order:*'], audience: ['did:web:trust.example.com:agents:refund'], limits: { amount: 500, currency: 'SAR' }, delegationDepth: 0 },
      validFrom: NOW - 7200,
      validUntil: NOW - 60,
      credentialStatus: {
        id: `${w.revListId}#${index}`, type: 'BitstringStatusListEntry', statusPurpose: 'revocation',
        statusListIndex: String(index), statusListCredential: w.revListId,
      },
    });
    const result = await w.gateway.handleTask(await w.task({ taskId: 'atk_expired', credentials: [jws] }));
    return {
      outcome: result.effect === 'DENY' ? `DENY (stage credential=${result.stages.credential})` : result.outcome,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n },
    };
  },
};

export const CREDENTIAL_005: AttackScenario = {
  id: 'CREDENTIAL-005',
  category: 'CREDENTIAL',
  kind: 'ATTACK',
  title: 'Not-yet-valid credential',
  expected: { verdict: 'DENIED', outcome: 'DENY', reasonCode: 'VC_NOT_YET_VALID' },
  async run() {
    const w = await buildAttackWorld();
    const index = await w.nextRevIndex();
    const { jws } = await w.issuer.issueDelegation({
      subjectDid: 'did:web:trust.example.com:agents:support',
      authority: { actions: ['refund:create'], resources: ['order:*'], audience: ['did:web:trust.example.com:agents:refund'], limits: { amount: 500, currency: 'SAR' }, delegationDepth: 0 },
      validFrom: NOW + 3600,
      validUntil: NOW + 86_400,
      credentialStatus: {
        id: `${w.revListId}#${index}`, type: 'BitstringStatusListEntry', statusPurpose: 'revocation',
        statusListIndex: String(index), statusListCredential: w.revListId,
      },
    });
    const result = await w.gateway.handleTask(await w.task({ taskId: 'atk_nfv', credentials: [jws] }));
    return {
      outcome: result.effect === 'DENY' ? `DENY (stage credential=${result.stages.credential})` : result.outcome,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n },
    };
  },
};

export const CREDENTIAL_006: AttackScenario = {
  id: 'CREDENTIAL-006',
  category: 'CREDENTIAL',
  kind: 'ATTACK',
  title: 'Subject mismatch: credential issued for another agent',
  expected: { verdict: 'DENIED', outcome: 'DENY — delegation chain must end at the actor', reasonCode: 'WRONG_SUBJECT' },
  async run() {
    const w = await buildWorldWithOtherSubject();
    // Actor SUPPORT_DID presents a credential whose subject is EVIL_DID.
    const result = await w.gateway.handleTask(
      await w.task({ taskId: 'atk_subject', credentials: [w.evilDelegation] }),
    );
    return {
      outcome: result.effect === 'DENY' ? `DENY (stage authority=${result.stages.authority})` : result.outcome,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n },
    };
  },
};

async function buildWorldWithOtherSubject() {
  const w = await buildAttackWorld();
  const index = await w.nextRevIndex();
  const { jws } = await w.issuer.issueDelegation({
    subjectDid: 'did:web:evil.example:agent', // NOT the actor
    authority: { actions: ['refund:create'], resources: ['order:*'], audience: ['did:web:trust.example.com:agents:refund'], limits: { amount: 500, currency: 'SAR' }, delegationDepth: 0 },
    validFrom: NOW - 3600,
    validUntil: NOW + 86_400,
    credentialStatus: {
      id: `${w.revListId}#${index}`, type: 'BitstringStatusListEntry', statusPurpose: 'revocation',
      statusListIndex: String(index), statusListCredential: w.revListId,
    },
  });
  return { ...w, evilDelegation: jws };
}

// helper re-export used by C6
void issueAttestation;
void withDid;
void LocalSigner;

export const CREDENTIAL_SCENARIOS = [CREDENTIAL_001, CREDENTIAL_002, CREDENTIAL_003, CREDENTIAL_004, CREDENTIAL_005, CREDENTIAL_006];
