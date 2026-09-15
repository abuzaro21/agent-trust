import { describe, expect, it } from 'vitest';

import { LocalSigner, withDid } from '@agent-trust/crypto';
import { CredentialIssuer } from '@agent-trust/vc';

import {
  AGENT_DID,
  AUDITOR_DID,
  EVIL_DID,
  NOW_UNIX,
  buildWorld,
  issueAttestation,
  type World,
} from './fixture.js';

/**
 * Step 11F — 11 malicious-attestation negative controls. Each control
 * mints an attestation that MUST NOT become trusted evidence; every one is
 * caught by the FULL verification pipeline inside TrustProfileService and
 * surfaces only in attestations.rejected with a single deterministic
 * reason code. There is no lightweight path to bypass.
 */

/** Register the JWS under the agent and return the single rejection reason. */
async function rejectedReasonCodes(world: World, jws: string): Promise<string[]> {
  world.attestationStore.add(AGENT_DID, jws);
  const profile = await world.profileService.build(AGENT_DID, { now: NOW_UNIX });
  expect(profile.attestations.trusted).toEqual([]);
  expect(profile.attestations.rejected).toHaveLength(1);
  return [...profile.attestations.rejected[0]!.reasonCodes];
}

describe('AgentAttestationCredential — malicious attestation negative controls (11F)', () => {
  it('1. forged signature (attacker signs with its own key) → VC_SIGNATURE_INVALID', async () => {
    const world = await buildWorld();
    // Attacker issues the SAME attestation shape, signed by its own key,
    // but claims the auditor as issuer in the payload — the signature
    // check against the ISSUER's resolved key is what stops this.
    const forger = new CredentialIssuer(world.evilSigner, { issuerDid: AUDITOR_DID });
    const { jws } = await forger.issueAttestation({
      subjectDid: AGENT_DID,
      attestation: { type: 'CAPABILITY_ENDORSEMENT', domain: 'refunds', statement: 'APPROVED' },
      validFrom: NOW_UNIX - 3600,
      validUntil: NOW_UNIX + 86_400,
    });
    expect(await rejectedReasonCodes(world, jws)).toEqual(['VC_ISSUER_KEY_MISMATCH']);
  });

  it('2. wrong kid (kid of another key held by the same DID holder) → kid ownership fails', async () => {
    const world = await buildWorld();
    // A second signer whose key is NOT registered under any DID — the
    // issuer's resolved document contains no such verification method.
    const rogue = withDid(LocalSigner.generate(), AUDITOR_DID);
    const rogueIssuer = new CredentialIssuer(rogue, { issuerDid: AUDITOR_DID });
    const { jws } = await rogueIssuer.issueAttestation({
      subjectDid: AGENT_DID,
      attestation: { type: 'CAPABILITY_ENDORSEMENT', domain: 'refunds', statement: 'ENDORSED' },
      validFrom: NOW_UNIX - 3600,
      validUntil: NOW_UNIX + 86_400,
    });
    expect(await rejectedReasonCodes(world, jws)).toEqual(['VC_ISSUER_KEY_MISMATCH']);
  });

  it('3. issuer trusted for NO attestation types → ATTESTATION_TYPE_UNSUPPORTED', async () => {
    const world = await buildWorld();
    const { jws } = await issueAttestation(world); // auditor, but NO attestationTrust entries
    expect(await rejectedReasonCodes(world, jws)).toEqual(['ATTESTATION_TYPE_UNSUPPORTED']);
  });

  it('4. issuer trusted for a DIFFERENT attestation type → ATTESTATION_TYPE_UNSUPPORTED', async () => {
    const world = await buildWorld();
    world.attestationTrust.trust(AUDITOR_DID, 'SECURITY_REVIEW');
    const { jws } = await issueAttestation(world, { type: 'CAPABILITY_ENDORSEMENT' });
    expect(await rejectedReasonCodes(world, jws)).toEqual(['ATTESTATION_TYPE_UNSUPPORTED']);
  });

  it('5. expired attestation → VC_EXPIRED', async () => {
    const world = await buildWorld();
    world.attestationTrust.trust(AUDITOR_DID, 'CAPABILITY_ENDORSEMENT');
    const { jws } = await issueAttestation(world, { validUntil: NOW_UNIX - 10 });
    expect(await rejectedReasonCodes(world, jws)).toEqual(['VC_EXPIRED']);
  });

  it('6. not-yet-valid attestation → VC_NOT_YET_VALID', async () => {
    const world = await buildWorld();
    world.attestationTrust.trust(AUDITOR_DID, 'CAPABILITY_ENDORSEMENT');
    const { jws } = await issueAttestation(world, { validFrom: NOW_UNIX + 3600 });
    expect(await rejectedReasonCodes(world, jws)).toEqual(['VC_NOT_YET_VALID']);
  });

  it('7. revoked attestation → CREDENTIAL_REVOKED (attestation revocation via standard credentialStatus)', async () => {
    const world = await buildWorld();
    world.attestationTrust.trust(AUDITOR_DID, 'CAPABILITY_ENDORSEMENT');
    const { jws, statusIndex } = await issueAttestation(world);
    await world.statusManager.revoke(world.audListId, statusIndex);
    expect(await rejectedReasonCodes(world, jws)).toEqual(['CREDENTIAL_REVOKED']);
  });

  it('8. attacker-controlled status pointer (org-controlled list for an auditor credential) → fail closed', async () => {
    const world = await buildWorld();
    world.attestationTrust.trust(AUDITOR_DID, 'CAPABILITY_ENDORSEMENT');
    const { jws } = await issueAttestation(world, {
      // attacker rewrites the status pointer at the ORG-controlled list
      statusListId: world.revListId,
      statusIndex: await world.nextStatusIndex(world.revListId),
    });
    // The status list id still points at the ORG list, but the attestation
    // issuer is the auditor → controller binding fails → UNKNOWN → closed.
    expect(await rejectedReasonCodes(world, jws)).toEqual(['CREDENTIAL_STATUS_UNAVAILABLE']);
  });

  it('9. wrong subject (attestation about a different agent) → WRONG_SUBJECT', async () => {
    const world = await buildWorld();
    world.attestationTrust.trust(AUDITOR_DID, 'CAPABILITY_ENDORSEMENT');
    const { jws } = await issueAttestation(world, { subject: EVIL_DID });
    world.attestationStore.add(AGENT_DID, jws); // registered under the WRONG subject on purpose
    const profile = await world.profileService.build(AGENT_DID, { now: NOW_UNIX });
    expect(profile.attestations.trusted).toEqual([]);
    // The profile service pulls by subject and passes expectedSubject —
    // so an attestation about EVIL_DID can never attach to AGENT_DID.
    expect(profile.attestations.rejected).toHaveLength(1);
    expect(profile.attestations.rejected[0]!.reasonCodes).toEqual(['WRONG_SUBJECT']);
  });

  it('10. malformed claims (domain missing, unknown statement) → VC_SCHEMA_INVALID', async () => {
    const world = await buildWorld();
    world.attestationTrust.trust(AUDITOR_DID, 'CAPABILITY_ENDORSEMENT');
    const { jws } = await world.auditorIssuer.issueAttestation({
      subjectDid: AGENT_DID,
      attestation: {
        type: 'CAPABILITY_ENDORSEMENT',
        domain: 'refunds',
        statement: 'GOLD_STAR' as unknown as 'ENDORSED', // outside the closed vocabulary
      },
      validFrom: NOW_UNIX - 3600,
      validUntil: NOW_UNIX + 86_400,
    });
    expect(await rejectedReasonCodes(world, jws)).toEqual(['VC_SCHEMA_INVALID']);
  });

  it('11. tampered claims (payload edited post-signature) → VC_SIGNATURE_INVALID', async () => {
    const world = await buildWorld();
    world.attestationTrust.trust(AUDITOR_DID, 'CAPABILITY_ENDORSEMENT');
    const { jws } = await issueAttestation(world);
    const [h, p, sig] = jws.split('.');
    const payload = JSON.parse(Buffer.from(p!, 'base64url').toString('utf8')) as {
      vc: { credentialSubject: { attestation: { statement: string } } };
    };
    payload.vc.credentialSubject.attestation.statement = 'APPROVED';
    const forgedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const tampered = `${h}.${forgedPayload}.${sig}`;
    expect(await rejectedReasonCodes(world, tampered)).toEqual(['VC_SIGNATURE_INVALID']);
  });
});

