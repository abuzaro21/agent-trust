import { beforeEach, describe, expect, it } from 'vitest';

import {
  LocalSigner,
  base64urlEncode,
  ecdsaDerToRaw,
  jwkThumbprint,
  utf8,
  withDid,
} from '@agent-trust/crypto';
import { InMemoryDidResolver, didDocumentForJwk } from '@agent-trust/did';
import type { Authority } from '@agent-trust/schemas';

import { CredentialIssuer } from '../src/issue.js';
import { InMemoryIssuerTrustStore } from '../src/trust.js';
import type { CredentialClaims, CredentialVerifier } from '../src/index.js';
import { CredentialVerifier as Verifier } from '../src/verify.js';

const NOW = 1_757_800_000;

const ORG_DID = 'did:web:acme.example:org';
const AGENT_DID = 'did:key:zAgentSubject';
const OTHER_AGENT_DID = 'did:key:zOtherSubject';

const AUTHORITY: Authority = {
  actions: ['refund:create'],
  resources: ['tenant:acme'],
  audience: ['did:web:payments.example:agent'],
  limits: { amount: 500, currency: 'SAR', perDay: 20 },
  delegationDepth: 0,
};

let orgSigner: ReturnType<typeof LocalSigner.generate>;
let resolver: InMemoryDidResolver;
let trustStore: InMemoryIssuerTrustStore;
let issuer: CredentialIssuer;
let verifier: CredentialVerifier;

beforeEach(async () => {
  orgSigner = LocalSigner.generate();
  resolver = new InMemoryDidResolver([
    didDocumentForJwk(ORG_DID, await orgSigner.publicKey()),
  ]);
  trustStore = new InMemoryIssuerTrustStore()
    .trust(ORG_DID, 'AgentMembershipCredential')
    .trust(ORG_DID, 'AgentDelegationCredential');
  issuer = new CredentialIssuer(orgSigner, { issuerDid: ORG_DID });
  verifier = new Verifier({ didResolver: resolver, trustStore });
});

describe('VC issuance + verification (positive)', () => {
  it('issues and verifies a membership credential', async () => {
    const { jws, claims } = await issuer.issueMembership({
      subjectDid: AGENT_DID,
      controller: ORG_DID,
      organization: 'Acme Retail',
      validFrom: NOW - 1000,
      validUntil: NOW + 3600,
    });
    const result = await verifier.verify(jws, { now: NOW });
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    expect(result.facts.subjectDid).toBe(AGENT_DID);
    expect(result.facts.credentialType).toBe('AgentMembershipCredential');
    expect(result.facts.membership?.organization).toBe('Acme Retail');
    expect(result.facts.membership?.controller).toBe(ORG_DID);
    expect(result.claims).toEqual(claims);
  });

  it('issues and verifies a delegation credential with full authority facts', async () => {
    const { jws } = await issuer.issueDelegation({
      subjectDid: AGENT_DID,
      authority: AUTHORITY,
      validFrom: NOW - 1000,
      validUntil: NOW + 3600,
    });
    const result = await verifier.verify(jws, {
      now: NOW,
      expectedSubject: AGENT_DID,
      expectedType: 'AgentDelegationCredential',
    });
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    expect(result.facts.issuerDid).toBe(ORG_DID);
    expect(result.facts.authority).toEqual(AUTHORITY);
  });

  it('verifies with the wall clock by default inside the validity window', async () => {
    const realNow = Math.floor(Date.now() / 1000);
    const { jws } = await issuer.issueMembership({
      subjectDid: AGENT_DID,
      validFrom: realNow - 100,
      validUntil: realNow + 3_600,
    });
    const result = await verifier.verify(jws);
    expect(result.valid).toBe(true);
  });
});

describe('VC negative controls', () => {
  it('rejects tampered claims (forged maxAmount style attack)', async () => {
    const { jws } = await issuer.issueDelegation({
      subjectDid: AGENT_DID,
      authority: { ...AUTHORITY, limits: { amount: 500, currency: 'SAR' } },
      validFrom: NOW - 100,
      validUntil: NOW + 3600,
    });
    // Replace the payload: 500 → 50000, keep header + signature untouched.
    const [h, p, s] = jws.split('.') as [string, string, string];
    const claims = JSON.parse(
      Buffer.from(p, 'base64url').toString('utf8'),
    ) as CredentialClaims;
    const subject = claims.vc.credentialSubject as {
      id: string;
      authority: { limits?: Record<string, unknown> };
    };
    subject.authority.limits = { amount: 50_000, currency: 'SAR' };
    const forgedPayload = base64urlEncode(utf8(JSON.stringify(claims)));
    const result = await verifier.verify(`${h}.${forgedPayload}.${s}`, { now: NOW });
    expect(result).toEqual({ valid: false, reasonCodes: ['VC_SIGNATURE_INVALID'] });
  });

  it('rejects a signature made with the wrong key under a valid kid', async () => {
    const evil = LocalSigner.generate();
    const claims: CredentialClaims = {
      iss: ORG_DID,
      sub: AGENT_DID,
      jti: 'vc_wrong_key_attack',
      nbf: NOW - 100,
      exp: NOW + 3600,
      vc: {
        type: ['VerifiableCredential', 'AgentDelegationCredential'],
        credentialSubject: { id: AGENT_DID, authority: AUTHORITY },
      },
    };
    // kid names the org's REAL method; the signature comes from the evil key.
    const orgKid = `${ORG_DID}#${jwkThumbprint(await orgSigner.publicKey())}`;
    const header = base64urlEncode(
      utf8(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid: orgKid })),
    );
    const payload = base64urlEncode(utf8(JSON.stringify(claims)));
    const signature = base64urlEncode(
      ecdsaDerToRaw(await evil.sign(utf8(`${header}.${payload}`))),
    );
    const result = await verifier.verify(`${header}.${payload}.${signature}`, { now: NOW });
    expect(result).toEqual({ valid: false, reasonCodes: ['VC_SIGNATURE_INVALID'] });
  });

  it('rejects a cryptographically valid credential from an untrusted issuer', async () => {
    trustStore.revoke(ORG_DID, 'AgentDelegationCredential');
    const { jws } = await issuer.issueDelegation({
      subjectDid: AGENT_DID,
      authority: AUTHORITY,
      validFrom: NOW - 100,
      validUntil: NOW + 3600,
    });
    const result = await verifier.verify(jws, { now: NOW });
    expect(result).toEqual({ valid: false, reasonCodes: ['UNTRUSTED_ISSUER'] });
  });

  it('rejects an expired credential', async () => {
    const { jws } = await issuer.issueMembership({
      subjectDid: AGENT_DID,
      validFrom: NOW - 1000,
      validUntil: NOW + 100,
    });
    const result = await verifier.verify(jws, { now: NOW + 101 });
    expect(result).toEqual({ valid: false, reasonCodes: ['VC_EXPIRED'] });
  });

  it('rejects a not-yet-valid credential', async () => {
    const { jws } = await issuer.issueMembership({
      subjectDid: AGENT_DID,
      validFrom: NOW + 1000,
      validUntil: NOW + 3600,
    });
    const result = await verifier.verify(jws, { now: NOW });
    expect(result).toEqual({ valid: false, reasonCodes: ['VC_NOT_YET_VALID'] });
  });

  it('rejects a kid whose DID differs from the issuer claim', async () => {
    // Signed by the org key, but kid names a different DID → mismatch.
    const claims: CredentialClaims = {
      iss: ORG_DID,
      sub: AGENT_DID,
      jti: 'vc_kid_mismatch_did',
      nbf: NOW - 100,
      vc: {
        type: ['VerifiableCredential', 'AgentMembershipCredential'],
        credentialSubject: { id: AGENT_DID, organization: 'Acme Retail' },
      },
    };
    const jws = await issueRaw(orgSigner, ORG_DID, claims, 'did:web:evil.example:org');
    const result = await verifier.verify(jws, { now: NOW });
    expect(result).toEqual({ valid: false, reasonCodes: ['VC_ISSUER_KEY_MISMATCH'] });
  });

  it('rejects a kid whose fragment is not in the issuer DID document', async () => {
    const rogue = LocalSigner.generate(); // different key, same DID label
    const claims: CredentialClaims = {
      iss: ORG_DID,
      sub: AGENT_DID,
      jti: 'vc_kid_mismatch_fragment',
      nbf: NOW - 100,
      vc: {
        type: ['VerifiableCredential', 'AgentMembershipCredential'],
        credentialSubject: { id: AGENT_DID },
      },
    };
    const jws = await issueRaw(rogue, ORG_DID, claims);
    const result = await verifier.verify(jws, { now: NOW });
    expect(result).toEqual({ valid: false, reasonCodes: ['VC_ISSUER_KEY_MISMATCH'] });
  });

  it('rejects a wrong expected subject', async () => {
    const { jws } = await issuer.issueMembership({
      subjectDid: AGENT_DID,
      validFrom: NOW - 100,
      validUntil: NOW + 3600,
    });
    const result = await verifier.verify(jws, {
      now: NOW,
      expectedSubject: OTHER_AGENT_DID,
    });
    expect(result).toEqual({ valid: false, reasonCodes: ['WRONG_SUBJECT'] });
  });

  it('rejects an unsupported credential type', async () => {
    const { jws } = await issuer.issue({
      type: ['VerifiableCredential', 'AgentAttestationCredential'],
      credentialSubject: { id: AGENT_DID, predicate: 'certified' },
      subjectDid: AGENT_DID,
      validFrom: NOW - 100,
      validUntil: NOW + 3600,
    });
    const result = await verifier.verify(jws, { now: NOW });
    expect(result).toEqual({ valid: false, reasonCodes: ['VC_TYPE_UNSUPPORTED'] });
  });

  it('rejects malformed credentials of every flavor', async () => {
    expect(await verifier.verify('not-a-jws', { now: NOW })).toEqual({
      valid: false,
      reasonCodes: ['VC_INVALID'],
    });
    expect(await verifier.verify('two.parts', { now: NOW })).toEqual({
      valid: false,
      reasonCodes: ['VC_INVALID'],
    });
    // Empty-signature JWS.
    const empty = `${base64urlEncode(utf8('{"alg":"ES256","kid":"k"}'))}.${base64urlEncode(
      utf8('{"iss":"x"}'),
    )}.`;
    expect(await verifier.verify(empty, { now: NOW })).toEqual({
      valid: false,
      reasonCodes: ['VC_INVALID'],
    });
    // Non-canonical base64url (contains '+').
    const plus = `eyJhbGciOiJFUzI1NiIsImtpZCI6ImsifQ+.e30.AAAA`;
    expect(await verifier.verify(plus, { now: NOW })).toEqual({
      valid: false,
      reasonCodes: ['VC_INVALID'],
    });
    // crit extension present.
    const crit = await issueRaw(
      orgSigner,
      ORG_DID,
      baseClaims(),
      undefined,
      { crit: ['ignored'] },
    );
    expect(await verifier.verify(crit, { now: NOW })).toEqual({
      valid: false,
      reasonCodes: ['VC_INVALID'],
    });
  });

  it('rejects schema-invalid claims (missing jti; authority without actions)', async () => {
    const noJti = baseClaims() as unknown as Record<string, unknown>;
    delete noJti.jti;
    const jws1 = await issueRaw(orgSigner, ORG_DID, noJti);
    expect(await verifier.verify(jws1, { now: NOW })).toEqual({
      valid: false,
      reasonCodes: ['VC_SCHEMA_INVALID'],
    });

    const badAuthority = baseClaims('AgentDelegationCredential') as unknown as Record<
      string,
      unknown
    >;
    const badSubject = badAuthority.vc as Record<string, unknown>;
    badSubject.credentialSubject = {
      id: AGENT_DID,
      authority: { resources: ['tenant:acme'], delegationDepth: 0 },
    };
    const jws2 = await issueRaw(orgSigner, ORG_DID, badAuthority);
    expect(await verifier.verify(jws2, { now: NOW })).toEqual({
      valid: false,
      reasonCodes: ['VC_SCHEMA_INVALID'],
    });
  });

  it('rejects an issuer whose DID cannot be resolved', async () => {
    const unknown = 'did:web:unknown.example:org';
    const claims = baseClaims();
    claims.iss = unknown;
    // Sign so kid matches `unknown` — resolution is what must fail.
    const jws = await issueRaw(orgSigner, unknown, claims);
    const result = await verifier.verify(jws, { now: NOW });
    expect(result).toEqual({ valid: false, reasonCodes: ['DID_RESOLUTION_FAILED'] });
  });

  it('rejects an expectedType mismatch', async () => {
    const { jws } = await issuer.issueMembership({
      subjectDid: AGENT_DID,
      validFrom: NOW - 100,
      validUntil: NOW + 3600,
    });
    const result = await verifier.verify(jws, {
      now: NOW,
      expectedType: 'AgentDelegationCredential',
    });
    expect(result).toEqual({ valid: false, reasonCodes: ['VC_TYPE_UNSUPPORTED'] });
  });
});

function baseClaims(type = 'AgentMembershipCredential'): CredentialClaims {
  return {
    iss: ORG_DID,
    sub: AGENT_DID,
    jti: 'vc_base_claims_fixture',
    nbf: NOW - 100,
    exp: NOW + 3600,
    vc: {
      type: ['VerifiableCredential', type],
      credentialSubject:
        type === 'AgentDelegationCredential'
          ? { id: AGENT_DID, authority: AUTHORITY }
          : { id: AGENT_DID, organization: 'Acme Retail' },
    },
  };
}

/** Sign raw claims, optionally overriding the kid DID or extra header fields. */
async function issueRaw(
  signer: ReturnType<typeof LocalSigner.generate>,
  kidDid: string,
  claims: unknown,
  altKidDid?: string,
  extraHeader: Record<string, unknown> = {},
): Promise<string> {
  const wrapped: ReturnType<typeof withDid> = withDid(signer, kidDid);
  const kid =
    altKidDid === undefined
      ? await wrapped.keyId()
      : `${altKidDid}#${jwkThumbprint(await signer.publicKey())}`;
  const header = { alg: 'ES256', typ: 'JWT', kid, ...extraHeader };
  const headerB64 = base64urlEncode(utf8(JSON.stringify(header)));
  const payloadB64 = base64urlEncode(utf8(JSON.stringify(claims)));
  const signature = base64urlEncode(
    ecdsaDerToRaw(await wrapped.sign(utf8(`${headerB64}.${payloadB64}`))),
  );
  return `${headerB64}.${payloadB64}.${signature}`;
}
