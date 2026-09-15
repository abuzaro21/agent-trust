import { describe, expect, it } from 'vitest';

import {
  SCHEMA_ID_ACTION_RECEIPT_BODY,
  SCHEMA_ID_ACTION_RECEIPT_ENVELOPE,
  SCHEMA_ID_AUDIT_CHECKPOINT_PAYLOAD,
  SCHEMA_ID_AGENT_PROOF,
  SCHEMA_ID_AUTHORITY,
  SCHEMA_ID_DELEGATION_CREDENTIAL_CLAIMS,
  SCHEMA_ID_DID_DOCUMENT,
  SCHEMA_ID_MEMBERSHIP_CREDENTIAL_CLAIMS,
  SCHEMA_ID_POLICY_DECISION,
  SCHEMA_ID_POLICY_INPUT,
  SCHEMA_ID_TRUST_EVALUATE_REQUEST,
  createValidator,
} from '../src/index.js';

const v = createValidator();

describe('authority schema', () => {
  const valid = {
    actions: ['refund:create'],
    resources: ['tenant:acme'],
    audience: ['did:web:payments.example:agent'],
    limits: { amount: 500, currency: 'SAR', perDay: 20 },
    delegationDepth: 0,
  };

  it('accepts the canonical delegation authority', () => {
    expect(v.validate(SCHEMA_ID_AUTHORITY, valid).valid).toBe(true);
  });

  it('rejects an action name without domain:verb shape', () => {
    expect(v.validate(SCHEMA_ID_AUTHORITY, { ...valid, actions: ['refund'] }).valid).toBe(false);
  });

  it('rejects negative amount limits', () => {
    expect(
      v.validate(SCHEMA_ID_AUTHORITY, { ...valid, limits: { amount: -1 } }).valid,
    ).toBe(false);
  });

  it('rejects negative delegation depth and empty actions', () => {
    expect(v.validate(SCHEMA_ID_AUTHORITY, { ...valid, delegationDepth: -1 }).valid).toBe(false);
    expect(v.validate(SCHEMA_ID_AUTHORITY, { ...valid, actions: [] }).valid).toBe(false);
  });
});

describe('agent-proof schema', () => {
  const valid = {
    kid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#key-1',
    jti: '0123456789abcdef',
    iat: 1757800000,
    exp: 1757800300,
    signature: 'MEUCIQDkT4X',
  };

  it('accepts a well-formed proof', () => {
    expect(v.validate(SCHEMA_ID_AGENT_PROOF, valid).valid).toBe(true);
  });

  it('rejects a kid that is not a DID URL', () => {
    expect(v.validate(SCHEMA_ID_AGENT_PROOF, { ...valid, kid: 'not-a-did' }).valid).toBe(false);
  });

  it('rejects a short jti and non-base64url signatures', () => {
    expect(v.validate(SCHEMA_ID_AGENT_PROOF, { ...valid, jti: 'short' }).valid).toBe(false);
    expect(
      v.validate(SCHEMA_ID_AGENT_PROOF, { ...valid, signature: '!!!not+b64url!!!' }).valid,
    ).toBe(false);
  });
});

describe('policy-input schema', () => {
  const valid = {
    actor: { did: 'did:web:agents.acme.example:support-1', controller: 'did:web:acme.example:org', quarantined: false },
    request: { action: 'refund:create', amount: 120, currency: 'SAR', resource: 'tenant:acme' },
    authority: { actions: ['refund:create'], maxAmount: 500, currency: 'SAR' },
    evidence: {
      credentialsValid: true,
      revocationChecked: true,
      replaySafe: true,
      successfulSimilarActions30d: 41,
      unresolvedIncidents: 0,
    },
  };

  it('accepts the canonical policy input', () => {
    expect(v.validate(SCHEMA_ID_POLICY_INPUT, valid).valid).toBe(true);
  });

  it('accepts a null authority (missing authority must reach policy, not crash validation)', () => {
    expect(v.validate(SCHEMA_ID_POLICY_INPUT, { ...valid, authority: null }).valid).toBe(true);
  });

  it('rejects missing evidence flags — policy must never see unverified facts', () => {
    const broken = {
      ...valid,
      evidence: { credentialsValid: true },
    };
    expect(v.validate(SCHEMA_ID_POLICY_INPUT, broken).valid).toBe(false);
  });
});

describe('policy-decision schema', () => {
  const valid = {
    decisionId: 'dec_01JABCDEFGH',
    effect: 'DENY',
    reasonCodes: ['AUTHORITY_LIMIT_EXCEEDED'],
    failedConstraints: [
      { field: 'request.amount', actual: 5000, operator: '<=', expected: 500 },
    ],
    policyBundleHash: `sha256:${'a'.repeat(64)}`,
  };

  it('accepts a structured denial', () => {
    expect(v.validate(SCHEMA_ID_POLICY_DECISION, valid).valid).toBe(true);
  });

  it('rejects an unknown effect', () => {
    expect(v.validate(SCHEMA_ID_POLICY_DECISION, { ...valid, effect: 'MAYBE' }).valid).toBe(false);
  });

  it('rejects an unknown reason code — codes are a closed enum', () => {
    expect(
      v.validate(SCHEMA_ID_POLICY_DECISION, { ...valid, reasonCodes: ['NOT_A_REASON'] }).valid,
    ).toBe(false);
  });

  it('rejects a malformed policy bundle hash', () => {
    expect(
      v.validate(SCHEMA_ID_POLICY_DECISION, { ...valid, policyBundleHash: 'deadbeef' }).valid,
    ).toBe(false);
  });
});

describe('trust-evaluate-request schema', () => {
  const valid = {
    actor: 'did:web:agents.acme.example:support-1',
    action: 'refund:create',
    resource: 'order:ORD-918',
    parameters: { amount: 120, currency: 'SAR' },
    audience: 'did:web:payments.example:refund-agent',
    taskId: 'task_018',
    credentials: ['eyJhbGciOiJFUzI1NiIsImtpZCI6ImsifQ.e30.AQAB'],
    proof: {
      kid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#key-1',
      jti: '0123456789abcdef',
      iat: 1757800000,
      exp: 1757800300,
      signature: 'MEUCIQDkT4X',
    },
  };

  it('accepts the canonical evaluate request', () => {
    expect(v.validate(SCHEMA_ID_TRUST_EVALUATE_REQUEST, valid).valid).toBe(true);
  });

  it('rejects a credential that is not a compact JWS', () => {
    expect(
      v.validate(SCHEMA_ID_TRUST_EVALUATE_REQUEST, {
        ...valid,
        credentials: ['not-a-jws'],
      }).valid,
    ).toBe(false);
  });

  it('rejects a missing proof', () => {
    const { proof: _proof, ...withoutProof } = valid;
    expect(v.validate(SCHEMA_ID_TRUST_EVALUATE_REQUEST, withoutProof).valid).toBe(false);
  });
});

describe('action-receipt schemas (Step 9)', () => {
  const hex = (c: string) => c.repeat(64);
  const validBody = {
    receiptId: 'rcpt_01JABCDEF01',
    streamId: 'acme-demo',
    sequence: 1,
    recordedAt: '2026-09-15T12:00:00Z',
    actor: { did: 'did:web:agents.acme.example:support-1', controller: 'did:web:acme.example:org' },
    request: {
      action: 'refund:create',
      resource: 'order:ORD-918',
      audience: 'did:web:payments.example:refund-agent',
      parameters: { amount: 120, currency: 'SAR' },
    },
    authority: { credentialId: 'vc_abc12345', issuer: 'did:web:acme.example:org', authorityDigest: hex('a') },
    security: {
      proofVerified: true,
      credentialVerified: true,
      issuerTrusted: true,
      credentialActive: true,
      quarantined: false,
      replayChecked: true,
    },
    decision: {
      effect: 'ALLOW',
      reasonCodes: ['IDENTITY_VERIFIED', 'WITHIN_AMOUNT_LIMIT'],
      policy: { id: 'agent-trust-refund', version: '1.1.0', hash: `sha256:${hex('b')}` },
    },
  };

  it('accepts a canonical receipt body and a genesis envelope around it', () => {
    expect(v.validate(SCHEMA_ID_ACTION_RECEIPT_BODY, validBody).valid).toBe(true);
    const envelope = {
      body: validBody,
      previousHash: '0'.repeat(64), // genesis
      eventHash: hex('c'),
    };
    expect(v.validate(SCHEMA_ID_ACTION_RECEIPT_ENVELOPE, envelope).valid).toBe(true);
  });

  it('rejects DENY receipts without reason codes and non-const security facts', () => {
    const denyBody = structuredClone(validBody);
    denyBody.decision.effect = 'DENY';
    expect(v.validate(SCHEMA_ID_ACTION_RECEIPT_BODY, denyBody).valid).toBe(true);

    const lying = structuredClone(validBody);
    (lying.security as Record<string, unknown>).proofVerified = false;
    expect(v.validate(SCHEMA_ID_ACTION_RECEIPT_BODY, lying).valid).toBe(false);
  });

  it('rejects an envelope with a non-hex previousHash (no bare "genesis" string)', () => {
    const envelope = {
      body: validBody,
      previousHash: 'genesis',
      eventHash: hex('c'),
    };
    expect(v.validate(SCHEMA_ID_ACTION_RECEIPT_ENVELOPE, envelope).valid).toBe(false);
  });

  it('rejects secret-bearing extras (additionalProperties: false)', () => {
    const leaky = { ...structuredClone(validBody), accessToken: 'eyJhbGciOi...' } as Record<string, unknown>;
    expect(v.validate(SCHEMA_ID_ACTION_RECEIPT_BODY, leaky).valid).toBe(false);
  });
});

describe('audit-checkpoint-payload schema', () => {
  const valid = {
    checkpointId: 'ckpt_01JABCDEFGH',
    streamId: 'acme-demo',
    sequence: 100,
    headHash: 'a'.repeat(64),
    issuedAt: '2026-09-15T12:00:00Z',
    algorithm: 'sha256',
    chainFormat: 'agent-trust/action-receipt/v1',
  };

  it('accepts a canonical checkpoint payload', () => {
    expect(v.validate(SCHEMA_ID_AUDIT_CHECKPOINT_PAYLOAD, valid).valid).toBe(true);
  });

  it('rejects a wrong algorithm, wrong chainFormat, or sha256:-prefixed headHash', () => {
    expect(v.validate(SCHEMA_ID_AUDIT_CHECKPOINT_PAYLOAD, { ...valid, algorithm: 'md5' }).valid).toBe(false);
    expect(v.validate(SCHEMA_ID_AUDIT_CHECKPOINT_PAYLOAD, { ...valid, chainFormat: 'other/v9' }).valid).toBe(false);
    expect(v.validate(SCHEMA_ID_AUDIT_CHECKPOINT_PAYLOAD, { ...valid, headHash: `sha256:${'a'.repeat(64)}` }).valid).toBe(false);
  });
});

describe('did-document schema', () => {
  it('accepts a minimal document with a JsonWebKey2020 method', () => {
    const doc = {
      id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      verificationMethod: [
        {
          id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#key-1',
          type: 'JsonWebKey2020',
          controller: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AAA', y: 'BBB' },
        },
      ],
    };
    expect(v.validate(SCHEMA_ID_DID_DOCUMENT, doc).valid).toBe(true);
  });

  it('rejects a document without an id', () => {
    expect(v.validate(SCHEMA_ID_DID_DOCUMENT, { verificationMethod: [] }).valid).toBe(false);
  });
});

describe('delegation-credential-claims schema', () => {
  const valid = {
    iss: 'did:web:acme.example:org',
    sub: 'did:web:agents.acme.example:refund-bot',
    jti: 'vc-delegation-001',
    nbf: 1757800000,
    exp: 1760000000,
    vc: {
      type: ['VerifiableCredential', 'AgentDelegationCredential'],
      credentialSubject: {
        id: 'did:web:agents.acme.example:refund-bot',
        authority: {
          actions: ['refund:create'],
          resources: ['tenant:acme'],
          limits: { amount: 500, currency: 'SAR', perDay: 20 },
          delegationDepth: 0,
        },
      },
    },
  };

  it('accepts canonical delegation claims and resolves the authority $ref', () => {
    expect(v.validate(SCHEMA_ID_DELEGATION_CREDENTIAL_CLAIMS, valid).valid).toBe(true);
  });

  it('rejects wrong credential type and non-DID issuer', () => {
    expect(
      v.validate(SCHEMA_ID_DELEGATION_CREDENTIAL_CLAIMS, {
        ...valid,
        iss: 'https://evil.example',
      }).valid,
    ).toBe(false);
    expect(
      v.validate(SCHEMA_ID_DELEGATION_CREDENTIAL_CLAIMS, {
        ...valid,
        vc: { ...valid.vc, type: ['VerifiableCredential'] },
      }).valid,
    ).toBe(false);
  });

  it('accepts authority-level validFrom/validUntil time windows', () => {
    expect(
      v.validate(SCHEMA_ID_DELEGATION_CREDENTIAL_CLAIMS, {
        ...valid,
        vc: {
          ...valid.vc,
          credentialSubject: {
            ...valid.vc.credentialSubject,
            authority: {
              ...valid.vc.credentialSubject.authority,
              validFrom: '2026-09-13T00:00:00Z',
              validUntil: '2026-10-13T00:00:00Z',
            },
          },
        },
      }).valid,
    ).toBe(true);
  });

  it('pre-Step-9 regression: non-canonical UTC forms are rejected (lexicographic-time safety)', () => {
    const withTime = (value: string) => ({
      ...valid,
      vc: {
        ...valid.vc,
        credentialSubject: {
          ...valid.vc.credentialSubject,
          authority: {
            ...valid.vc.credentialSubject.authority,
            validUntil: value,
          },
        },
      },
    });
    // Timezone offset breaks lexicographic vs chronological equality.
    expect(v.validate(SCHEMA_ID_AUTHORITY, { ...valid.vc.credentialSubject.authority, validUntil: '2026-10-13T02:00:00+02:00' }).valid).toBe(false);
    // Fractional seconds change string width (".500" sorts AFTER "Z"-less
    // forms incorrectly) — not canonical.
    expect(v.validate(SCHEMA_ID_AUTHORITY, { ...valid.vc.credentialSubject.authority, validUntil: '2026-10-13T00:00:00.500Z' }).valid).toBe(false);
    // Non-UTC zone designator.
    expect(v.validate(SCHEMA_ID_AUTHORITY, { ...valid.vc.credentialSubject.authority, validUntil: '2026-10-13T00:00:00+00:00' }).valid).toBe(false);
    // Through the delegation claims schema too.
    expect(v.validate(SCHEMA_ID_DELEGATION_CREDENTIAL_CLAIMS, withTime('2026-10-13T00:00:00.500Z')).valid).toBe(false);
    expect(v.validate(SCHEMA_ID_DELEGATION_CREDENTIAL_CLAIMS, withTime('2026-10-13T00:00:00Z')).valid).toBe(true);
  });
});

describe('membership-credential-claims schema', () => {
  const validMembership = {
    iss: 'did:web:acme.example:org',
    sub: 'did:web:agents.acme.example:refund-bot',
    jti: 'vc-membership-001',
    nbf: 1757800000,
    vc: {
      type: ['VerifiableCredential', 'AgentMembershipCredential'],
      credentialSubject: {
        id: 'did:web:agents.acme.example:refund-bot',
        controller: 'did:web:acme.example:org',
        organization: 'Acme Retail',
        runtimeBinding: 'spiffe://acme.prod/agents/refund-01',
      },
    },
  };

  it('accepts canonical membership claims', () => {
    expect(
      v.validate(SCHEMA_ID_MEMBERSHIP_CREDENTIAL_CLAIMS, validMembership).valid,
    ).toBe(true);
  });

  it('rejects a non-DID subject and the wrong credential type marker', () => {
    expect(
      v.validate(SCHEMA_ID_MEMBERSHIP_CREDENTIAL_CLAIMS, {
        ...validMembership,
        sub: 'not-a-did',
      }).valid,
    ).toBe(false);
    expect(
      v.validate(SCHEMA_ID_MEMBERSHIP_CREDENTIAL_CLAIMS, {
        ...validMembership,
        vc: { ...validMembership.vc, type: ['VerifiableCredential', 'AgentDelegationCredential'] },
      }).valid,
    ).toBe(false);
  });
});
