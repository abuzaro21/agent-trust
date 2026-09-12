import { describe, expect, it } from 'vitest';

import {
  SCHEMA_ID_ACTION_RECEIPT,
  SCHEMA_ID_AGENT_PROOF,
  SCHEMA_ID_AUTHORITY,
  SCHEMA_ID_DELEGATION_CREDENTIAL_CLAIMS,
  SCHEMA_ID_DID_DOCUMENT,
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

describe('action-receipt schema', () => {
  const sha = `sha256:${'0'.repeat(64)}`;
  const valid = {
    eventId: 'evt_01',
    actorDid: 'did:web:agents.acme.example:support-1',
    action: 'refund:create',
    resource: 'order:ORD-918',
    decisionId: 'dec_01JABCDEFGH',
    effect: 'ALLOW',
    requestHash: sha,
    previousHash: 'genesis',
    eventHash: `sha256:${'1'.repeat(64)}`,
    timestamp: '2026-09-13T12:00:00Z',
  };

  it('accepts a genesis receipt', () => {
    expect(v.validate(SCHEMA_ID_ACTION_RECEIPT, valid).valid).toBe(true);
  });

  it('rejects a previousHash that is neither a sha256 ref nor genesis', () => {
    expect(
      v.validate(SCHEMA_ID_ACTION_RECEIPT, { ...valid, previousHash: 'md5:xyz' }).valid,
    ).toBe(false);
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
});
