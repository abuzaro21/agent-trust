import type { JsonSchema } from '../json-schema.js';

export const SCHEMA_ID_ATTESTATION_CREDENTIAL_CLAIMS =
  'https://agent-trust.dev/schemas/attestation-credential-claims.json';

/**
 * The JWT claims inside a compact-JWS AgentAttestationCredential (Step 11D).
 * Closed machine-readable categories; free text cannot carry semantics.
 * Revocation/suspension reuse the standard credentialStatus mechanism.
 */
export const attestationCredentialClaimsSchema: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: SCHEMA_ID_ATTESTATION_CREDENTIAL_CLAIMS,
  title: 'AgentAttestationCredential JWT claims',
  type: 'object',
  additionalProperties: true,
  required: ['iss', 'sub', 'jti', 'nbf', 'vc'],
  properties: {
    iss: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
    sub: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
    jti: { type: 'string', minLength: 8 },
    nbf: { type: 'integer', minimum: 0 },
    exp: { type: 'integer', minimum: 0 },
    vc: {
      type: 'object',
      required: ['type', 'credentialSubject'],
      properties: {
        type: {
          type: 'array',
          minItems: 2,
          contains: { const: 'AgentAttestationCredential' },
          items: { type: 'string' },
        },
        credentialSubject: {
          type: 'object',
          additionalProperties: false,
          required: ['id', 'attestation'],
          properties: {
            id: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
            attestation: {
              type: 'object',
              additionalProperties: false,
              required: ['type', 'domain', 'statement'],
              properties: {
                type: {
                  enum: ['CAPABILITY_ENDORSEMENT', 'SECURITY_REVIEW', 'OPERATIONAL_APPROVAL'],
                },
                domain: { type: 'string', minLength: 1, maxLength: 128 },
                statement: { enum: ['ENDORSED', 'APPROVED', 'OBSERVED'] },
                scope: {
                  type: 'object',
                  additionalProperties: false,
                  properties: {
                    actions: { type: 'array', items: { type: 'string', minLength: 1 } },
                    resources: { type: 'array', items: { type: 'string', minLength: 1 } },
                    audience: { type: 'array', items: { type: 'string', minLength: 1 } },
                  },
                },
                evidence: {
                  type: 'object',
                  additionalProperties: false,
                  properties: {
                    uri: { type: 'string', minLength: 1, maxLength: 512 },
                    digest: { type: 'string', pattern: '^[0-9a-f]{64}$' },
                  },
                },
              },
            },
          },
        },
        credentialStatus: { type: 'object' },
      },
    },
  },
};
