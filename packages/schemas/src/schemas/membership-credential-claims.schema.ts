import type { JsonSchema } from '../json-schema.js';

export const SCHEMA_ID_MEMBERSHIP_CREDENTIAL_CLAIMS =
  'https://agent-trust.dev/schemas/membership-credential-claims.json';

/**
 * The JWT claims inside a compact-JWS AgentMembershipCredential
 * (W3C VC 2.0, JOSE profile). Proves who controls the agent and which
 * organization it belongs to; carries no authority (that is the
 * delegation credential's job, so membership can never grant powers).
 */
export const membershipCredentialClaimsSchema: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: SCHEMA_ID_MEMBERSHIP_CREDENTIAL_CLAIMS,
  title: 'AgentMembershipCredential JWT claims',
  type: 'object',
  additionalProperties: true,
  required: ['iss', 'sub', 'jti', 'nbf', 'vc'],
  properties: {
    iss: { type: 'string', pattern: '^did:[a-z0-9]+:.+', description: 'Issuer (controller org) DID.' },
    sub: { type: 'string', pattern: '^did:[a-z0-9]+:.+', description: 'Member agent DID.' },
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
          contains: { const: 'AgentMembershipCredential' },
          items: { type: 'string' },
        },
        credentialSubject: {
          type: 'object',
          required: ['id'],
          properties: {
            id: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
            controller: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
            organization: { type: 'string', minLength: 1 },
            runtimeBinding: { type: 'string', minLength: 1 },
          },
        },
        credentialStatus: { type: 'object' },
      },
    },
  },
};
