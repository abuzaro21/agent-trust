import { SCHEMA_ID_AUTHORITY } from './authority.schema.js';
import type { JsonSchema } from '../json-schema.js';

export const SCHEMA_ID_DELEGATION_CREDENTIAL_CLAIMS =
  'https://agent-trust.dev/schemas/delegation-credential-claims.json';

/**
 * The JWT claims inside a compact-JWS AgentDelegationCredential
 * (W3C VC 2.0, JOSE profile). `vc.credentialSubject.authority` is the
 * authority object; attenuation is verified against the parent chain.
 */
export const delegationCredentialClaimsSchema: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: SCHEMA_ID_DELEGATION_CREDENTIAL_CLAIMS,
  title: 'AgentDelegationCredential JWT claims',
  type: 'object',
  additionalProperties: true,
  required: ['iss', 'sub', 'jti', 'nbf', 'exp', 'vc'],
  properties: {
    iss: { type: 'string', pattern: '^did:[a-z0-9]+:.+', description: 'Delegator DID.' },
    sub: { type: 'string', pattern: '^did:[a-z0-9]+:.+', description: 'Delegate agent DID.' },
    jti: { type: 'string', minLength: 8 },
    nbf: { type: 'integer', minimum: 0 },
    exp: { type: 'integer', minimum: 0 },
    aud: {
      oneOf: [
        { type: 'string' },
        { type: 'array', items: { type: 'string' }, minItems: 1 },
      ],
    },
    vc: {
      type: 'object',
      required: ['type', 'credentialSubject'],
      properties: {
        type: {
          type: 'array',
          minItems: 2,
          contains: { const: 'AgentDelegationCredential' },
          items: { type: 'string' },
        },
        credentialSubject: {
          type: 'object',
          required: ['id', 'authority'],
          properties: {
            id: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
            authority: { $ref: `${SCHEMA_ID_AUTHORITY}#` },
          },
        },
        credentialStatus: { type: 'object' },
      },
    },
  },
};
