import type { JsonSchema } from '../json-schema.js';

export const SCHEMA_ID_AUTHORITY = 'https://agent-trust.dev/schemas/authority.json';

export const authoritySchema: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: SCHEMA_ID_AUTHORITY,
  title: 'Authority',
  description:
    'Scoped authority carried by an AgentDelegationCredential. Attenuation (Authority(child) ⊆ Authority(parent)) is enforced by the delegation verifier, not by this schema.',
  type: 'object',
  additionalProperties: false,
  required: ['actions', 'resources', 'delegationDepth'],
  properties: {
    actions: {
      type: 'array',
      minItems: 1,
      uniqueItems: true,
      items: { $ref: '#/$defs/actionName' },
    },
    resources: {
      type: 'array',
      minItems: 1,
      uniqueItems: true,
      items: { type: 'string', minLength: 1 },
    },
    audience: {
      type: 'array',
      uniqueItems: true,
      items: { $ref: '#/$defs/did' },
    },
    limits: {
      type: 'object',
      additionalProperties: false,
      properties: {
        amount: { type: 'number', exclusiveMinimum: 0 },
        currency: { type: 'string', minLength: 3, maxLength: 3 },
        perDay: { type: 'integer', exclusiveMinimum: 0 },
      },
    },
    delegationDepth: { type: 'integer', minimum: 0 },
  },
  $defs: {
    did: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
    actionName: { type: 'string', pattern: '^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$' },
  },
};
