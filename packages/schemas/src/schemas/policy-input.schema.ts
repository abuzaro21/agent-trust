import type { JsonSchema } from '../json-schema.js';

export const SCHEMA_ID_POLICY_INPUT = 'https://agent-trust.dev/schemas/policy-input.json';

export const policyInputSchema: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: SCHEMA_ID_POLICY_INPUT,
  title: 'PolicyInput',
  description:
    'The only input the policy engine accepts: pre-verified facts plus request context. Rego never parses cryptography (ADR-0002).',
  type: 'object',
  additionalProperties: false,
  required: ['actor', 'request', 'authority', 'evidence'],
  properties: {
    actor: {
      type: 'object',
      additionalProperties: false,
      required: ['did', 'quarantined'],
      properties: {
        did: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
        controller: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
        quarantined: { type: 'boolean' },
      },
    },
    request: {
      type: 'object',
      additionalProperties: false,
      required: ['action', 'resource'],
      properties: {
        action: { type: 'string', pattern: '^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$' },
        amount: { type: 'number', exclusiveMinimum: 0 },
        currency: { type: 'string', minLength: 3, maxLength: 3 },
        resource: { type: 'string', minLength: 1 },
      },
    },
    authority: {
      oneOf: [
        { type: 'null' },
        {
          type: 'object',
          additionalProperties: false,
          required: ['actions'],
          properties: {
            actions: {
              type: 'array',
              minItems: 1,
              items: { type: 'string', minLength: 1 },
            },
            maxAmount: { type: 'number', exclusiveMinimum: 0 },
            currency: { type: 'string', minLength: 3, maxLength: 3 },
          },
        },
      ],
    },
    evidence: {
      type: 'object',
      additionalProperties: false,
      required: ['credentialsValid', 'revocationChecked', 'replaySafe'],
      properties: {
        credentialsValid: { type: 'boolean' },
        revocationChecked: { type: 'boolean' },
        replaySafe: { type: 'boolean' },
        successfulSimilarActions30d: { type: 'integer', minimum: 0 },
        unresolvedIncidents: { type: 'integer', minimum: 0 },
      },
    },
  },
};
