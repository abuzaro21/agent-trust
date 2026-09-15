import type { JsonSchema } from '../json-schema.js';

export const SCHEMA_ID_AUTHORITY = 'https://agent-trust.dev/schemas/authority.json';

/**
 * Canonical UTC timestamp: the Wasm policy compares authority time windows
 * lexicographically (time.parse_rfc3339_ns is unavailable in OPA's Wasm
 * runtime), which is chronologically correct ONLY in this exact form —
 * fixed width, zero-padded, UTC 'Z', no offsets, no fractional seconds.
 * Pre-Step-9 review pinned this at the AUTHORITY boundary (delegation VC
 * claims are attacker-influencable input at verification time), not just
 * in the VerifiedFacts schema.
 */
export const CANONICAL_UTC_PATTERN = '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$';

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
    validFrom: { type: 'string', pattern: CANONICAL_UTC_PATTERN },
    validUntil: { type: 'string', pattern: CANONICAL_UTC_PATTERN },
  },
  $defs: {
    did: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
    actionName: { type: 'string', pattern: '^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$' },
  },
};
