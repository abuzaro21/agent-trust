import type { JsonSchema } from '../json-schema.js';

export const SCHEMA_ID_VERIFIED_FACTS = 'https://agent-trust.dev/schemas/verified-facts.json';

/**
 * Canonical UTC timestamp: the Wasm policy compares time windows
 * lexicographically (time.parse_rfc3339_ns is not implemented in OPA's
 * Wasm runtime), which is chronologically correct ONLY in this exact
 * Z-normalized form. The trusted fact-assembler produces these via
 * Date.toISOString().
 */
export const CANONICAL_UTC_PATTERN = '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$';

/**
 * The ONLY input the policy engine accepts (Step 8A): pre-verified facts
 * assembled by trusted code. Every security gate upstream (PoP, VC
 * verification, issuer trust, status, quarantine, replay) is REQUIRED and
 * must be true here — failed verification never reaches the PDP, so the
 * schema makes "partially verified" inexpressible. Missing facts are
 * schema-invalid → the engine fails closed.
 */
export const verifiedFactsSchema: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: SCHEMA_ID_VERIFIED_FACTS,
  title: 'VerifiedFacts',
  type: 'object',
  additionalProperties: false,
  required: ['actor', 'request', 'identity', 'credential', 'authority', 'status', 'replay', 'context'],
  properties: {
    actor: {
      type: 'object',
      additionalProperties: false,
      required: ['did'],
      properties: {
        did: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
        controller: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
      },
    },
    request: {
      type: 'object',
      additionalProperties: false,
      required: ['action', 'resource', 'audience'],
      properties: {
        action: { type: 'string', pattern: '^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$' },
        resource: { type: 'string', minLength: 1 },
        audience: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
        parameters: {
          type: 'object',
          additionalProperties: false,
          properties: {
            amount: { type: 'number', exclusiveMinimum: 0 },
            currency: { type: 'string', minLength: 3, maxLength: 3 },
          },
        },
      },
    },
    identity: {
      type: 'object',
      additionalProperties: false,
      required: ['proofVerified'],
      properties: { proofVerified: { const: true } },
    },
    credential: {
      type: 'object',
      additionalProperties: false,
      required: ['verified', 'issuer', 'issuerTrusted', 'types'],
      properties: {
        verified: { const: true },
        issuer: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
        issuerTrusted: { const: true },
        types: {
          type: 'array',
          minItems: 1,
          items: { type: 'string', minLength: 1 },
        },
      },
    },
    authority: {
      type: 'object',
      additionalProperties: false,
      required: ['actions', 'resources'],
      properties: {
        actions: { type: 'array', minItems: 1, items: { type: 'string', minLength: 1 } },
        resources: { type: 'array', minItems: 1, items: { type: 'string', minLength: 1 } },
        audience: { type: 'array', items: { type: 'string', minLength: 1 } },
        limits: {
          type: 'object',
          additionalProperties: false,
          properties: {
            amount: { type: 'number', exclusiveMinimum: 0 },
            currency: { type: 'string', minLength: 3, maxLength: 3 },
            perDay: { type: 'integer', exclusiveMinimum: 0 },
          },
        },
        validFrom: { type: 'string', pattern: CANONICAL_UTC_PATTERN },
        validUntil: { type: 'string', pattern: CANONICAL_UTC_PATTERN },
      },
    },
    status: {
      type: 'object',
      additionalProperties: false,
      required: ['credentialActive', 'quarantined'],
      properties: {
        credentialActive: { const: true },
        quarantined: { const: false },
      },
    },
    replay: {
      type: 'object',
      additionalProperties: false,
      required: ['checked', 'claimed'],
      properties: {
        checked: { const: true },
        claimed: { const: true },
      },
    },
    context: {
      type: 'object',
      additionalProperties: false,
      required: ['now'],
      properties: {
        now: { type: 'string', pattern: CANONICAL_UTC_PATTERN },
      },
    },
  },
};
