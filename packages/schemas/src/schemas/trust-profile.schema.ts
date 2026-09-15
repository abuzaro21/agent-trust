import type { JsonSchema } from '../json-schema.js';

export const SCHEMA_ID_TRUST_PROFILE = 'https://agent-trust.dev/schemas/trust-profile.json';

const HEX64 = '^[0-9a-f]{64}$';
const CANONICAL_UTC = '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$';

/**
 * TrustProfile (Step 11A) — a contextual, EVIDENCE-BACKED READ MODEL.
 *
 * The schema structurally FORBIDS scalar trust/reputation/scoring fields
 * (additionalProperties: false everywhere + no such property defined):
 * there is no way to express score/trustScore/rating/stars in a valid
 * profile. Policy remains the only authorization engine; the profile
 * explains the evidence.
 */
export const trustProfileSchema: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: SCHEMA_ID_TRUST_PROFILE,
  title: 'TrustProfile',
  type: 'object',
  additionalProperties: false,
  required: ['agent', 'generatedAt', 'identity', 'authority', 'credentials', 'attestations', 'history'],
  properties: {
    agent: {
      type: 'object',
      additionalProperties: false,
      required: ['did'],
      properties: {
        did: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
        controller: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
      },
    },
    generatedAt: { type: 'string', pattern: CANONICAL_UTC },
    context: {
      type: 'object',
      additionalProperties: false,
      properties: {
        action: { type: 'string', pattern: '^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$' },
        resource: { type: 'string', minLength: 1 },
        audience: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
      },
    },
    identity: {
      type: 'object',
      additionalProperties: false,
      required: ['resolved'],
      properties: {
        resolved: { type: 'boolean' },
        verificationMethodCount: { type: 'integer', minimum: 0 },
      },
    },
    authority: {
      type: 'object',
      additionalProperties: false,
      required: ['active'],
      properties: {
        active: {
          type: 'array',
          items: {
            type: 'object',
            additionalProperties: false,
            required: ['credentialId', 'issuer', 'actions', 'resources', 'applicable'],
            properties: {
              credentialId: { type: 'string', minLength: 4 },
              issuer: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
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
              validUntil: { type: 'string', pattern: CANONICAL_UTC },
              /** sha256 digest of the canonical verified authority object. */
              evidenceDigest: { type: 'string', pattern: HEX64 },
              /** Context-relevance marker — evidence presentation, NOT policy. */
              applicable: { type: 'boolean' },
            },
          },
        },
      },
    },
    credentials: {
      type: 'object',
      additionalProperties: false,
      required: ['active', 'suspended', 'revoked'],
      properties: {
        active: { type: 'integer', minimum: 0 },
        suspended: { type: 'integer', minimum: 0 },
        revoked: { type: 'integer', minimum: 0 },
      },
    },
    attestations: {
      type: 'object',
      additionalProperties: false,
      required: ['trusted', 'rejected'],
      properties: {
        trusted: {
          type: 'array',
          items: {
            type: 'object',
            additionalProperties: false,
            required: ['credentialId', 'issuer', 'type', 'statement', 'domain'],
            properties: {
              credentialId: { type: 'string', minLength: 4 },
              issuer: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
              type: { enum: ['CAPABILITY_ENDORSEMENT', 'SECURITY_REVIEW', 'OPERATIONAL_APPROVAL'] },
              statement: { enum: ['ENDORSED', 'APPROVED', 'OBSERVED'] },
              domain: { type: 'string', minLength: 1 },
              validUntil: { type: 'string', pattern: CANONICAL_UTC },
            },
          },
        },
        rejected: {
          type: 'array',
          items: {
            type: 'object',
            additionalProperties: false,
            required: ['reasonCodes'],
            properties: {
              credentialId: { type: 'string', minLength: 4 },
              issuer: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
              reasonCodes: { type: 'array', minItems: 1, items: { type: 'string', minLength: 4 } },
            },
          },
        },
      },
    },
    history: {
      type: 'object',
      additionalProperties: false,
      required: ['integrity', 'byAction'],
      properties: {
        integrity: {
          type: 'object',
          additionalProperties: false,
          required: ['verified'],
          properties: {
            verified: { type: 'boolean' },
            verifiedThroughSequence: { type: 'integer', minimum: 0 },
            checkpointId: { type: 'string', minLength: 8 },
            checkpointHeadHash: { type: 'string', pattern: HEX64 },
            detail: { type: 'string', maxLength: 256 },
          },
        },
        byAction: {
          type: 'object',
          additionalProperties: {
            type: 'object',
            additionalProperties: false,
            required: ['decisions', 'execution', 'reasonCodes'],
            properties: {
              decisions: {
                type: 'object',
                additionalProperties: false,
                required: ['allow', 'deny'],
                properties: {
                  allow: { type: 'integer', minimum: 0 },
                  deny: { type: 'integer', minimum: 0 },
                },
              },
              execution: {
                type: 'object',
                additionalProperties: false,
                required: ['succeeded', 'failed', 'uncertain'],
                properties: {
                  succeeded: { type: 'integer', minimum: 0 },
                  failed: { type: 'integer', minimum: 0 },
                  uncertain: { type: 'integer', minimum: 0 },
                },
              },
              reasonCodes: {
                type: 'object',
                additionalProperties: { type: 'integer', minimum: 0 },
              },
              lastObservedAt: { type: 'string', pattern: CANONICAL_UTC },
            },
          },
        },
      },
    },
  },
};
