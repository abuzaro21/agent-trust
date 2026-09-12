import { REASON_CODES } from '../reason-codes.js';
import type { JsonSchema } from '../json-schema.js';

export const SCHEMA_ID_POLICY_DECISION = 'https://agent-trust.dev/schemas/policy-decision.json';

export const policyDecisionSchema: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: SCHEMA_ID_POLICY_DECISION,
  title: 'PolicyDecision',
  description:
    'Structured, deterministic decision object. Reason codes and failed constraints are machine-generated; an LLM may rephrase them later but never generates them.',
  type: 'object',
  additionalProperties: false,
  required: ['decisionId', 'effect', 'reasonCodes', 'policyBundleHash'],
  properties: {
    decisionId: { type: 'string', minLength: 8 },
    effect: { enum: ['ALLOW', 'DENY', 'REQUIRE_APPROVAL'] },
    reasonCodes: {
      type: 'array',
      minItems: 1,
      items: { enum: [...REASON_CODES] },
    },
    failedConstraints: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['field', 'operator'],
        properties: {
          field: { type: 'string', minLength: 1 },
          actual: {},
          operator: { type: 'string', minLength: 1 },
          expected: {},
        },
      },
    },
    matchedPolicies: {
      type: 'array',
      items: { type: 'string', minLength: 1 },
    },
    evidenceRefs: {
      type: 'array',
      items: { type: 'string', minLength: 1 },
    },
    policyBundleHash: { type: 'string', pattern: '^sha256:[a-f0-9]{64}$' },
    expiresAt: { type: 'string', format: 'date-time' },
  },
};
