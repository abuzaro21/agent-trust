import { REASON_CODES } from '../reason-codes.js';
import type { JsonSchema } from '../json-schema.js';

export const SCHEMA_ID_POLICY_RESULT = 'https://agent-trust.dev/schemas/policy-result.json';

/**
 * The RAW structured output the compiled Rego entrypoint must produce
 * (Step 8E). The engine validates the Wasm result against this schema
 * before trusting it — undefined, empty, malformed, unknown-effect, and
 * unknown-reason-code outputs all fail closed (Step 8J). The full
 * PolicyDecision (decisionId + policyBundleHash added) is built by the
 * engine afterwards.
 */
export const policyResultSchema: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: SCHEMA_ID_POLICY_RESULT,
  title: 'PolicyResult (raw Rego entrypoint output)',
  type: 'object',
  additionalProperties: false,
  required: ['effect', 'reasonCodes'],
  properties: {
    effect: { enum: ['ALLOW', 'DENY', 'REQUIRE_APPROVAL'] },
    reasonCodes: {
      type: 'array',
      minItems: 1,
      items: { enum: [...REASON_CODES] },
    },
  },
};
