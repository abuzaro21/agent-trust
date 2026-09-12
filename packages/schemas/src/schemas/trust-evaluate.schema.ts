import { SCHEMA_ID_AGENT_PROOF } from './agent-proof.schema.js';
import type { JsonSchema } from '../json-schema.js';

export const SCHEMA_ID_TRUST_EVALUATE_REQUEST =
  'https://agent-trust.dev/schemas/trust-evaluate-request.json';

export const trustEvaluateRequestSchema: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: SCHEMA_ID_TRUST_EVALUATE_REQUEST,
  title: 'TrustEvaluateRequest',
  description: 'POST /v1/trust/evaluate request body (the heart of the fabric).',
  type: 'object',
  additionalProperties: false,
  required: ['actor', 'action', 'resource', 'taskId', 'credentials', 'proof'],
  properties: {
    actor: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
    action: { type: 'string', pattern: '^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$' },
    resource: { type: 'string', minLength: 1 },
    parameters: { type: 'object', additionalProperties: true },
    audience: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
    taskId: { type: 'string', minLength: 1 },
    nonce: { type: 'string', minLength: 8 },
    credentials: {
      type: 'array',
      items: {
        type: 'string',
        description: 'Compact JWS (Verifiable Credential).',
        pattern: '^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$',
      },
    },
    proof: { $ref: `${SCHEMA_ID_AGENT_PROOF}#` },
  },
};
