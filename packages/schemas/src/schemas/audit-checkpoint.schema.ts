import type { JsonSchema } from '../json-schema.js';

export const SCHEMA_ID_AUDIT_CHECKPOINT_PAYLOAD =
  'https://agent-trust.dev/schemas/audit-checkpoint-payload.json';

/**
 * Signed checkpoint payload (Step 9I): anchors one stream's chain head at
 * a sequence. Signed as a compact JWS via the existing Signer/JWS stack;
 * iss/kid/iat arrive through the JOSE conventions (additional properties
 * allowed for them). chainFormat pins the receipt hash domain separator.
 */
export const auditCheckpointPayloadSchema: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: SCHEMA_ID_AUDIT_CHECKPOINT_PAYLOAD,
  title: 'AuditCheckpointPayload',
  type: 'object',
  required: ['checkpointId', 'streamId', 'sequence', 'headHash', 'issuedAt', 'algorithm', 'chainFormat'],
  properties: {
    checkpointId: { type: 'string', minLength: 8 },
    streamId: { type: 'string', minLength: 1, maxLength: 256 },
    sequence: { type: 'integer', minimum: 0 },
    headHash: { type: 'string', pattern: '^[0-9a-f]{64}$' },
    issuedAt: { type: 'string', pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$' },
    algorithm: { const: 'sha256' },
    chainFormat: { const: 'agent-trust/action-receipt/v1' },
  },
};
