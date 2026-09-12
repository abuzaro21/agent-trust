import type { JsonSchema } from '../json-schema.js';

export const SCHEMA_ID_ACTION_RECEIPT = 'https://agent-trust.dev/schemas/action-receipt.json';

const HASH_PATTERN = {
  anyHash: '^(sha256:[a-f0-9]{64}|genesis)$',
  sha256: '^sha256:[a-f0-9]{64}$',
};

export const actionReceiptSchema: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: SCHEMA_ID_ACTION_RECEIPT,
  title: 'ActionReceipt',
  description:
    'One entry in the append-only action hash chain. eventHash = SHA-256(previousEventHash || canonical(payload)). Any edit or deletion breaks every later event.',
  type: 'object',
  additionalProperties: false,
  required: [
    'eventId',
    'actorDid',
    'action',
    'resource',
    'decisionId',
    'effect',
    'requestHash',
    'previousHash',
    'eventHash',
    'timestamp',
  ],
  properties: {
    eventId: { type: 'string', minLength: 1 },
    actorDid: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
    action: { type: 'string', minLength: 1 },
    resource: { type: 'string', minLength: 1 },
    decisionId: { type: 'string', minLength: 8 },
    effect: { enum: ['ALLOW', 'DENY', 'REQUIRE_APPROVAL'] },
    requestHash: { type: 'string', pattern: HASH_PATTERN.sha256 },
    previousHash: { type: 'string', pattern: HASH_PATTERN.anyHash },
    eventHash: { type: 'string', pattern: HASH_PATTERN.sha256 },
    timestamp: { type: 'string', format: 'date-time' },
  },
};
