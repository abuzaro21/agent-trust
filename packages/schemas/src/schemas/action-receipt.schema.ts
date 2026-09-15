import type { JsonSchema } from '../json-schema.js';

export const SCHEMA_ID_ACTION_RECEIPT_BODY =
  'https://agent-trust.dev/schemas/action-receipt-body.json';
export const SCHEMA_ID_ACTION_RECEIPT_ENVELOPE =
  'https://agent-trust.dev/schemas/action-receipt-envelope.json';

/**
 * ActionReceiptBody (Step 9C) — the canonical, HASHED payload of one trust
 * decision. Evidence is recorded as identifiers and digests only; raw
 * credentials, tokens, secrets, and customer PII are structurally
 * excluded (the schema rejects unknown properties, and the receipt
 * builder is a strict field allowlist).
 *
 * `security` facts are pinned const — a receipt is only ever written for
 * a request that passed every gate; policy re-verification of these is
 * meaningless (the policy engine already consumed them).
 */
const HEX64 = '^[0-9a-f]{64}$';

export const actionReceiptBodySchema: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: SCHEMA_ID_ACTION_RECEIPT_BODY,
  title: 'ActionReceiptBody',
  type: 'object',
  additionalProperties: false,
  required: ['receiptId', 'streamId', 'sequence', 'recordedAt', 'actor', 'request', 'decision', 'security'],
  properties: {
    receiptId: { type: 'string', minLength: 8 },
    streamId: { type: 'string', minLength: 1, maxLength: 256 },
    sequence: { type: 'integer', minimum: 1 },
    recordedAt: { type: 'string', pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$' },
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
    authority: {
      type: 'object',
      additionalProperties: false,
      properties: {
        credentialId: { type: 'string', minLength: 4 },
        issuer: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
        /** sha256 hex digest of the canonical authority object. */
        authorityDigest: { type: 'string', pattern: HEX64 },
      },
    },
    security: {
      type: 'object',
      additionalProperties: false,
      required: ['proofVerified', 'credentialVerified', 'issuerTrusted', 'credentialActive', 'quarantined', 'replayChecked'],
      properties: {
        proofVerified: { const: true },
        credentialVerified: { const: true },
        issuerTrusted: { const: true },
        credentialActive: { const: true },
        quarantined: { const: false },
        replayChecked: { const: true },
      },
    },
    decision: {
      type: 'object',
      additionalProperties: false,
      required: ['effect', 'reasonCodes', 'policy'],
      properties: {
        effect: { enum: ['ALLOW', 'DENY', 'REQUIRE_APPROVAL'] },
        reasonCodes: { type: 'array', minItems: 1, items: { type: 'string', minLength: 4 } },
        policy: {
          type: 'object',
          additionalProperties: false,
          required: ['id', 'version', 'hash'],
          properties: {
            id: { type: 'string', minLength: 1 },
            version: { type: 'string', minLength: 1 },
            hash: { type: 'string', pattern: '^sha256:[a-f0-9]{64}$' },
          },
        },
      },
    },
    execution: {
      type: 'object',
      additionalProperties: false,
      required: ['state'],
      properties: {
        state: { enum: ['NOT_EXECUTED', 'SUCCEEDED', 'FAILED'] },
        resultDigest: { type: 'string', pattern: HEX64 },
      },
    },
    /**
     * Append-only correlation (Step 10): the decision receipt and the
     * execution-outcome receipt are SEPARATE chained receipts — never a
     * mutation of one record. The outcome receipt references the decision
     * receipt via decisionReceiptId; taskId is the idempotency key.
     */
    correlation: {
      type: 'object',
      additionalProperties: false,
      required: ['taskId'],
      properties: {
        taskId: { type: 'string', minLength: 1, maxLength: 128 },
        decisionReceiptId: { type: 'string', minLength: 8 },
      },
    },
  },
};

/**
 * Chain envelope (Step 9D): hash fields live OUTSIDE the hashed body.
 * previousHash/eventHash are fixed-size 64-char lowercase hex (32 bytes);
 * the stream's first receipt uses the all-zero genesis previousHash.
 */
export const actionReceiptEnvelopeSchema: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: SCHEMA_ID_ACTION_RECEIPT_ENVELOPE,
  title: 'ActionReceipt',
  type: 'object',
  additionalProperties: false,
  required: ['body', 'previousHash', 'eventHash'],
  properties: {
    body: { $ref: `${SCHEMA_ID_ACTION_RECEIPT_BODY}#` },
    previousHash: { type: 'string', pattern: HEX64 },
    eventHash: { type: 'string', pattern: HEX64 },
  },
};
