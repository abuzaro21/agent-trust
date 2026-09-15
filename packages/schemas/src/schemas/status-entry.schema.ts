import type { JsonSchema } from '../json-schema.js';

export const SCHEMA_ID_BITSTRING_STATUS_ENTRY =
  'https://agent-trust.dev/schemas/bitstring-status-entry.json';

/**
 * A BitstringStatusListEntry as embedded in `credentialStatus` (W3C
 * Bitstring Status List, minimal demo profile). One entry per credential —
 * a credential needing both revocation and suspension purposes carries two
 * credentials, one per list.
 */
export const bitstringStatusEntrySchema: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: SCHEMA_ID_BITSTRING_STATUS_ENTRY,
  title: 'BitstringStatusListEntry',
  type: 'object',
  required: ['id', 'type', 'statusPurpose', 'statusListIndex', 'statusListCredential'],
  properties: {
    id: { type: 'string', minLength: 1 },
    type: { const: 'BitstringStatusListEntry' },
    statusPurpose: { enum: ['revocation', 'suspension'] },
    statusListIndex: { type: 'string', pattern: '^[0-9]+$' },
    statusListCredential: { type: 'string', minLength: 1 },
  },
};
