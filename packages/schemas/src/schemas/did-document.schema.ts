import type { JsonSchema } from '../json-schema.js';

export const SCHEMA_ID_DID_DOCUMENT = 'https://agent-trust.dev/schemas/did-document.json';

export const didDocumentSchema: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: SCHEMA_ID_DID_DOCUMENT,
  title: 'DidDocument (support subset)',
  description:
    'The subset of a W3C DID Document this fabric consumes. Services and other properties are tolerated but ignored.',
  type: 'object',
  required: ['id'],
  properties: {
    '@context': {
      oneOf: [{ type: 'string' }, { type: 'array', items: { type: 'string' } }],
    },
    id: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
    verificationMethod: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'type', 'controller'],
        properties: {
          id: { type: 'string', pattern: '^did:[a-z0-9]+:.+#.+$' },
          type: { type: 'string', minLength: 1 },
          controller: { type: 'string', pattern: '^did:[a-z0-9]+:.+' },
          publicKeyJwk: { type: 'object' },
        },
      },
    },
    authentication: {
      type: 'array',
      items: {
        oneOf: [
          { type: 'string', pattern: '^did:[a-z0-9]+:.+#.+$' },
          { type: 'object' },
        ],
      },
    },
  },
};
