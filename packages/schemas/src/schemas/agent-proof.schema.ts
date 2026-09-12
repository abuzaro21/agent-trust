import type { JsonSchema } from '../json-schema.js';

export const SCHEMA_ID_AGENT_PROOF = 'https://agent-trust.dev/schemas/agent-proof.json';

export const agentProofSchema: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: SCHEMA_ID_AGENT_PROOF,
  title: 'AgentProof',
  description:
    'Proof-of-possession bound to a single request. signature = base64url(ES256(canonicalJson({htu, requestBodyDigest, jti, iat, exp, nonce?}))). Cross-field validity (exp > iat, freshness) is enforced at verification time.',
  type: 'object',
  additionalProperties: false,
  required: ['kid', 'jti', 'iat', 'exp', 'signature'],
  properties: {
    kid: {
      type: 'string',
      pattern: '^did:[a-z0-9]+:.+#.+$',
      description: 'DID URL of the signing verification method.',
    },
    jti: { type: 'string', minLength: 16 },
    iat: { type: 'integer', minimum: 0 },
    exp: { type: 'integer', minimum: 0 },
    nonce: { type: 'string', minLength: 8 },
    signature: { type: 'string', pattern: '^[A-Za-z0-9_-]+$' },
  },
};
