// ajv ships CJS builds whose ESM-style typings do not interop cleanly under
// NodeNext; createRequire returns the real exports. These minimal local
// types keep the used surface precise without reaching into ajv's internals.
import { createRequire } from 'node:module';

const requireCjs = createRequire(import.meta.url);

interface AjvErrorObject {
  instancePath: string;
  message?: string;
}

type AjvValidateFn = ((data: unknown) => boolean) & {
  errors: AjvErrorObject[] | null | undefined;
};

interface Ajv2020Instance {
  addSchema(schema: unknown): unknown;
  getSchema(id: string): AjvValidateFn | undefined;
}

interface Ajv2020Options {
  strict?: boolean;
  allErrors?: boolean;
}

const Ajv2020 = requireCjs('ajv/dist/2020.js') as new (
  options?: Ajv2020Options,
) => Ajv2020Instance;
const addFormats = requireCjs('ajv-formats') as (ajv: Ajv2020Instance) => Ajv2020Instance;

import { SCHEMA_ID_ACTION_RECEIPT, actionReceiptSchema } from './schemas/action-receipt.schema.js';
import { SCHEMA_ID_AGENT_PROOF, agentProofSchema } from './schemas/agent-proof.schema.js';
import { SCHEMA_ID_AUTHORITY, authoritySchema } from './schemas/authority.schema.js';
import {
  SCHEMA_ID_DELEGATION_CREDENTIAL_CLAIMS,
  delegationCredentialClaimsSchema,
} from './schemas/delegation-credential.schema.js';
import {
  SCHEMA_ID_MEMBERSHIP_CREDENTIAL_CLAIMS,
  membershipCredentialClaimsSchema,
} from './schemas/membership-credential-claims.schema.js';
import {
  SCHEMA_ID_DID_DOCUMENT,
  didDocumentSchema,
} from './schemas/did-document.schema.js';
import {
  SCHEMA_ID_POLICY_DECISION,
  policyDecisionSchema,
} from './schemas/policy-decision.schema.js';
import {
  SCHEMA_ID_POLICY_INPUT,
  policyInputSchema,
} from './schemas/policy-input.schema.js';
import {
  SCHEMA_ID_BITSTRING_STATUS_ENTRY,
  bitstringStatusEntrySchema,
} from './schemas/status-entry.schema.js';
import {
  SCHEMA_ID_TRUST_EVALUATE_REQUEST,
  trustEvaluateRequestSchema,
} from './schemas/trust-evaluate.schema.js';

export const ALL_SCHEMAS = [
  authoritySchema,
  agentProofSchema,
  policyInputSchema,
  policyDecisionSchema,
  trustEvaluateRequestSchema,
  actionReceiptSchema,
  didDocumentSchema,
  delegationCredentialClaimsSchema,
  membershipCredentialClaimsSchema,
  bitstringStatusEntrySchema,
] as const;

export const SCHEMA_IDS = [
  SCHEMA_ID_AUTHORITY,
  SCHEMA_ID_AGENT_PROOF,
  SCHEMA_ID_POLICY_INPUT,
  SCHEMA_ID_POLICY_DECISION,
  SCHEMA_ID_TRUST_EVALUATE_REQUEST,
  SCHEMA_ID_ACTION_RECEIPT,
  SCHEMA_ID_DID_DOCUMENT,
  SCHEMA_ID_DELEGATION_CREDENTIAL_CLAIMS,
  SCHEMA_ID_MEMBERSHIP_CREDENTIAL_CLAIMS,
  SCHEMA_ID_BITSTRING_STATUS_ENTRY,
] as const;

export interface ValidationOutcome {
  valid: boolean;
  errors: string[];
}

export interface Validator {
  validate<T = unknown>(schemaId: string, data: unknown): ValidationOutcome & { data?: T };
}

/** Compile all contract schemas once; resolve by $id. */
export function createValidator(): Validator {
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  addFormats(ajv);
  for (const schema of ALL_SCHEMAS) {
    ajv.addSchema(schema as Record<string, unknown>);
  }
  return {
    validate(schemaId, data) {
      const check = ajv.getSchema(schemaId);
      if (!check) {
        throw new Error(`Unknown schema id: ${schemaId}`);
      }
      const valid = check(data) as boolean;
      return {
        valid,
        errors: (check.errors ?? []).map(
          (e) => `${e.instancePath || '/'} ${e.message ?? '(no message)'}`.trim(),
        ),
      };
    },
  };
}
