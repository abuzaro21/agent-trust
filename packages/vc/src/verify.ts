import type { PublicJwk } from '@agent-trust/crypto';
import type { DidResolver } from '@agent-trust/did';
import { parseDidUrl } from '@agent-trust/did';
import {
  type Authority,
  type ReasonCode,
  SCHEMA_ID_DELEGATION_CREDENTIAL_CLAIMS,
  SCHEMA_ID_MEMBERSHIP_CREDENTIAL_CLAIMS,
  type Validator,
  createValidator,
} from '@agent-trust/schemas';

import {
  JwsFormatError,
  decodeJwsPayload,
  parseCompactJws,
  verifyCompactJwsSignature,
} from './jws.js';
import { IssuerTrustStore } from './trust.js';
import {
  type CredentialClaims,
  type CredentialType,
  type VcVerification,
  type VerifiedFacts,
  SUPPORTED_CREDENTIAL_TYPES,
} from './types.js';

export interface VerifyOptions {
  /** Frozen clock for deterministic tests; default Date.now()/1000. */
  now?: number;
  /** When provided, a different subject is WRONG_SUBJECT. */
  expectedSubject?: string;
  /** When provided, a different type is VC_TYPE_UNSUPPORTED. */
  expectedType?: CredentialType;
}

export interface VerifierDeps {
  didResolver: DidResolver;
  trustStore: IssuerTrustStore;
}

const CLAIMS_SCHEMA_BY_TYPE: Record<CredentialType, string> = {
  AgentMembershipCredential: SCHEMA_ID_MEMBERSHIP_CREDENTIAL_CLAIMS,
  AgentDelegationCredential: SCHEMA_ID_DELEGATION_CREDENTIAL_CLAIMS,
};

const BASE_TYPE = 'VerifiableCredential';

/**
 * Verification is a fixed-order pipeline; the first failing stage decides
 * the single deterministic reason code:
 *
 *  1. compact-JWS structure + profile (alg/kid/crit)  → VC_INVALID
 *  2. base claims shape                               → VC_SCHEMA_INVALID
 *  3. supported credential type                       → VC_TYPE_UNSUPPORTED
 *  4. per-type claims schema                          → VC_SCHEMA_INVALID
 *  5. issuer DID resolution                           → DID_RESOLUTION_FAILED
 *  6. kid belongs to the issuer DID                   → VC_ISSUER_KEY_MISMATCH
 *  7. signature over the received bytes               → VC_SIGNATURE_INVALID
 *  8. issuer trusted for this type                    → UNTRUSTED_ISSUER
 *  9. validFrom / validUntil                          → VC_NOT_YET_VALID / VC_EXPIRED
 * 10. expected subject                                → WRONG_SUBJECT
 *
 * A valid signature alone never equals trust — stages 8–10 exist precisely
 * because stages 1–7 prove integrity, not acceptance.
 */
export class CredentialVerifier {
  readonly #didResolver: DidResolver;
  readonly #trustStore: IssuerTrustStore;
  readonly #validator: Validator;

  constructor(deps: VerifierDeps) {
    this.#didResolver = deps.didResolver;
    this.#trustStore = deps.trustStore;
    this.#validator = createValidator();
  }

  async verify(jws: string, opts: VerifyOptions = {}): Promise<VcVerification> {
    const now = opts.now ?? Math.floor(Date.now() / 1000);

    // Stage 1 — compact JWS structure and JOSE profile.
    let parsed;
    try {
      parsed = parseCompactJws(jws);
    } catch (e) {
      if (e instanceof JwsFormatError) return deny('VC_INVALID');
      throw e;
    }

    // Stage 2 — base claims shape.
    const payload = decodeJwsPayload(parsed);
    const claims = payload as Partial<CredentialClaims>;
    if (
      typeof claims.iss !== 'string' ||
      typeof claims.sub !== 'string' ||
      typeof claims.jti !== 'string' ||
      typeof claims.nbf !== 'number' ||
      typeof claims.vc !== 'object' ||
      claims.vc === null ||
      !Array.isArray(claims.vc.type) ||
      typeof claims.vc.credentialSubject !== 'object' ||
      claims.vc.credentialSubject === null ||
      typeof claims.vc.credentialSubject.id !== 'string'
    ) {
      return deny('VC_SCHEMA_INVALID');
    }

    // Stage 3 — closed set of supported credential types.
    const concreteTypes = claims.vc.type.filter((t) => t !== BASE_TYPE);
    if (concreteTypes.length !== 1) return deny('VC_TYPE_UNSUPPORTED');
    const credentialType = concreteTypes[0] as CredentialType;
    if (!(SUPPORTED_CREDENTIAL_TYPES as readonly string[]).includes(credentialType)) {
      return deny('VC_TYPE_UNSUPPORTED');
    }
    if (opts.expectedType !== undefined && opts.expectedType !== credentialType) {
      return deny('VC_TYPE_UNSUPPORTED');
    }

    // Stage 4 — per-type claims schema.
    const outcome = this.#validator.validate(CLAIMS_SCHEMA_BY_TYPE[credentialType], payload);
    if (!outcome.valid) return deny('VC_SCHEMA_INVALID');

    // Stage 5 — issuer DID resolution.
    const resolution = await this.#didResolver.resolve(claims.iss);
    if (!resolution.didDocument) return deny('DID_RESOLUTION_FAILED');

    // Stage 6 — the signing kid must name a verification method of the issuer.
    const kid = parsed.protectedHeader.kid as string;
    const { did: kidDid } = parseDidUrl(kid);
    if (kidDid !== claims.iss) return deny('VC_ISSUER_KEY_MISMATCH');
    const method = resolution.didDocument.verificationMethod?.find((m) => m.id === kid);
    if (!method || !method.publicKeyJwk) return deny('VC_ISSUER_KEY_MISMATCH');

    // Stage 7 — signature over the exact received bytes.
    if (!verifyCompactJwsSignature(parsed, method.publicKeyJwk as PublicJwk)) {
      return deny('VC_SIGNATURE_INVALID');
    }

    // Stage 8 — issuer trust for this credential type.
    if (!(await this.#trustStore.isTrusted(claims.iss, credentialType))) {
      return deny('UNTRUSTED_ISSUER');
    }

    // Stage 9 — temporal validity.
    if (now < claims.nbf) return deny('VC_NOT_YET_VALID');
    if (claims.exp !== undefined && now >= claims.exp) return deny('VC_EXPIRED');

    // Stage 10 — expected subject.
    if (opts.expectedSubject !== undefined && opts.expectedSubject !== claims.sub) {
      return deny('WRONG_SUBJECT');
    }

    return { valid: true, facts: buildFacts(credentialType, claims as CredentialClaims), claims: claims as CredentialClaims };
  }
}

function deny(reasonCode: ReasonCode): VcVerification {
  return { valid: false, reasonCodes: [reasonCode] };
}

function buildFacts(credentialType: CredentialType, claims: CredentialClaims): VerifiedFacts {
  const facts: VerifiedFacts = {
    credentialValid: true,
    issuerTrusted: true,
    credentialId: claims.jti,
    credentialType,
    issuerDid: claims.iss,
    subjectDid: claims.sub,
    validFrom: claims.nbf,
    ...(claims.exp !== undefined ? { validUntil: claims.exp } : {}),
  };
  if (credentialType === 'AgentDelegationCredential') {
    facts.authority = claims.vc.credentialSubject.authority as Authority;
  } else {
    const { id: _id, controller, organization, runtimeBinding } =
      claims.vc.credentialSubject as Record<string, unknown>;
    facts.membership = {
      ...(controller !== undefined ? { controller: controller as string } : {}),
      ...(organization !== undefined ? { organization: organization as string } : {}),
      ...(runtimeBinding !== undefined ? { runtimeBinding: runtimeBinding as string } : {}),
    };
  }
  return facts;
}
