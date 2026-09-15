import type { PublicJwk } from '@agent-trust/crypto';
import type { DidResolver } from '@agent-trust/did';
import { parseDidUrl } from '@agent-trust/did';
import {
  type Authority,
  type ReasonCode,
  SCHEMA_ID_ATTESTATION_CREDENTIAL_CLAIMS,
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
import type { AgentQuarantineStore, CredentialStatusChecker, CredentialStatusResult } from './status-seam.js';
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
  /**
   * Optional status gate (Step 6). When absent, credentials that DECLARE a
   * status mechanism are denied CREDENTIAL_STATUS_UNAVAILABLE — a declared
   * check we cannot run never passes silently.
   */
  statusChecker?: CredentialStatusChecker;
  /** Optional emergency kill switch (Step 6G), keyed by subject DID. */
  quarantineStore?: AgentQuarantineStore;
}

const CLAIMS_SCHEMA_BY_TYPE: Record<CredentialType, string> = {
  AgentMembershipCredential: SCHEMA_ID_MEMBERSHIP_CREDENTIAL_CLAIMS,
  AgentDelegationCredential: SCHEMA_ID_DELEGATION_CREDENTIAL_CLAIMS,
  AgentAttestationCredential: SCHEMA_ID_ATTESTATION_CREDENTIAL_CLAIMS,
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
 *  7b. quarantine of the VERIFIED subject             → AGENT_QUARANTINED
 *  8. issuer trusted for this credential type          → UNTRUSTED_ISSUER
 *  9. validFrom / validUntil                          → VC_NOT_YET_VALID / VC_EXPIRED
 * 10. expected subject                                → WRONG_SUBJECT
 * 11. credential status (when declared)               → CREDENTIAL_REVOKED /
 *     (stage 2b, before all of the above,                CREDENTIAL_SUSPENDED /
 *      is the quarantine kill switch on the              CREDENTIAL_STATUS_UNAVAILABLE
 *      caller-attested actor: expectedSubject)
 *
 * Quarantine identity binding (hardened in the Step 7 pre-check): the
 * early stage-2b check uses ONLY expectedSubject — an identity attested by
 * the trusted caller — never the raw credential subject, which is
 * attacker-chosen data until the signature verifies. The verified
 * credential subject is checked at stage 7b, after stage 7 proved the
 * signature. A forged credential therefore cannot learn or influence
 * quarantine state for any identity.
 *
 * A valid signature alone never equals trust — stages 8–11 exist precisely
 * because stages 1–7 prove integrity, not acceptance.
 */
export class CredentialVerifier {
  readonly #didResolver: DidResolver;
  readonly #trustStore: IssuerTrustStore;
  readonly #statusChecker: CredentialStatusChecker | undefined;
  readonly #quarantineStore: AgentQuarantineStore | undefined;
  readonly #validator: Validator;

  constructor(deps: VerifierDeps) {
    this.#didResolver = deps.didResolver;
    this.#trustStore = deps.trustStore;
    this.#statusChecker = deps.statusChecker;
    this.#quarantineStore = deps.quarantineStore;
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

    // Stage 2b — emergency quarantine kill switch on the CALLER-ATTESTED
    // actor. expectedSubject comes from trusted request context (e.g. the
    // PoP-verified actor DID), so it is a legitimate early identity. The
    // raw credential subject is unverified here and is deliberately NOT
    // consulted until stage 7b.
    if (this.#quarantineStore !== undefined && opts.expectedSubject !== undefined) {
      const quarantined = await this.#quarantineStore.isQuarantined(opts.expectedSubject);
      if (quarantined) return deny('AGENT_QUARANTINED');
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

    // Stage 7b — quarantine of the now CRYPTOGRAPHICALLY VERIFIED subject.
    // The subject is signature-bound to the issuer at this point, so this
    // decision no longer consumes attacker-chosen data.
    if (this.#quarantineStore !== undefined) {
      const quarantined = await this.#quarantineStore.isQuarantined(claims.sub);
      if (quarantined) return deny('AGENT_QUARANTINED');
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

    // Stage 11 — credential status gate. Only runs when the credential
    // DECLARES a status mechanism; credentials without credentialStatus
    // keep their pre-Step-6 behavior. Declared-but-uncheckable fails closed.
    const statusEntry = claims.vc.credentialStatus;
    if (statusEntry !== undefined) {
      if (this.#statusChecker === undefined) return deny('CREDENTIAL_STATUS_UNAVAILABLE');
      let result: CredentialStatusResult;
      try {
        result = await this.#statusChecker.check({
          credentialId: claims.jti,
          issuerDid: claims.iss,
          status: statusEntry,
          now,
        });
      } catch {
        return deny('CREDENTIAL_STATUS_UNAVAILABLE');
      }
      if (result.state === 'REVOKED') return deny('CREDENTIAL_REVOKED');
      if (result.state === 'SUSPENDED') return deny('CREDENTIAL_SUSPENDED');
      if (result.state !== 'ACTIVE') return deny('CREDENTIAL_STATUS_UNAVAILABLE');
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
  } else if (credentialType === 'AgentAttestationCredential') {
    const { id: _id, attestation } = claims.vc.credentialSubject as Record<string, unknown>;
    facts.attestation = attestation as VerifiedFacts['attestation'];
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
