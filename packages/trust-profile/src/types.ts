import type { ReasonCode } from '@agent-trust/schemas';
import type { AgentAttestation, CredentialType } from '@agent-trust/vc';

/**
 * Read-model seams (Step 11C). The profile service answers "WHAT verified
 * evidence exists for this agent" — so its inputs are the credential JWSs
 * the SUBJECT (or its controller) registered, each of which is then pushed
 * through the FULL CredentialVerifier. Registration never trusts: a store
 * entry is only a pointer to bytes to verify.
 */

/** Credentials registered as pertaining to one agent subject. */
export interface AttestationStore {
  /** All attestation credentials registered for this subject DID. */
  listForSubject(subjectDid: string): Promise<string[]>;
}

/** Delegation (authority) credentials registered for one agent subject. */
export interface AgentCredentialStore {
  listForSubject(subjectDid: string): Promise<string[]>;
}

/**
 * Profile-level issuer trust for attestations, scoped by ISSUER + TYPE.
 * Trusting an auditor for SECURITY_REVIEW says nothing about
 * CAPABILITY_ENDORSEMENT from the same issuer — the scoping is the point.
 * Deliberately separate from the credential IssuerTrustStore: an issuer
 * trusted to sign delegations is not automatically trusted to attest.
 */
export interface AttestationTrustPolicy {
  isTrusted(issuerDid: string, attestationType: AgentAttestation['type']): Promise<boolean>;
}

export class InMemoryAttestationTrustPolicy implements AttestationTrustPolicy {
  readonly #trusted = new Set<string>();

  trust(issuerDid: string, attestationType: AgentAttestation['type']): this {
    this.#trusted.add(`${issuerDid}|${attestationType}`);
    return this;
  }

  revoke(issuerDid: string, attestationType: AgentAttestation['type']): this {
    this.#trusted.delete(`${issuerDid}|${attestationType}`);
    return this;
  }

  async isTrusted(issuerDid: string, attestationType: AgentAttestation['type']): Promise<boolean> {
    return this.#trusted.has(`${issuerDid}|${attestationType}`);
  }
}

export interface InMemoryStoreOptions {
  /** Fixed clock (unix seconds) for deterministic expiresAt sweeps. */
  clock?: () => number;
}

/**
 * Registration is keyed by the SUBJECT DID WRITTEN INTO the credential —
 * never by a caller-supplied label. A Sybil minting 100 self-vouches
 * registers them under its own DID; they can never attach to another
 * agent's profile, and count ≠ trust anyway (Step 11Y).
 */
export class InMemoryAttestationStore implements AttestationStore {
  readonly #bySubject = new Map<string, string[]>();
  readonly #expiresAt = new Map<string, number>();
  readonly #clock: () => number;

  constructor(opts: InMemoryStoreOptions = {}) {
    this.#clock = opts.clock ?? (() => Math.floor(Date.now() / 1000));
  }

  async add(subjectDid: string, jws: string, opts: { expiresAt?: number } = {}): Promise<void> {
    const list = this.#bySubject.get(subjectDid) ?? [];
    list.push(jws);
    this.#bySubject.set(subjectDid, list);
    if (opts.expiresAt !== undefined) this.#expiresAt.set(jws, opts.expiresAt);
  }

  async listForSubject(subjectDid: string): Promise<string[]> {
    const now = this.#clock();
    const list = this.#bySubject.get(subjectDid) ?? [];
    const fresh = list.filter((jws) => (this.#expiresAt.get(jws) ?? Infinity) > now);
    if (fresh.length !== list.length) this.#bySubject.set(subjectDid, fresh);
    return [...fresh];
  }
}

export class InMemoryAgentCredentialStore implements AgentCredentialStore {
  readonly #bySubject = new Map<string, string[]>();
  readonly #expiresAt = new Map<string, number>();
  readonly #clock: () => number;

  constructor(opts: InMemoryStoreOptions = {}) {
    this.#clock = opts.clock ?? (() => Math.floor(Date.now() / 1000));
  }

  async add(subjectDid: string, jws: string, opts: { expiresAt?: number } = {}): Promise<void> {
    const list = this.#bySubject.get(subjectDid) ?? [];
    list.push(jws);
    this.#bySubject.set(subjectDid, list);
    if (opts.expiresAt !== undefined) this.#expiresAt.set(jws, opts.expiresAt);
  }

  async listForSubject(subjectDid: string): Promise<string[]> {
    const now = this.#clock();
    const list = this.#bySubject.get(subjectDid) ?? [];
    const fresh = list.filter((jws) => (this.#expiresAt.get(jws) ?? Infinity) > now);
    if (fresh.length !== list.length) this.#bySubject.set(subjectDid, fresh);
    return [...fresh];
  }
}

/** Context in which the profile is being read — presentation only. */
export interface ProfileContext {
  action?: string;
  resource?: string;
  audience?: string;
}

export type TrustProfile = {
  agent: { did: string; controller?: string };
  generatedAt: string;
  context?: ProfileContext;
  identity: { resolved: boolean; verificationMethodCount?: number };
  authority: {
    active: {
      credentialId: string;
      issuer: string;
      actions: string[];
      resources: string[];
      audience?: string[];
      limits?: { amount?: number; currency?: string; perDay?: number };
      validUntil?: string;
      evidenceDigest: string;
      applicable: boolean;
    }[];
  };
  credentials: { active: number; suspended: number; revoked: number };
  attestations: {
    trusted: {
      credentialId: string;
      issuer: string;
      type: AgentAttestation['type'];
      statement: AgentAttestation['statement'];
      domain: string;
      validUntil?: string;
    }[];
    rejected: {
      credentialId?: string;
      issuer?: string;
      reasonCodes: ReasonCode[];
    }[];
  };
  history: {
    integrity:
      | { verified: true; verifiedThroughSequence: number; checkpointId?: string; checkpointHeadHash?: string }
      | { verified: false; detail?: string };
    byAction: Record<
      string,
      {
        decisions: { allow: number; deny: number };
        execution: { succeeded: number; failed: number; uncertain: number };
        reasonCodes: Record<string, number>;
        lastObservedAt?: string;
      }
    >;
  };
};

/** CredentialType narrowing that keeps the ATTESTATION_TYPE_UNSUPPORTED branch total. */
export function asCredentialType(t: string): CredentialType | null {
  return (t === 'AgentMembershipCredential' ||
    t === 'AgentDelegationCredential' ||
    t === 'AgentAttestationCredential')
    ? t
    : null;
}
