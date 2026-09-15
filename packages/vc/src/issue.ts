import type { Signer } from '@agent-trust/crypto';
import { withDid } from '@agent-trust/crypto';
import { parseDidUrl } from '@agent-trust/did';
import { randomUUID } from 'node:crypto';
import type { Authority } from '@agent-trust/schemas';

import { signCompactJws } from './jws.js';
import {
  type CredentialClaims,
  type TimeInput,
  toUnixSeconds,
} from './types.js';

export interface MembershipInput {
  subjectDid: string;
  controller?: string;
  organization?: string;
  /** e.g. spiffe://acme.prod/agents/refund-01 */
  runtimeBinding?: string;
  validFrom: TimeInput;
  validUntil?: TimeInput;
  /** Optional BitstringStatusListEntry binding (Step 6). */
  credentialStatus?: Record<string, unknown>;
}

export interface DelegationInput {
  subjectDid: string;
  authority: Authority;
  validFrom: TimeInput;
  validUntil?: TimeInput;
  /** Optional BitstringStatusListEntry binding (Step 6). */
  credentialStatus?: Record<string, unknown>;
}

export interface AttestationInput {
  subjectDid: string;
  attestation: import('./types.js').AgentAttestation;
  validFrom: TimeInput;
  validUntil?: TimeInput;
  /** Optional BitstringStatusListEntry binding — attestation revocation
   * reuses credential status, never a custom mechanism (Step 11S). */
  credentialStatus?: Record<string, unknown>;
}

/**
 * Issues compact-JWS credentials through the Signer seam. The signer's DID
 * labels the issuer; key material never leaves the Signer implementation.
 */
export class CredentialIssuer {
  readonly #signer: Signer;

  constructor(signer: Signer, opts: { issuerDid?: string } = {}) {
    this.#signer = opts.issuerDid !== undefined ? withDid(signer, opts.issuerDid) : signer;
  }

  async issueMembership(
    input: MembershipInput,
  ): Promise<{ jws: string; claims: CredentialClaims }> {
    const subject: Record<string, unknown> = { id: input.subjectDid };
    if (input.controller !== undefined) subject.controller = input.controller;
    if (input.organization !== undefined) subject.organization = input.organization;
    if (input.runtimeBinding !== undefined) subject.runtimeBinding = input.runtimeBinding;

    return this.issue({
      type: ['VerifiableCredential', 'AgentMembershipCredential'],
      credentialSubject: subject as CredentialClaims['vc']['credentialSubject'],
      subjectDid: input.subjectDid,
      validFrom: input.validFrom,
      validUntil: input.validUntil,
      credentialStatus: input.credentialStatus,
    });
  }

  async issueDelegation(
    input: DelegationInput,
  ): Promise<{ jws: string; claims: CredentialClaims }> {
    return this.issue({
      type: ['VerifiableCredential', 'AgentDelegationCredential'],
      credentialSubject: { id: input.subjectDid, authority: input.authority },
      subjectDid: input.subjectDid,
      validFrom: input.validFrom,
      validUntil: input.validUntil,
      credentialStatus: input.credentialStatus,
    });
  }

  async issueAttestation(
    input: AttestationInput,
  ): Promise<{ jws: string; claims: CredentialClaims }> {
    return this.issue({
      type: ['VerifiableCredential', 'AgentAttestationCredential'],
      credentialSubject: { id: input.subjectDid, attestation: input.attestation },
      subjectDid: input.subjectDid,
      validFrom: input.validFrom,
      validUntil: input.validUntil,
      credentialStatus: input.credentialStatus,
    });
  }

  async issue(input: {
    type: string[];
    credentialSubject: CredentialClaims['vc']['credentialSubject'];
    subjectDid: string;
    validFrom: TimeInput;
    validUntil?: TimeInput;
    credentialStatus?: Record<string, unknown>;
  }): Promise<{ jws: string; claims: CredentialClaims }> {
    const kid = await this.#signer.keyId();
    const issuerDid = parseDidUrl(kid).did;
    const nbf = toUnixSeconds(input.validFrom);
    const claims: CredentialClaims = {
      iss: issuerDid,
      sub: input.subjectDid,
      jti: `vc_${randomUUID()}`,
      nbf,
      ...(input.validUntil !== undefined ? { exp: toUnixSeconds(input.validUntil) } : {}),
      vc: {
        type: input.type,
        credentialSubject: input.credentialSubject,
        ...(input.credentialStatus !== undefined
          ? { credentialStatus: input.credentialStatus }
          : {}),
      },
    };
    const jws = await signCompactJws(this.#signer, claims as unknown as Record<string, unknown>);
    return { jws, claims };
  }
}
