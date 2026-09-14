import type { CredentialType } from './types.js';

/**
 * Issuer trust seam. A cryptographically perfect credential from an issuer
 * this registry does not list for that credential type is UNTRUSTED_ISSUER
 * — signature validity and trust are separate decisions, exactly as the
 * W3C model separates them. In-memory now; Postgres-backed later behind
 * the same interface.
 */
export interface IssuerTrustStore {
  isTrusted(issuerDid: string, credentialType: CredentialType): Promise<boolean>;
}

export class InMemoryIssuerTrustStore implements IssuerTrustStore {
  readonly #trusted = new Set<string>();

  /** Trust one issuer for one credential type. */
  trust(issuerDid: string, credentialType: CredentialType): this {
    this.#trusted.add(`${issuerDid}|${credentialType}`);
    return this;
  }

  revoke(issuerDid: string, credentialType: CredentialType): this {
    this.#trusted.delete(`${issuerDid}|${credentialType}`);
    return this;
  }

  async isTrusted(issuerDid: string, credentialType: CredentialType): Promise<boolean> {
    return this.#trusted.has(`${issuerDid}|${credentialType}`);
  }
}
