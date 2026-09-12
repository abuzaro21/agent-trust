/**
 * EC P-256 public key in JWK form — the only key material this fabric
 * publishes. Structurally assignable to the standard JsonWebKey type.
 */
export interface PublicJwk {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
}

/**
 * Frozen key-custody abstraction (ADR / architecture). Private material
 * never leaves a Signer implementation — P0 ships LocalSigner for tests
 * and the protected demo; P1 adds a Cloud KMS/HSM signer behind the same
 * interface with zero changes to VC/delegation/policy code.
 */
export interface Signer {
  /** DID URL of this signer's verification method (did#fragment). */
  keyId(): Promise<string>;
  /** Public key in JWK form (safe to publish). */
  publicKey(): Promise<PublicJwk>;
  /** ES256 signature over raw bytes. */
  sign(data: Uint8Array): Promise<Uint8Array>;
}
