import type { PublicJwk } from '@agent-trust/crypto';

/** The subset of a W3C DID Document this fabric consumes. */
export interface VerificationMethod {
  /** DID URL, e.g. did:key:z6Mk...#<thumbprint> */
  id: string;
  type: string;
  controller: string;
  publicKeyJwk?: PublicJwk;
}

export interface DidDocument {
  '@context'?: string | string[];
  id: string;
  verificationMethod?: VerificationMethod[];
  authentication?: (string | VerificationMethod)[];
}

export type DidResolutionError =
  | 'invalidDid'
  | 'notFound'
  | 'representationNotSupported'
  | 'methodUnsupported'
  | 'internalError'
  | (string & {});

export interface DidResolutionMetadata {
  error?: DidResolutionError;
  contentType?: string;
  message?: string;
}

export interface DidResolutionResult {
  didDocument: DidDocument | null;
  didResolutionMetadata: DidResolutionMetadata;
}

/**
 * Frozen seam (ADR-0001): no core code path may reference a concrete DID
 * method — only this interface. P0 ships did:key and did:web; P1 adds
 * did:webvh as another implementation of exactly this shape.
 */
export interface DidResolver {
  supports(did: string): boolean;
  resolve(did: string): Promise<DidResolutionResult>;
}

/** Split a DID URL like did:key:z6Mk...#fragment into its parts. */
export function parseDidUrl(url: string): { did: string; fragment: string | undefined } {
  const hashIndex = url.indexOf('#');
  if (hashIndex === -1) return { did: url, fragment: undefined };
  return { did: url.slice(0, hashIndex), fragment: url.slice(hashIndex + 1) };
}

const DID_PATTERN = /^did:[a-z0-9]+:[^\s#]+$/;

export function isDid(value: string): boolean {
  return DID_PATTERN.test(value);
}
