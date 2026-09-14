import type { PublicJwk } from '@agent-trust/crypto';
import { jwkThumbprint } from '@agent-trust/crypto';

import type { DidDocument, DidResolutionResult, DidResolver } from './types.js';

/**
 * Build a minimal DID document exposing one JsonWebKey2020 verification
 * method. Fixture/tests helper — the fragment is the RFC 7638 thumbprint,
 * matching LocalSigner/withDid keyIds so kid lookup is stable.
 */
export function didDocumentForJwk(did: string, jwk: PublicJwk): DidDocument {
  const methodId = `${did}#${jwkThumbprint(jwk)}`;
  return {
    '@context': 'https://www.w3.org/ns/did/v1',
    id: did,
    verificationMethod: [
      { id: methodId, type: 'JsonWebKey2020', controller: did, publicKeyJwk: jwk },
    ],
    authentication: [methodId],
  };
}

/**
 * Test/demo resolver: a pre-registered map of DID documents. Implements the
 * same DidResolver seam as did:key/did:web so verification code never knows
 * where a document came from. Unregistered DIDs resolve to notFound —
 * never a thrown error.
 */
export class InMemoryDidResolver implements DidResolver {
  readonly #docs = new Map<string, DidDocument>();

  constructor(docs: Iterable<DidDocument> = []) {
    for (const doc of docs) this.register(doc);
  }

  register(doc: DidDocument): void {
    this.#docs.set(doc.id, doc);
  }

  supports(did: string): boolean {
    return this.#docs.has(did);
  }

  async resolve(did: string): Promise<DidResolutionResult> {
    const didDocument = this.#docs.get(did);
    if (!didDocument) {
      return { didDocument: null, didResolutionMetadata: { error: 'notFound' } };
    }
    return {
      didDocument,
      didResolutionMetadata: { contentType: 'application/did+json' },
    };
  }
}
