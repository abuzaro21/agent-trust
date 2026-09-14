import { jwkThumbprint } from './local-signer.js';
import type { Signer } from './types.js';

/**
 * Present an existing signer under a concrete DID: keyId() becomes the DID
 * URL `<did>#<thumbprint>`, matching didDocumentForJwk fragments. Signing
 * and key material are untouched — this is identity labeling, not custody.
 */
export function withDid(signer: Signer, did: string): Signer {
  return {
    async keyId() {
      return `${did}#${jwkThumbprint(await signer.publicKey())}`;
    },
    publicKey() {
      return signer.publicKey();
    },
    sign(data) {
      return signer.sign(data);
    },
  };
}
