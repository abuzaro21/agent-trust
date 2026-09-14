export type { PublicJwk, Signer } from './types.js';
export {
  LocalSigner,
  jwkThumbprint,
} from './local-signer.js';
export {
  base64urlDecode,
  base64urlEncode,
  bytesEqual,
  canonicalJson,
  sha256,
  sha256Hex,
  stripUndefined,
  utf8,
} from './helpers.js';
export { verifyEs256 } from './verify.js';
export { ecdsaDerToRaw, ecdsaRawToDer } from './ecdsa-sig.js';
export { withDid } from './signer-with-did.js';
export {
  type ProofBinding,
  type ProofFailure,
  type ProofVerification,
  canonicalProofBinding,
  createProof,
  requestBodyDigestOf,
  verifyProof,
} from './proof.js';
