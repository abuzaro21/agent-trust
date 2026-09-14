export type {
  DidDocument,
  DidResolutionError,
  DidResolutionMetadata,
  DidResolutionResult,
  DidResolver,
  VerificationMethod,
} from './types.js';
export { isDid, parseDidUrl } from './types.js';

export { base58btcDecode, base58btcEncode, varintDecode, varintEncode } from './multibase.js';

export {
  DidKeyResolver,
  didKeyDocument,
  didKeyFromPublicKeyJwk,
  publicKeyJwkFromDidKey,
} from './did-key.js';

export { DidWebResolver, didWebToUrl } from './did-web.js';

export { InMemoryDidResolver, didDocumentForJwk } from './in-memory.js';

export { MultiDidResolver } from './registry.js';
