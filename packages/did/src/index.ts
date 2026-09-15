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

export {
  WebDidResolver,
  didWebToUrl,
  parseDidWebIdentifier,
  validateDidWebDocument,
  validatePublicJwk,
  cacheMaxAgeSeconds,
  type DidWebCacheEntry,
  type DidWebResolverOptions,
  type ResolveOptions,
} from './did-web.js';

export {
  DidWebTransportError,
  NodeHttpsDidWebClient,
  assertDestinationAllowed,
  classifyAddress,
  parseIpv6,
  type AddressVerdict,
  type DidWebDnsLookup,
  type DidWebFetchOptions,
  type DidWebHttpClient,
  type DidWebHttpResponse,
  type DidWebNetworkPolicy,
  type NodeHttpsClientOptions,
} from './did-web-transport.js';

export { InMemoryDidResolver, didDocumentForJwk } from './in-memory.js';

export { MultiDidResolver } from './registry.js';
