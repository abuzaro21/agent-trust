import { EventEmitter } from 'node:events';

import { beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * Socket-level pinning test for the DEFAULT did:web request primitive.
 *
 * The attack scenarios inject the request primitive, so they cannot see how the
 * production `https.get` call is configured. A DNS-rebinding defence only holds
 * if the socket (a) connects to the address that was VALIDATED and (b) cannot
 * trigger a second resolution. This test mocks `node:https` and inspects the
 * options the real transport hands to it. No network is touched.
 */

type GetOptions = {
  host: string;
  servername: string;
  lookup: (hostname: string, o: unknown, cb: (err: Error | null, address?: string, family?: number) => void) => void;
};
const captured: GetOptions[] = [];

vi.mock('node:https', () => ({
  get: (options: GetOptions, onResponse: (res: unknown) => void) => {
    captured.push(options);
    const req = new EventEmitter() as EventEmitter & { destroy: (e?: Error) => void };
    req.destroy = () => undefined;
    queueMicrotask(() => {
      const res = Object.assign((async function* () {})(), { statusCode: 200, headers: {} });
      onResponse(res);
    });
    return req;
  },
}));

import { NodeHttpsDidWebClient } from '@agent-trust/did';

beforeEach(() => {
  captured.length = 0;
});

describe('default did:web request primitive pins the validated address', () => {
  it('connects to the validated IP, keeps the hostname only for TLS SNI, and forces the socket lookup to the validated IP', async () => {
    let lookups = 0;
    const client = new NodeHttpsDidWebClient({
      // DNS rebinding race: public on the first answer, private on any later one.
      dnsLookup: async () => {
        lookups += 1;
        return lookups === 1 ? [{ address: '93.184.216.34', family: 4 }] : [{ address: '10.0.0.5', family: 4 }];
      },
    });
    await client.get(new URL('https://trust.example.com/did.json'), { timeoutMs: 1000, maxBytes: 1024 });

    expect(lookups).toBe(1);
    expect(captured).toHaveLength(1);
    const options = captured[0]!;
    expect(options.host).toBe('93.184.216.34'); // NOT the hostname (a hostname would be re-resolved by the socket)
    expect(options.servername).toBe('trust.example.com');
    // Even if the socket layer asked to resolve a name, the pinned lookup answers with the validated address.
    const answer = await new Promise<{ address?: string; family?: number }>((resolve, reject) =>
      options.lookup('trust.example.com', {}, (err, address, family) => (err ? reject(err) : resolve({ address, family }))),
    );
    expect(answer).toEqual({ address: '93.184.216.34', family: 4 });
  });
});
