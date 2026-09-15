import { NextResponse } from 'next/server';

import { didToRoute, identityMode, loadLiveIdentities } from '@/server/identity';

/**
 * STEP 16E — public did:web document serving (live mode only).
 *
 * When the deployment's DID host is THIS app (DEMO_DID_DOMAIN=<own host>),
 * the live documents are served at exactly the URLs the did:web method
 * derives from their identifiers: /agents/{org,support,refund}/did.json.
 * With an external identity host (e.g. GitHub Pages), this route still
 * mirrors the documents so both hosting paths resolve identically.
 *
 * Fixture mode has no public identities → 404.
 *
 * Response contains ONLY public material (id + verificationMethod +
 * controller + publicKeyJwk). Caching (Step 16F): bounded max-age so
 * emergency key rotation propagates quickly; the Step 12 resolver caps
 * its own cache lifetime at 10 min regardless of these headers.
 */
const DID_CACHE_CONTROL = 'public, max-age=300, stale-while-revalidate=60';

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ name: string }> },
): Promise<NextResponse> {
  try {
    if (identityMode() !== 'web') {
      return NextResponse.json({ error: 'NOT_FOUND' }, { status: 404 });
    }
    const live = await loadLiveIdentities();
    const wanted = `/agents/${(await params).name}/did.json`;
    for (const doc of live.documents) {
      if (didToRoute(doc.id) === wanted) {
        return NextResponse.json(doc, {
          headers: {
            'content-type': 'application/did+ld+json',
            'cache-control': DID_CACHE_CONTROL,
            'access-control-allow-origin': '*',
          },
        });
      }
    }
    return NextResponse.json({ error: 'NOT_FOUND' }, { status: 404 });
  } catch {
    // A misconfigured deployment must not 500 its identity surface.
    return NextResponse.json({ error: 'NOT_FOUND' }, { status: 404 });
  }
}
