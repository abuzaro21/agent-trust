import { NextResponse } from 'next/server';

import { identityMode } from '@/server/identity';

/**
 * STEP 16N — lightweight production liveness. NEVER runs a trust
 * transaction and never builds the demo world (a cold did:web resolution
 * may take seconds); it reports only static, non-sensitive deployment
 * identity. Dependency readiness is the /api/demo/status endpoint's job.
 */
export function GET(): NextResponse {
  let identity: string;
  try {
    identity = identityMode();
  } catch (e) {
    return NextResponse.json(
      { status: 'misconfigured', detail: e instanceof Error ? e.message : String(e) },
      { status: 503 },
    );
  }
  return NextResponse.json({
    status: 'ok',
    identityMode: identity,
    build: {
      sha: process.env.DEMO_BUILD_SHA ?? 'dev',
      version: '1.0.0',
    },
  });
}
