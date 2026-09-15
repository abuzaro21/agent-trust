import { NextResponse } from 'next/server';

import { profileSnapshot } from '@/server/world';

/** GET /api/agents/:did/profile — renders the REAL Step 11 TrustProfile. */
export async function GET(
  _request: Request,
  context: { params: Promise<{ did: string }> },
): Promise<NextResponse> {
  try {
    const { did } = await context.params;
    const snapshot = await profileSnapshot(did);
    return NextResponse.json(snapshot);
  } catch (e) {
    return NextResponse.json(
      { error: 'PROFILE_UNAVAILABLE', detail: e instanceof Error ? e.message : String(e) },
      { status: 503 },
    );
  }
}
