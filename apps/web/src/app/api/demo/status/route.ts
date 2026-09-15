import { NextResponse } from 'next/server';

import { demoWorld } from '@/server/world';

/** GET /api/demo/status — honest infrastructure labels for the demo. */
export async function GET(): Promise<NextResponse> {
  try {
    const w = await demoWorld();
    return NextResponse.json({
      replayStore: w.replayStoreKind,
      executor: 'Demo Refund Executor (simulation — no real payment movement)',
      policy: 'embedded OPA Wasm (committed, hash-pinned artifact)',
      audit: 'hash-chained receipts + signed checkpoint (in-memory demo store)',
      clock: 'frozen demo clock 2026-09-15T12:00:00Z',
    });
  } catch (e) {
    return NextResponse.json(
      { error: 'STATUS_UNAVAILABLE', detail: e instanceof Error ? e.message : String(e) },
      { status: 503 },
    );
  }
}
