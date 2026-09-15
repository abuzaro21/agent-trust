import { NextResponse } from 'next/server';

import { identityMode } from '@/server/identity';
import { demoWorld } from '@/server/world';

/**
 * GET /api/demo/status — honest infrastructure labels for the demo, plus
 * the live identity set (public DIDs only — never keys) and the build
 * identity so reviewers can correlate the live demo with a GitHub commit
 * (Step 16G/16O). Readiness endpoint: builds the world on demand, so it
 * reports REAL configuration, not just env-var presence.
 */
export async function GET(): Promise<NextResponse> {
  try {
    const w = await demoWorld();
    return NextResponse.json({
      identityMode: w.identityMode,
      dids: w.dids,
      replayStore: w.replayStoreKind,
      executor: 'Demo Refund Executor (simulation — no real payment movement)',
      policy: 'embedded OPA Wasm (committed, hash-pinned artifact)',
      audit: 'hash-chained receipts + signed checkpoint (in-memory demo store)',
      environment:
        'Challenge Demo Environment — single app replica; audit/demo state resets on restart; replay claims persist while Redis is configured',
      clock: 'frozen demo clock 2026-09-15T12:00:00Z',
      build: {
        sha: process.env.DEMO_BUILD_SHA ?? 'dev',
        version: '1.0.0',
      },
    });
  } catch (e) {
    let mode = 'unknown';
    try {
      mode = identityMode();
    } catch {
      /* invalid DEMO_IDENTITY_MODE surfaces in detail below */
    }
    return NextResponse.json(
      {
        error: 'STATUS_UNAVAILABLE',
        identityMode: mode,
        detail: e instanceof Error ? e.message : String(e),
      },
      { status: 503 },
    );
  }
}
