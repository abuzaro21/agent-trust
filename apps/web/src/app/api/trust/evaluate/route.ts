import { NextResponse } from 'next/server';

import { runCustom, runPreset, toDecisionDto, toReceiptDto, type CustomRunInput, type PresetId } from '@/server/world';

/**
 * POST /api/trust/evaluate — THIN adapter (14T). It calls the real
 * TrustGateway via the demo world; no verification, delegation, or
 * policy logic exists in this route or anywhere in the frontend.
 */
const PRESETS = new Set<PresetId>([
  'valid-120',
  'over-5000',
  'spoof',
  'revoked',
  'replay',
  'quarantine',
  'wrong-audience',
  'tampered',
]);

export async function POST(request: Request): Promise<NextResponse> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'REQUEST_MALFORMED', detail: 'invalid JSON body' }, { status: 400 });
  }
  const input = body as { preset?: string } & CustomRunInput;
  try {
    if (input.preset !== undefined) {
      if (!PRESETS.has(input.preset as PresetId)) {
        return NextResponse.json({ error: 'REQUEST_MALFORMED', detail: `unknown preset: ${input.preset}` }, { status: 400 });
      }
      const outcome = await runPreset(input.preset as PresetId);
      return NextResponse.json({
        result: toDecisionDto(outcome.result),
        ...(outcome.firstResult !== undefined ? { firstResult: toDecisionDto(outcome.firstResult) } : {}),
        runReceipts: outcome.runReceipts.map(toReceiptDto),
        ...(outcome.note !== undefined ? { note: outcome.note } : {}),
      });
    }
    const outcome = await runCustom(input);
    return NextResponse.json({
      result: toDecisionDto(outcome.result),
      runReceipts: outcome.runReceipts.map(toReceiptDto),
      ...(outcome.note !== undefined ? { note: outcome.note } : {}),
    });
  } catch (e) {
    // Infrastructure failures surface their machine reason — never a
    // generic "something went wrong" (14X).
    return NextResponse.json(
      { error: 'GATEWAY_UNAVAILABLE', detail: e instanceof Error ? e.message : String(e) },
      { status: 503 },
    );
  }
}
