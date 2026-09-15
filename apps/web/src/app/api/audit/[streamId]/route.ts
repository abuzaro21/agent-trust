import { NextResponse } from 'next/server';

import { auditSnapshot, toReceiptDto } from '@/server/world';

/** GET /api/audit/:streamId — receipts + chain/checkpoint verification. */
export async function GET(): Promise<NextResponse> {
  try {
    const snapshot = await auditSnapshot();
    return NextResponse.json({
      receipts: snapshot.receipts.map(toReceiptDto),
      chain: snapshot.chain,
      checkpoint: snapshot.checkpoint,
    });
  } catch (e) {
    return NextResponse.json(
      { error: 'AUDIT_UNAVAILABLE', detail: e instanceof Error ? e.message : String(e) },
      { status: 503 },
    );
  }
}
