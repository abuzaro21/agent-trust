/**
 * examples/check-trust.ts — the whole thesis in 20 lines.
 *
 *   corepack pnpm exec tsx examples/check-trust.ts
 *
 * A legitimate agent asks to refund 120 SAR → ALLOW.
 * The SAME agent, SAME credential, asks for 5000 SAR → DENY.
 * The decision never came from reputation: it is this specific action,
 * in this scope, right now. (Deterministic in-memory world — no network.)
 */
import { buildAttackWorld, SUPPORT_DID, REFUND_DID, NOW } from '@agent-trust/attacks';
import { createTaskRequest } from '@agent-trust/gateway';

const world = await buildAttackWorld(); // the real gateway + full pipeline

async function refund(amount: number, tag: string): Promise<string> {
  const request = await createTaskRequest({
    signer: world.supportSigner,
    taskId: `example-${tag}-${Math.random().toString(36).slice(2, 8)}`,
    actor: SUPPORT_DID,
    audience: REFUND_DID,
    action: 'refund:create',
    resource: 'order:ORD-1',
    parameters: { amount, currency: 'SAR' },
    credentials: [world.delegationJws],
    now: NOW,
  });
  const result = await world.gateway.handleTask(request);
  return `${result.outcome} ${result.effect ?? ''} [${result.reasonCodes.join(', ')}]`;
}

console.log('refund  120 SAR →', await refund(120, 'ok')); // AUTHORIZED ALLOW
console.log('refund 5000 SAR →', await refund(5000, 'over')); // DENIED DENY AUTHORITY_LIMIT_EXCEEDED
