/**
 * Request-parameter gate (runs right after the task schema, before any
 * crypto, replay claim or audit write). Receipts and VerifiedFacts only
 * admit `{ amount > 0, currency: 3 uppercase letters }`, so values that
 * can never be recorded or evaluated are refused here instead of reaching
 * the audit chain.
 *
 * `refund:create` is the protected P0 action: amount and currency are
 * REQUIRED and no other parameter is accepted. Other actions keep their
 * existing behavior (no required parameters); only the typed fields are
 * range-checked when present.
 */
const REFUND_ACTION = 'refund:create';
const CURRENCY = /^[A-Z]{3}$/;

export function validateActionParameters(action: string, parameters: unknown): string | undefined {
  const isRefund = action === REFUND_ACTION;
  if (parameters === undefined) {
    return isRefund ? 'refund:create requires amount and currency' : undefined;
  }
  if (typeof parameters !== 'object' || parameters === null || Array.isArray(parameters)) {
    return 'parameters must be an object';
  }
  const p = parameters as Record<string, unknown>;
  if (isRefund) {
    const extra = Object.keys(p).filter((k) => k !== 'amount' && k !== 'currency');
    if (extra.length > 0) return `unexpected refund parameter(s): ${extra.join(', ')}`;
    if (!('amount' in p) || !('currency' in p)) return 'refund:create requires amount and currency';
  }
  if ('amount' in p && (typeof p.amount !== 'number' || !Number.isFinite(p.amount) || p.amount <= 0)) {
    return 'amount must be a positive finite number';
  }
  if ('currency' in p && (typeof p.currency !== 'string' || !CURRENCY.test(p.currency))) {
    return 'currency must be a 3-letter uppercase code';
  }
  return undefined;
}
