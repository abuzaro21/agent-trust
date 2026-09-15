import { describe, expect, it } from 'vitest';

import { explainReason, shortHash, stagesToView } from '../src/lib/presentation';

/**
 * Presentation-layer tests: stage mapping from GatewayResult (never
 * inferred from reason codes), text-alongside-color status, and the
 * static reason explainers.
 */

const ALLOW_STAGES = {
  identity: 'PASS',
  replay: 'PASS',
  credential: 'PASS',
  authority: 'PASS',
  policy: 'ALLOW',
  audit: 'PASS',
  execution: 'SUCCEEDED',
};

const DENY_STAGES = {
  identity: 'PASS',
  replay: 'PASS',
  credential: 'PASS',
  authority: 'PASS',
  policy: 'DENY',
  audit: 'PASS',
  execution: 'NOT_RUN',
};

describe('stagesToView (renders backend stages verbatim)', () => {
  it('ALLOW: all ok, in pipeline order', () => {
    const views = stagesToView(ALLOW_STAGES);
    expect(views.map((v) => v.key)).toEqual([
      'identity',
      'credential',
      'authority',
      'replay',
      'policy',
      'audit',
      'execution',
    ]);
    expect(views.every((v) => v.tone === 'ok')).toBe(true);
  });

  it('DENY: policy deny, execution NOT_RUN renders as neutral dash', () => {
    const views = stagesToView(DENY_STAGES);
    const policy = views.find((v) => v.key === 'policy')!;
    const execution = views.find((v) => v.key === 'execution')!;
    expect(policy.tone).toBe('deny');
    expect(execution.value).toBe('—');
    expect(execution.tone).toBe('neutral');
  });

  it('every stage carries TEXT alongside color (status never color-only)', () => {
    for (const v of stagesToView(ALLOW_STAGES)) {
      expect(typeof v.value).toBe('string');
      expect(v.value.length).toBeGreaterThan(0);
    }
  });

  it('EXECUTION_UNCERTAIN renders as warn', () => {
    const views = stagesToView({ ...ALLOW_STAGES, execution: 'EXECUTION_UNCERTAIN' });
    expect(views.find((v) => v.key === 'execution')!.tone).toBe('warn');
  });
});

describe('explainReason (static help text only)', () => {
  it('AUTHORITY_LIMIT_EXCEEDED cites requested vs delegated amounts', () => {
    expect(explainReason('AUTHORITY_LIMIT_EXCEEDED', { amount: 5000, limit: 500 })).toContain('5000');
  });
  it('unknown code falls back to the code itself (never invents a story)', () => {
    expect(explainReason('SOMETHING_NEW')).toBe('SOMETHING_NEW');
  });
});

describe('shortHash', () => {
  it('abbreviates long hex digests', () => {
    const h = shortHash('c02483106fa17c23c1c817398b98388b49c601e9054f3beb0031f40dd548eea8');
    expect(h).toBe("c0248310…eea8");
  });
});
