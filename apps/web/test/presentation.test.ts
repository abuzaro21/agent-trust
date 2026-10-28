import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { ATTACK_REGISTRY } from '@agent-trust/attacks';

import type { DecisionDto, ProfileDto } from '../src/lib/dto';
import {
  FAILURE_SCENARIOS,
  LIFECYCLE,
  PIPELINE_STEPS,
  PRIMARY_SCENARIOS,
  amountMeter,
  explainReason,
  limitFromProfile,
  pipelineView,
  shortHash,
  stagesToView,
  stoppedAt,
  verdictFor,
} from '../src/lib/presentation';
import { POST as evaluate } from '../src/app/api/trust/evaluate/route';

/**
 * Presentation-layer tests: stage mapping from GatewayResult (never inferred
 * from reason codes), the REAL gateway order, reason-specific wording, and the
 * guarantee that the frontend decides nothing.
 */

const ALLOW_STAGES = { identity: 'PASS', replay: 'PASS', credential: 'PASS', authority: 'PASS', policy: 'ALLOW', audit: 'PASS', execution: 'SUCCEEDED' };
const POLICY_DENY_STAGES = { ...ALLOW_STAGES, policy: 'DENY', execution: 'NOT_RUN' };
const SPOOF_STAGES = { identity: 'FAIL', replay: 'NOT_RUN', credential: 'NOT_RUN', authority: 'NOT_RUN', policy: 'NOT_RUN', audit: 'NOT_RUN', execution: 'NOT_RUN' };

function decision(over: Partial<DecisionDto> & { stages?: DecisionDto['stages'] }): DecisionDto {
  return {
    taskId: 't1',
    outcome: 'DENIED',
    effect: 'DENY',
    reasonCodes: ['AUTHORITY_LIMIT_EXCEEDED'],
    stages: POLICY_DENY_STAGES,
    decisionReceiptId: 'rcpt_dec_t1',
    ...over,
  };
}

describe('pipeline order matches the real gateway', () => {
  it('flat view: identity → replay → credentials → delegation → policy → decision receipt → execution', () => {
    expect(stagesToView(ALLOW_STAGES).map((v) => v.key)).toEqual(['identity', 'replay', 'credential', 'authority', 'policy', 'audit', 'execution']);
  });

  it('eight steps in gateway order, grouped verification | policy | provenance', () => {
    expect(PIPELINE_STEPS.map((s) => s.key)).toEqual(['identity', 'replay', 'credential', 'delegation', 'policy', 'decisionReceipt', 'execution', 'outcomeReceipt']);
    const groups = pipelineView(decision({ outcome: 'AUTHORIZED', effect: 'ALLOW', reasonCodes: [], stages: ALLOW_STAGES, executionReceiptId: 'rcpt_out_t1' }));
    expect(groups.map((g) => g.id)).toEqual(['verification', 'policy', 'provenance']);
    expect(groups[0]!.steps.map((s) => s.key)).toEqual(['identity', 'replay', 'credential', 'delegation']);
    expect(groups[1]!.steps.map((s) => s.key)).toEqual(['policy']);
    expect(groups[2]!.steps.map((s) => s.key)).toEqual(['decisionReceipt', 'execution', 'outcomeReceipt']);
    const orders = groups.flatMap((g) => g.steps.map((s) => s.order));
    expect(orders).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });

  it('the delegation step never claims the amount is allowed (limit is enforced by policy)', () => {
    const delegation = PIPELINE_STEPS.find((s) => s.key === 'delegation')!;
    const policy = PIPELINE_STEPS.find((s) => s.key === 'policy')!;
    expect(delegation.label).toMatch(/verified/i);
    expect(delegation.detail).toMatch(/policy/i);
    expect(policy.detail).toMatch(/amount/i);
  });
});

describe('pipelineView renders backend stages verbatim', () => {
  it('ALLOW: every step ok, execution labelled simulated, outcome receipt recorded', () => {
    const groups = pipelineView(decision({ outcome: 'AUTHORIZED', effect: 'ALLOW', reasonCodes: [], stages: ALLOW_STAGES, executionReceiptId: 'rcpt_out_t1' }));
    const steps = groups.flatMap((g) => g.steps);
    expect(steps.every((s) => s.tone === 'ok')).toBe(true);
    expect(steps.find((s) => s.key === 'execution')!.value).toBe('SUCCEEDED (simulated)');
    expect(steps.find((s) => s.key === 'outcomeReceipt')!.value).toBe('RECORDED');
  });

  it('limit DENY: verification all pass, policy fails, later steps are not-run dashes', () => {
    const groups = pipelineView(decision({}));
    expect(groups[0]!.steps.every((s) => s.tone === 'ok')).toBe(true);
    expect(groups[1]!.steps[0]!.tone).toBe('deny');
    const exec = groups[2]!.steps.find((s) => s.key === 'execution')!;
    expect(exec.value).toBe('—');
    expect(exec.tone).toBe('neutral');
    expect(stoppedAt(groups)!.key).toBe('policy');
  });

  it('spoof: identity fails first and nothing after it ran', () => {
    const groups = pipelineView(decision({ reasonCodes: ['IDENTITY_PROOF_INVALID'], stages: SPOOF_STAGES, decisionReceiptId: undefined }));
    const steps = groups.flatMap((g) => g.steps);
    expect(stoppedAt(groups)!.key).toBe('identity');
    expect(steps.filter((s) => s.key !== 'identity').every((s) => s.tone === 'neutral')).toBe(true);
  });

  it('EXECUTION_UNCERTAIN outcome shows an unrecorded outcome receipt as a warning', () => {
    const groups = pipelineView(decision({ outcome: 'EXECUTION_UNCERTAIN', effect: 'ALLOW', reasonCodes: ['AUDIT_OUTCOME_UNRECORDED'], stages: { ...ALLOW_STAGES, execution: 'SUCCEEDED' } }));
    const out = groups.flatMap((g) => g.steps).find((s) => s.key === 'outcomeReceipt')!;
    expect(out.value).toBe('UNRECORDED');
    expect(out.tone).toBe('warn');
  });

  it('every step carries TEXT alongside colour (status is never colour-only)', () => {
    for (const s of pipelineView(decision({})).flatMap((g) => g.steps)) expect(s.value.length).toBeGreaterThan(0);
  });
});

describe('verdict and reason-specific messages', () => {
  it('ALLOW verdict', () => {
    const v = verdictFor(decision({ outcome: 'AUTHORIZED', effect: 'ALLOW', reasonCodes: [], stages: ALLOW_STAGES }));
    expect(v).toMatchObject({ kind: 'allow', tone: 'ok', headline: 'Authorized' });
  });

  it('limit denial cites the requested and delegated amounts', () => {
    const v = verdictFor(decision({}), { requested: 5000, limit: 500, currency: 'SAR' });
    expect(v.kind).toBe('deny');
    expect(v.sentence).toContain('5,000');
    expect(v.sentence).toContain('500');
  });

  it('unrelated denials never mention delegated limits or "exceeds"', () => {
    for (const code of ['IDENTITY_PROOF_INVALID', 'CREDENTIAL_REVOKED', 'REPLAY_DETECTED', 'AGENT_QUARANTINED', 'AUDIENCE_MISMATCH', 'UNTRUSTED_ISSUER', 'REQUEST_MALFORMED']) {
      const text = explainReason(code, { requested: 5000, limit: 500, currency: 'SAR' });
      expect(text, code).not.toMatch(/exceed|above the .* limit|delegated .* limit/i);
    }
  });

  it('each frequent denial has its own distinct, non-empty explanation', () => {
    const codes = ['AUTHORITY_LIMIT_EXCEEDED', 'ACTION_NOT_IN_SCOPE', 'AUTHORITY_EXPIRED', 'AUTHORITY_NOT_YET_VALID', 'CURRENCY_MISMATCH', 'IDENTITY_PROOF_INVALID', 'CREDENTIAL_REVOKED', 'REPLAY_DETECTED', 'AGENT_QUARANTINED', 'AUDIENCE_MISMATCH', 'POLICY_EVALUATION_ERROR'];
    const texts = codes.map((c) => explainReason(c));
    expect(new Set(texts).size).toBe(codes.length);
    expect(texts.every((t) => t.length > 20)).toBe(true);
  });

  it('REQUEST_MALFORMED describes input validation, not a missing credential', () => {
    expect(explainReason('REQUEST_MALFORMED')).toMatch(/validation/i);
    expect(explainReason('REQUEST_MALFORMED')).not.toMatch(/delegation credential is required/i);
  });

  it('a spoof is described as "not authenticated" and a valid signature is never called permission', () => {
    expect(explainReason('IDENTITY_PROOF_INVALID')).toMatch(/not authenticated/i);
    expect(explainReason('UNTRUSTED_ISSUER')).toMatch(/valid signature is not permission/i);
  });

  it('unknown code falls back to the code itself (never invents a story)', () => {
    expect(explainReason('SOMETHING_NEW')).toContain('SOMETHING_NEW');
    expect(explainReason(undefined)).toMatch(/no denial reason/i);
  });

  it('no copy claims external anchoring of the audit log', () => {
    const all = [...FAILURE_SCENARIOS.map((s) => s.proves + (s.note ?? '')), ...LIFECYCLE.map((s) => s.text)].join(' ');
    expect(all).not.toMatch(/anchored|blockchain|transparency log/i);
  });
});

describe('amount meter appears only for amount decisions', () => {
  const limitDeny = decision({});
  const spoof = decision({ reasonCodes: ['IDENTITY_PROOF_INVALID'], stages: SPOOF_STAGES });
  const allow = decision({ outcome: 'AUTHORIZED', effect: 'ALLOW', reasonCodes: [], stages: ALLOW_STAGES });

  it('shown for ALLOW and for AUTHORITY_LIMIT_EXCEEDED', () => {
    expect(amountMeter(allow, 120, 500)).toMatchObject({ percent: 24, tone: 'ok' });
    expect(amountMeter(limitDeny, 5000, 500)).toMatchObject({ percent: 100, tone: 'deny' });
  });
  it('hidden for unrelated denials and when the limit is unknown', () => {
    expect(amountMeter(spoof, 5000, 500)).toBeUndefined();
    expect(amountMeter(limitDeny, 5000, undefined)).toBeUndefined();
    expect(amountMeter(limitDeny, undefined, 500)).toBeUndefined();
  });
});

describe('limits come from the backend profile, not a constant', () => {
  const profile = (amount?: number): ProfileDto =>
    ({ profile: { authority: { active: [{ limits: amount === undefined ? undefined : { amount, currency: 'SAR' } }] } } }) as unknown as ProfileDto;
  it('reads the signed delegation limit', () => {
    expect(limitFromProfile(profile(750))).toEqual({ amount: 750, currency: 'SAR' });
    expect(limitFromProfile(profile(undefined))).toBeUndefined();
    expect(limitFromProfile(null)).toBeUndefined();
  });
});

describe('UI ↔ backend contract', () => {
  it('every preset the UI can request is accepted by the real evaluate route', async () => {
    const ids = new Set<string>([...PRIMARY_SCENARIOS.map((s) => s.id), ...FAILURE_SCENARIOS.map((s) => s.id), ...LIFECYCLE.flatMap((s) => (s.preset ? [s.preset] : []))]);
    expect(ids.size).toBeGreaterThanOrEqual(8);
    for (const id of ids) {
      const res = await evaluate(new Request('http://localhost/api/trust/evaluate', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ preset: id }) }));
      expect(res.status, id).toBe(200);
    }
  });

  it('lifecycle and failure cards point at real attack-suite scenarios', () => {
    const have = new Set(ATTACK_REGISTRY.map((s) => s.id));
    for (const id of [...FAILURE_SCENARIOS.map((s) => s.suite), ...LIFECYCLE.flatMap((s) => (s.suite ? [s.suite] : []))]) expect(have.has(id), id).toBe(true);
  });
});

describe('the frontend makes no security decisions', () => {
  const SRC = join(__dirname, '../src');
  const files: string[] = [];
  (function walk(dir: string) {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) {
        if (name === 'api' || name === 'server') continue; // server-side adapters are allowed to import the engine
        walk(full);
      } else if (/\.(ts|tsx)$/.test(name)) files.push(full);
    }
  })(SRC);

  it('browser code (app pages, components, lib) imports no trust engine package', () => {
    expect(files.length).toBeGreaterThan(3);
    for (const f of files) {
      const text = readFileSync(f, 'utf8');
      expect(text, f).not.toMatch(/from ['"]@agent-trust\/(gateway|policy|vc|status|replay|delegation|did|crypto|audit|trust-profile|attacks)['"]/);
    }
  });

  it('browser code never derives a decision from numbers (no amount-vs-limit comparison that sets allow/deny)', () => {
    for (const f of files) {
      const text = readFileSync(f, 'utf8');
      expect(text, f).not.toMatch(/amount\s*(<=|<|>=|>)\s*(limit|500)/);
      expect(text, f).not.toMatch(/Number\([^)]*\)\s*(<=|>)\s*500/);
    }
  });

  it('no trust score or rating field is rendered', () => {
    for (const f of files) {
      expect(readFileSync(f, 'utf8'), f).not.toMatch(/trustScore|reputationScore|riskScore/);
    }
  });
});

describe('shortHash', () => {
  it('abbreviates long hex digests', () => {
    expect(shortHash('c02483106fa17c23c1c817398b98388b49c601e9054f3beb0031f40dd548eea8')).toBe('c0248310…eea8');
    expect(shortHash(undefined)).toBe('—');
  });
});
