import type { AttackObserved, AttackResult, AttackScenario } from './types.js';
import { ATTACK_REGISTRY, INVARIANT_CHECKS } from './registry.js';
import { NOW } from './world.js';
import type { ReasonCode } from '@agent-trust/schemas';

/**
 * Step 13N/13O — the deterministic runner. A scenario PASSes only when:
 *   (a) the expected reason code (or predicate) is observed, AND
 *   (b) the outcome summary is not an UNDETECTED/UNEXPECTED marker, AND
 *   (c) the security invariants for that scenario hold (executor calls,
 *       victim history, cache state, …) — denial alone is not proof.
 */

export interface AttackRunSummary {
  total: number;
  attacks: number;
  failureDemos: number;
  passed: number;
  failed: number;
  byCategory: Record<string, { total: number; passed: number }>;
}

export interface AttackReport {
  suite: 'agent-trust/adversarial-suite/v1';
  baselineCommit: string;
  summary: AttackRunSummary;
  scenarios: AttackResult[];
}

function outcomeLooksBad(o: AttackObserved): boolean {
  return /UNDETECTED|UNEXPECTED|UNUSUAL|STALE KEY SURVIVED|UNEXPECTED CACHE|connected \(unexpected\)/i.test(o.outcome);
}

function reasonMatches(s: AttackScenario, codes: ReasonCode[]): boolean {
  if (s.expected.reasonCodesMatch !== undefined) return s.expected.reasonCodesMatch(codes);
  if (s.expected.reasonCode !== undefined) return codes.includes(s.expected.reasonCode);
  return true; // outcome+invariants carry the judgment
}

export async function runAttackSuite(opts: { only?: string[] } = {}): Promise<AttackReport> {
  const results: AttackResult[] = [];
  const scenarios = opts.only
    ? ATTACK_REGISTRY.filter((sc) => opts.only!.includes(sc.id))
    : ATTACK_REGISTRY;
  for (const sc of scenarios) {
    const started = performance.now();
    let observed: AttackObserved;
    let invariantOk = false;
    let detail: string | undefined;
    try {
      observed = await sc.run({ now: NOW });
      const check = INVARIANT_CHECKS[sc.id];
      const inv = check ? check(observed) : { ok: true };
      invariantOk = inv.ok;
      detail = 'detail' in inv ? (inv.detail as string | undefined) : undefined;
    } catch (e) {
      observed = { outcome: `EXCEPTION: ${String(e)}`, reasonCodes: [], invariants: {} };
      detail = String(e);
    }
    const status: AttackResult['status'] =
      reasonMatches(sc, observed.reasonCodes) && !outcomeLooksBad(observed) && invariantOk ? 'PASS' : 'FAIL';
    results.push({
      id: sc.id,
      kind: sc.kind,
      category: sc.category,
      title: sc.title,
      status,
      expected: {
        outcome: sc.expected.outcome,
        ...(sc.expected.reasonCode !== undefined ? { reasonCode: sc.expected.reasonCode } : {}),
      },
      observed,
      durationMs: Math.round((performance.now() - started) * 10) / 10,
      ...(detail !== undefined ? { detail } : {}),
    });
  }

  const byCategory: AttackRunSummary['byCategory'] = {};
  for (const r of results) {
    const bucket = byCategory[r.category] ?? { total: 0, passed: 0 };
    bucket.total += 1;
    if (r.status === 'PASS') bucket.passed += 1;
    byCategory[r.category] = bucket;
  }
  return {
    suite: 'agent-trust/adversarial-suite/v1',
    baselineCommit: '414cbaa',
    summary: {
      total: results.length,
      attacks: results.filter((r) => r.kind === 'ATTACK').length,
      failureDemos: results.filter((r) => r.kind === 'FAILURE_DEMO').length,
      passed: results.filter((r) => r.status === 'PASS').length,
      failed: results.filter((r) => r.status === 'FAIL').length,
      byCategory,
    },
    scenarios: results,
  };
}

/** Step 13O — human-readable rendering (also the terminal output). */
export function renderReportMd(report: AttackReport): string {
  const lines: string[] = [];
  lines.push('# Adversarial Suite Report');
  lines.push('');
  lines.push(`> ${report.summary.passed}/${report.summary.total} security scenarios passed ` +
    `(${report.summary.attacks} attacks + ${report.summary.failureDemos} failure demos), baseline ${report.baselineCommit}.`);
  lines.push('');
  lines.push('| Scenario | Layer | Title | Expected | Observed | Status |');
  lines.push('|---|---|---|---|---|---|');
  for (const r of report.scenarios) {
    lines.push(
      `| ${r.id} | ${r.category} | ${r.title} | ${r.expected.reasonCode ?? r.expected.outcome} | ${r.observed.outcome}${r.observed.reasonCodes.length > 0 && r.expected.reasonCode === undefined ? ` (${r.observed.reasonCodes.join(', ')})` : ''} | ${r.status === 'PASS' ? 'PASS' : '**FAIL**'} |`,
    );
  }
  lines.push('');
  lines.push('## Coverage by trust layer');
  for (const [cat, bucket] of Object.entries(report.summary.byCategory)) {
    lines.push(`- ${cat}: ${bucket.passed}/${bucket.total}`);
  }
  return `${lines.join('\n')}\n`;
}
