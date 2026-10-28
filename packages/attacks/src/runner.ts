import type { AttackObserved, AttackResult, AttackScenario } from './types.js';
import { ATTACK_REGISTRY, INVARIANT_CHECKS } from './registry.js';
import { judge, type InvariantCheck } from './oracle.js';
import { NOW } from './world.js';

/**
 * Step 13N/13O — the deterministic runner. The oracle lives in ./oracle.ts:
 * a scenario PASSes only when it declares a typed expected verdict and
 * exactly one reason-code policy, the observed TYPED verdict equals it, the
 * reason-code policy holds, a registered invariant checker exists and
 * accepts the observation, and the human outcome text carries no failure
 * marker (defence in depth). Missing pieces FAIL; an exception FAILs.
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

/** Pure: judge one scenario against one observation with a given checker (also used by the negative-control tests). */
export { judge };

export async function runAttackSuite(opts: { only?: string[] } = {}): Promise<AttackReport> {
  const results: AttackResult[] = [];
  const scenarios = opts.only
    ? ATTACK_REGISTRY.filter((sc) => opts.only!.includes(sc.id))
    : ATTACK_REGISTRY;
  for (const sc of scenarios) {
    const started = performance.now();
    let observed: AttackObserved;
    let failures: string[];
    try {
      observed = await sc.run({ now: NOW });
      failures = judge(sc, observed, (INVARIANT_CHECKS as Record<string, InvariantCheck | undefined>)[sc.id]).failures;
    } catch (e) {
      observed = { outcome: `EXCEPTION: ${String(e)}`, verdict: 'BREACHED', reasonCodes: [], invariants: {} };
      failures = [`scenario threw: ${String(e)}`];
    }
    const status: AttackResult['status'] = failures.length === 0 ? 'PASS' : 'FAIL';
    results.push({
      id: sc.id,
      kind: sc.kind,
      category: sc.category,
      title: sc.title,
      status,
      expected: {
        outcome: sc.expected.outcome,
        verdict: sc.expected.verdict,
        ...(sc.expected.reasonCode !== undefined ? { reasonCode: sc.expected.reasonCode } : {}),
        ...(sc.expected.noReasonCode !== undefined ? { noReasonCode: sc.expected.noReasonCode } : {}),
      },
      observed,
      durationMs: Math.round((performance.now() - started) * 10) / 10,
      ...(failures.length > 0 ? { failures, detail: failures.join(' | ') } : {}),
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
