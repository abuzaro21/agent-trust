'use client';

import { useEffect, useMemo, useState } from 'react';

import type { AttackReportDto, AttackScenarioDto } from '@/lib/dto';

/**
 * /attacks — the Step 13 adversarial suite rendered from the generated
 * report (or an explicit run). Loads a snapshot by default; the full
 * suite NEVER auto-runs on page load (14O).
 */

const SHOWCASE = ['AUTHORITY-001', 'IDENTITY-001', 'STATUS-001', 'REPLAY-001', 'AUDIT-007', 'ATTEST-002'];

export default function AttacksPage() {
  const [report, setReport] = useState<AttackReportDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState<string | null>('AUTHORITY-001');

  const load = async (run = false) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(run ? '/api/attacks/report?run=1' : '/api/attacks/report');
      const json = await res.json();
      if (!res.ok || json.error !== undefined) {
        setError(`${json.error ?? 'ATTACK_REPORT_UNAVAILABLE'}${json.detail ? `: ${json.detail}` : ''}`);
      } else {
        setReport(json as AttackReportDto);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load(false);
  }, []);

  const scenarios = useMemo(() => report?.scenarios ?? [], [report]);

  return (
    <main style={{ maxWidth: 1100, margin: '0 auto', padding: '32px 24px 64px' }}>
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.4rem' }}>Security Tests — Adversarial Suite</h1>
          <p style={{ color: 'var(--fg-muted)', margin: '6px 0 0' }}>
            Every scenario asserts the denial reason <em>and</em> that protected side effects never happened.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <a href="/" className="badge badge--neutral" style={{ textDecoration: 'none' }}>← Trust console</a>
          <button
            onClick={() => void load(true)}
            disabled={loading}
            style={{ padding: '8px 14px', borderRadius: 6, border: '1px solid var(--border-strong)', background: 'var(--surface-raised)', color: 'var(--fg)', opacity: loading ? 0.6 : 1 }}
          >
            {loading ? 'Running suite…' : 'Run full suite'}
          </button>
        </div>
      </header>

      {error !== null && (
        <div role="alert" className="card" style={{ marginTop: 16, borderColor: 'rgba(239,68,68,.5)' }}>
          <span className="mono" style={{ color: 'var(--deny)' }}>{error}</span>
        </div>
      )}

      {report === null && error === null && !loading && <p style={{ color: 'var(--fg-subtle)' }}>Loading report…</p>}
      {loading && <p style={{ color: 'var(--fg-subtle)' }}>Running all scenarios (isolated worlds, ~4 s)…</p>}

      {report !== null && (
        <>
          <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 10, marginTop: 20 }}>
            <div className="card" style={{ gridColumn: '1 / -1', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
              <div style={{ fontSize: '1.5rem', fontWeight: 700 }}>
                <span style={{ color: 'var(--ok)' }}>{report.summary.passed} / {report.summary.total}</span>
                <span style={{ color: 'var(--fg-subtle)', fontSize: '1rem', fontWeight: 500 }}> security scenarios passed</span>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <span className="badge badge--neutral">{report.summary.attacks} attacks</span>
                <span className="badge badge--neutral">{report.summary.failureDemos} failure demos</span>
                <span className="badge badge--neutral">baseline {report.baselineCommit}</span>
              </div>
            </div>
            {Object.entries(report.summary.byCategory).map(([cat, bucket]) => (
              <div key={cat} className="card" style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: bucket.passed === bucket.total ? 'var(--ok)' : 'var(--deny)' }}>
                  {bucket.passed}/{bucket.total}
                </div>
                <div style={{ color: 'var(--fg-subtle)', fontSize: '.8rem', marginTop: 2 }}>{cat.replaceAll('_', ' ')}</div>
              </div>
            ))}
          </section>

          <section style={{ marginTop: 24 }}>
            <h2 style={{ fontSize: '.85rem', textTransform: 'uppercase', letterSpacing: '.08em', color: 'var(--fg-subtle)' }}>
              Showcase scenarios
            </h2>
            <div style={{ display: 'grid', gap: 10 }}>
              {SHOWCASE.map((id) => {
                const sc = scenarios.find((x) => x.id === id);
                return sc ? <ScenarioCard key={id} sc={sc} open={open === id} onToggle={() => setOpen((cur) => (cur === id ? null : id))} /> : null;
              })}
            </div>
          </section>

          <section style={{ marginTop: 24 }}>
            <h2 style={{ fontSize: '.85rem', textTransform: 'uppercase', letterSpacing: '.08em', color: 'var(--fg-subtle)' }}>
              All {report.summary.total} scenarios
            </h2>
            <details className="card" open={false}>
              <summary style={{ cursor: 'pointer' }}>Expand full scenario list</summary>
              <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: 12, fontSize: '.82rem' }}>
                <thead>
                  <tr style={{ textAlign: 'left', color: 'var(--fg-subtle)' }}>
                    <th style={{ padding: '4px 8px' }}>ID</th>
                    <th style={{ padding: '4px 8px' }}>Layer</th>
                    <th style={{ padding: '4px 8px' }}>Title</th>
                    <th style={{ padding: '4px 8px' }}>Observed</th>
                    <th style={{ padding: '4px 8px' }}>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {scenarios.map((sc) => (
                    <tr key={sc.id} style={{ borderTop: '1px solid var(--border)' }}>
                      <td style={{ padding: '6px 8px' }} className="mono">{sc.id}</td>
                      <td style={{ padding: '6px 8px' }}>{sc.category.replaceAll('_', ' ')}</td>
                      <td style={{ padding: '6px 8px' }}>{sc.title}</td>
                      <td style={{ padding: '6px 8px' }} className="mono" title={sc.observed.outcome}>{truncate(sc.observed.outcome, 80)}</td>
                      <td style={{ padding: '6px 8px' }}>
                        <span className={`badge badge--${sc.status === 'PASS' ? 'ok' : 'deny'}`}>{sc.status}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>
          </section>

          <p style={{ color: 'var(--fg-subtle)', fontSize: '.8rem', marginTop: 24 }}>
            This page is a read model over the deterministic suite; it adds no trust logic and no scores.
            Regenerate from source with <code className="mono">pnpm demo:attacks</code>.
          </p>
        </>
      )}
    </main>
  );
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

function ScenarioCard(props: { sc: AttackScenarioDto; open: boolean; onToggle: () => void }) {
  const { sc } = props;
  const passed = sc.status === 'PASS';
  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
      <button
        onClick={props.onToggle}
        aria-expanded={props.open}
        style={{
          display: 'grid',
          gridTemplateColumns: '24px 140px 1fr auto',
          gap: 12,
          width: '100%',
          padding: '12px 16px',
          background: props.open ? 'var(--surface-raised)' : 'transparent',
          border: 'none',
          color: 'var(--fg)',
          textAlign: 'left',
          alignItems: 'center',
        }}
      >
        <span aria-hidden style={{ color: passed ? 'var(--ok)' : 'var(--deny)', fontWeight: 700 }}>{passed ? '✓' : '✕'}</span>
        <span className="mono">{sc.id}</span>
        <span style={{ fontSize: '.9rem' }}>{sc.title}</span>
        <span className={`badge badge--${passed ? 'ok' : 'deny'}`}>{passed ? 'blocked' : 'FAIL'}</span>
      </button>
      {props.open && (
        <div style={{ padding: '0 16px 14px', borderTop: '1px solid var(--border)', margin: '0 16px 0', paddingTop: 10 }}>
          <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: '180px 1fr', gap: '4px 16px', fontSize: '.85rem' }}>
            <dt style={{ color: 'var(--fg-subtle)' }}>Expected</dt>
            <dd style={{ margin: 0 }}>{sc.expected.outcome}{sc.expected.reasonCode ? ` (${sc.expected.reasonCode})` : ''}</dd>
            <dt style={{ color: 'var(--fg-subtle)' }}>Observed</dt>
            <dd style={{ margin: 0 }} className="mono">{sc.observed.outcome}</dd>
            {sc.observed.reasonCodes.length > 0 && (
              <>
                <dt style={{ color: 'var(--fg-subtle)' }}>Reason codes</dt>
                <dd style={{ margin: 0 }} className="mono">{sc.observed.reasonCodes.join(', ')}</dd>
              </>
            )}
            <dt style={{ color: 'var(--fg-subtle)' }}>Invariants</dt>
            <dd style={{ margin: 0 }} className="mono">{formatInvariants(sc.observed.invariants)}</dd>
            {sc.detail !== undefined && (
              <>
                <dt style={{ color: 'var(--fg-subtle)' }}>Failure detail</dt>
                <dd style={{ margin: 0 }} className="mono">{sc.detail}</dd>
              </>
            )}
          </dl>
        </div>
      )}
    </div>
  );
}

function formatInvariants(inv: Record<string, unknown>): string {
  return Object.entries(inv).map(([k, v]) => {
    if (typeof v === 'object' && v !== null) return `${k}=${JSON.stringify(v)}`;
    return `${k}=${String(v)}`;
  }).join(' · ');
}
