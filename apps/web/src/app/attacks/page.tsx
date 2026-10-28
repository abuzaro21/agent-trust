'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';

import type { AttackReportDto, AttackScenarioDto } from '@/lib/dto';

/**
 * /attacks — the adversarial suite, rendered from the stored report artifact.
 * The report is generated when the container image is built; this page only
 * reads it. It never triggers a server-side run and adds no trust logic.
 */

const SHOWCASE = ['AUTHORITY-001', 'IDENTITY-001', 'STATUS-001', 'REPLAY-001', 'AUDIT-007', 'ATTEST-002'];

export default function AttacksPage() {
  const [report, setReport] = useState<AttackReportDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState<string | null>('AUTHORITY-001');

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/attacks/report');
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
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const scenarios = useMemo(() => report?.scenarios ?? [], [report]);

  return (
    <div className="page">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden>✓</span>
          <span>Agent Trust · Security tests</span>
        </div>
        <nav className="nav" aria-label="Page">
          <a href="/">← Back to the demo</a>
        </nav>
      </header>

      <main id="main">
        <section className="hero" style={{ paddingBottom: 0 }}>
          <h1 style={{ fontSize: 'clamp(1.8rem, 4vw, 2.6rem)', maxWidth: '22ch' }}>Every attack is checked twice.</h1>
          <p className="lead">
            Each scenario asserts the denial reason <strong>and</strong> that the protected action never happened (the executor never ran; a spoof is never attributed to its victim).
          </p>
        </section>

        <div className="callout" style={{ marginTop: 'var(--s5)' }}>
          <strong>About this report:</strong> it was generated when the container image was built and is served as a stored file. It did not run when you opened this page. To reproduce it, run{' '}
          <code className="mono">pnpm test:attacks</code> from the repository.
        </div>

        {error !== null && (
          <div className="err" role="alert" style={{ marginTop: 'var(--s4)' }}>
            <strong>Report unavailable.</strong> <span className="mono wrap-any">{error}</span>{' '}
            <button type="button" className="btn btn--small" onClick={() => void load()}>Retry</button>
          </div>
        )}
        {loading && error === null && (
          <p className="note" style={{ marginTop: 'var(--s5)' }} role="status">Loading report…</p>
        )}

        {report !== null && (
          <>
            <section className="card" style={{ marginTop: 'var(--s5)' }} aria-labelledby="sum-h">
              <h2 className="card-title" id="sum-h">Summary</h2>
              <p style={{ marginTop: 'var(--s2)' }}>
                <strong className="num" style={{ fontSize: '2rem', color: report.summary.failed === 0 ? 'var(--ok)' : 'var(--deny)' }}>
                  {report.summary.passed} / {report.summary.total}
                </strong>{' '}
                scenarios passed
              </p>
              <div className="chips">
                <span className="badge badge--neutral">{report.summary.attacks} attacks</span>
                <span className="badge badge--neutral">{report.summary.failureDemos} failure demos</span>
                <span className="badge badge--neutral" title="The commit the suite was first baselined at — not the deployed build.">suite first baselined at {report.baselineCommit}</span>
              </div>
              <div className="grid-auto" style={{ marginTop: 'var(--s4)', gridTemplateColumns: 'repeat(auto-fill, minmax(min(100%, 150px), 1fr))' }}>
                {Object.entries(report.summary.byCategory).map(([cat, b]) => (
                  <div key={cat} className="card tight">
                    <div className="num" style={{ fontWeight: 700, color: b.passed === b.total ? 'var(--ok)' : 'var(--deny)' }}>
                      {b.passed}/{b.total}
                    </div>
                    <div className="note">{cat.replaceAll('_', ' ').toLowerCase()}</div>
                  </div>
                ))}
              </div>
            </section>

            <section className="section" aria-labelledby="show-h" style={{ paddingTop: 'var(--s6)' }}>
              <h2 className="card-title" id="show-h" style={{ marginBottom: 'var(--s3)' }}>Showcase scenarios</h2>
              <div className="stack">
                {SHOWCASE.map((id) => {
                  const sc = scenarios.find((x) => x.id === id);
                  return sc ? <ScenarioCard key={id} sc={sc} open={open === id} onToggle={() => setOpen((cur) => (cur === id ? null : id))} /> : null;
                })}
              </div>
            </section>

            <section className="section" aria-labelledby="all-h" style={{ paddingTop: 'var(--s6)' }}>
              <h2 className="card-title" id="all-h" style={{ marginBottom: 'var(--s3)' }}>All {report.summary.total} scenarios</h2>
              <details className="card disclose">
                <summary>Expand the full scenario list</summary>
                <div className="table-wrap">
                  <table className="table">
                    <thead>
                      <tr>
                        <th scope="col">ID</th>
                        <th scope="col">Layer</th>
                        <th scope="col">Title</th>
                        <th scope="col">Observed</th>
                        <th scope="col">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scenarios.map((sc) => (
                        <tr key={sc.id}>
                          <td className="mono" style={{ whiteSpace: 'nowrap' }}>{sc.id}</td>
                          <td>{sc.category.replaceAll('_', ' ').toLowerCase()}</td>
                          <td>{sc.title}</td>
                          <td className="mono wrap-any" title={sc.observed.outcome}>{truncate(sc.observed.outcome, 80)}</td>
                          <td><span className={`badge badge--${sc.status === 'PASS' ? 'ok' : 'deny'}`}>{sc.status}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </details>
            </section>
          </>
        )}

        <footer className="footer">
          <p>This page is a read model over a deterministic suite; it adds no trust logic and no scores.</p>
        </footer>
      </main>
    </div>
  );
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

function ScenarioCard(props: { sc: AttackScenarioDto; open: boolean; onToggle: () => void }) {
  const { sc } = props;
  const passed = sc.status === 'PASS';
  const panel = `panel-${sc.id}`;
  return (
    <article className="card tight" style={{ padding: 0, overflow: 'hidden' }}>
      <h3 style={{ margin: 0, fontSize: '1rem' }}>
        <button
          type="button"
          className="btn"
          onClick={props.onToggle}
          aria-expanded={props.open}
          aria-controls={panel}
          style={{ width: '100%', justifyContent: 'flex-start', gap: 'var(--s3)', border: 0, borderRadius: 0, background: props.open ? 'var(--surface-2)' : 'transparent', textAlign: 'left', flexWrap: 'wrap' }}
        >
          <span aria-hidden style={{ color: passed ? 'var(--ok)' : 'var(--deny)', fontWeight: 800 }}>{passed ? '✓' : '✕'}</span>
          <span className="mono">{sc.id}</span>
          <span style={{ flex: '1 1 220px', fontWeight: 520 }}>{sc.title}</span>
          <span className={`badge badge--${passed ? 'ok' : 'deny'}`}>{passed ? 'blocked' : 'FAIL'}</span>
        </button>
      </h3>
      {props.open && (
        <div id={panel} style={{ padding: 'var(--s4)', borderTop: '1px solid var(--border)' }}>
          <dl className="kv">
            <dt>Expected</dt>
            <dd>{sc.expected.outcome}{sc.expected.reasonCode ? ` (${sc.expected.reasonCode})` : ''}</dd>
            <dt>Observed</dt>
            <dd className="mono wrap-any">{sc.observed.outcome}</dd>
            {sc.observed.reasonCodes.length > 0 && (
              <>
                <dt>Reason codes</dt>
                <dd className="mono wrap-any">{sc.observed.reasonCodes.join(', ')}</dd>
              </>
            )}
            <dt>Invariants</dt>
            <dd className="mono wrap-any">{formatInvariants(sc.observed.invariants)}</dd>
            {sc.detail !== undefined && (
              <>
                <dt>Failure detail</dt>
                <dd className="mono wrap-any">{sc.detail}</dd>
              </>
            )}
          </dl>
        </div>
      )}
    </article>
  );
}

function formatInvariants(inv: Record<string, unknown>): string {
  return Object.entries(inv)
    .map(([k, v]) => (typeof v === 'object' && v !== null ? `${k}=${JSON.stringify(v)}` : `${k}=${String(v)}`))
    .join(' · ');
}
