'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import type { AuditDto, AttackReportDto, DecisionDto, EvaluationDto, ProfileDto } from '@/lib/dto';
import { explainReason, shortHash, stagesToView } from '@/lib/presentation';

const PRESETS: { id: string; label: string; tone: 'ok' | 'deny' | 'warn'; hint: string }[] = [
  { id: 'valid-120', label: '✓ Valid 120 SAR', tone: 'ok', hint: 'In scope, fresh, executed' },
  { id: 'over-5000', label: '✕ Over-limit 5000 SAR', tone: 'deny', hint: 'Same agent — exceeds 500 SAR delegation' },
  { id: 'spoof', label: '✕ Spoofed Agent', tone: 'deny', hint: 'Claims SupportAgent, signs with its own key' },
  { id: 'revoked', label: '✕ Revoked Credential', tone: 'deny', hint: 'Isolated credential revoked at the status list' },
  { id: 'replay', label: '✕ Replay Attack', tone: 'deny', hint: 'Runs once, then re-sends the exact bytes' },
  { id: 'quarantine', label: 'Quarantined Agent', tone: 'warn', hint: 'Emergency identity kill switch' },
  { id: 'wrong-audience', label: 'Wrong Audience', tone: 'warn', hint: 'Delegation does not name this service' },
  { id: 'tampered', label: 'Tampered Request', tone: 'warn', hint: '120 signed, 5000 on the wire' },
];

const SPOOFED_DID = 'did:web:evil.example:agent';

interface DemoStatus {
  identityMode: 'fixture' | 'web';
  dids: { org: string; support: string; refund: string };
  replayStore: 'redis' | 'in-memory';
  build?: { sha?: string };
  environment?: string;
}

export default function Dashboard() {
  const [profile, setProfile] = useState<ProfileDto | null>(null);
  const [audit, setAudit] = useState<AuditDto | null>(null);
  const [evaluation, setEvaluation] = useState<EvaluationDto | null>(null);
  const [running, setRunning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [amount, setAmount] = useState('120');
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const [status, setStatus] = useState<DemoStatus | null>(null);
  const pipelineRef = useRef<HTMLDivElement>(null);

  const refresh = useCallback(async (attempt = 0): Promise<void> => {
    try {
      const [pr, ar, s] = await Promise.all([
        fetch('/api/agents/support/profile'),
        fetch('/api/audit/acme-demo'),
        fetch('/api/demo/status').then((r) => (r.ok ? r.json() : null)),
      ]);
      if (!pr.ok || !ar.ok) throw new Error('backend initializing');
      setProfile(await pr.json());
      setAudit(await ar.json());
      if (s?.dids !== undefined) setStatus(s as DemoStatus);
      setError(null);
    } catch {
      // STEP 16AJ — cold start on sleeping hosts: the first request can
      // outlive the initial render. Retry with backoff; the honest
      // "Initializing" state stays visible meanwhile (never fake data).
      if (attempt < 6) {
        setTimeout(() => void refresh(attempt + 1), 800 + attempt * 700);
      } else {
        setError('Dashboard backend unavailable.');
      }
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const run = useCallback(
    async (preset?: string) => {
      setRunning(preset ?? 'custom');
      setError(null);
      try {
        const body = preset ? { preset } : { amount: Number(amount) };
        const res = await fetch('/api/trust/evaluate', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body),
        });
        const json = (await res.json()) as EvaluationDto & { error?: string; detail?: string };
        if (!res.ok || json.error !== undefined) {
          setError(`${json.error ?? 'ERROR'}${json.detail ? `: ${json.detail}` : ''}`);
          return;
        }
        setEvaluation(json);
        // Refresh profile + audit so evidence reflects the run.
        const [p, a] = await Promise.all([
          fetch('/api/agents/support/profile').then((r) => r.json()),
          fetch('/api/audit/acme-demo').then((r) => r.json()),
        ]);
        setProfile(p);
        setAudit(a);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setRunning(null);
        pipelineRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    },
    [amount],
  );

  const decision = evaluation?.result;
  const stageViews = useMemo(() => (decision ? stagesToView(decision.stages) : []), [decision]);
  const primaryDenial = decision && decision.effect !== 'ALLOW' ? decision.reasonCodes[0] : undefined;
  const requested = decision
    ? (audit?.receipts.find((r) => r.taskId === decision.taskId)?.amount ?? undefined)
    : undefined;

  return (
    <main style={{ maxWidth: 1280, margin: '0 auto', padding: '32px 24px 64px' }}>
      <Header status={status} />

      <section style={{ display: 'grid', gridTemplateColumns: 'minmax(0,5fr) minmax(0,7fr)', gap: 16, marginTop: 24 }}>
        <div style={{ display: 'grid', gap: 16, alignContent: 'start' }}>
          <ProfilePanel profile={profile} />
          <AttestationPanel profile={profile} />
        </div>
        <div style={{ display: 'grid', gap: 16, alignContent: 'start' }}>
          <ComposerPanel
            amount={amount}
            onAmount={setAmount}
            running={running}
            onRun={() => void run()}
            onPreset={(id) => void run(id)}
            presets={PRESETS}
          />
          <div ref={pipelineRef}>
            {decision ? (
              <DecisionPanel
                decision={decision}
                spoofed={decision.taskId.startsWith('web_spoof') || (decision.reasonCodes.includes('IDENTITY_PROOF_INVALID') && evaluation?.note?.includes('victim') === true)}
                requestedAmount={requested}
                stageViews={stageViews}
                firstResult={evaluation?.firstResult}
                note={evaluation?.note}
                onEvidence={() => setEvidenceOpen((v) => !v)}
                evidenceOpen={evidenceOpen}
              />
            ) : (
              <div className="card" aria-live="polite">
                <h2>Decision</h2>
                <p style={{ color: 'var(--fg-subtle)', margin: 0 }}>
                  Run a request or a preset scenario. The decision, the pipeline stages, and the evidence
                  below all come from the live gateway — this UI never computes them.
                </p>
              </div>
            )}
          </div>
        </div>
      </section>

      {error !== null && (
        <div role="alert" className="card" style={{ marginTop: 16, borderColor: 'rgba(239,68,68,.5)' }}>
          <strong style={{ color: 'var(--deny)' }}>Request failed</strong>
          <div className="mono" style={{ marginTop: 4 }}>{error}</div>
        </div>
      )}

      <section style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr) minmax(0,1fr)', gap: 16, marginTop: 16 }}>
        <AuditPanel audit={audit} />
        <HistoryPanel profile={profile} />
      </section>

      {evidenceOpen && decision !== undefined && (        <EvidenceDrawer decision={decision} receipts={evaluation?.runReceipts ?? []} onClose={() => setEvidenceOpen(false)} />
      )}

      <ArchitectureSnapshot />
    </main>
  );
}

function Header({ status }: { status: DemoStatus | null }) {
  return (
    <header>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 16, flexWrap: 'wrap' }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.55rem', letterSpacing: '-0.02em' }}>The Agent That Earns Trust</h1>
          <p style={{ margin: '6px 0 0', color: 'var(--fg-muted)' }}>
            Verifiable identity. Scoped authority. Explainable decisions.
          </p>
        </div>
        <nav style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <span className="badge badge--neutral" title={status?.environment ?? 'demo environment'}>
            Challenge Demo · simulation, not a payment system
          </span>
          <a href="/attacks" className="badge badge--neutral" style={{ textDecoration: 'none' }}>
            Security Tests →
          </a>
        </nav>
      </div>
      <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
        <span className={`badge ${status?.identityMode === 'web' ? 'badge--ok' : 'badge--neutral'}`}>
          Identity: {status?.identityMode === 'web' ? '✓ did:web (live HTTPS)' : 'did:web fixtures'}
        </span>
        <span className={`badge ${status?.replayStore === 'redis' ? 'badge--ok' : 'badge--neutral'}`}>
          Replay: {status?.replayStore === 'redis' ? '✓ Redis-backed' : 'in-memory (dev)'}
        </span>
        {status?.build?.sha !== undefined && status.build.sha !== 'dev' && (
          <span className="badge badge--neutral">build {status.build.sha.slice(0, 7)}</span>
        )}
      </div>
      <p className="mono" style={{ marginTop: 12, color: 'var(--fg-subtle)', fontSize: '.78rem' }}>
        Trust is evaluated from verifiable evidence and context — there is no universal trust score, and none is computed here.
      </p>
    </header>
  );
}

// ------------------------------------------------------------ profile side

function ProfilePanel({ profile }: { profile: ProfileDto | null }) {
  if (profile === null) return <SkeletonCard title="Trust Profile" />;
  const p = profile.profile;
  const authority = p.authority.active[0];
  return (
    <div className="card">
      <h2>Trust Profile — SupportAgent</h2>
      <div style={{ display: 'grid', gap: 10 }}>
        <Field label="DID" mono value={p.agent.did} />
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          <BadgeRow label="Identity" ok={p.identity.resolved} text={p.identity.resolved ? '✓ resolved' : '✗ unresolved'} />
          <BadgeRow label="Credential status" ok={p.credentials.active > 0 && p.credentials.revoked === 0 && p.credentials.suspended === 0}
            text={`${p.credentials.active} active`} warn={p.credentials.suspended} deny={p.credentials.revoked} />
        </div>
        {authority !== undefined && (
          <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: 'var(--space-3)' }}>
            <div className="mono" style={{ fontWeight: 600 }}>{authority.actions.join(', ')}</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '2px 12px', marginTop: 6, fontSize: '.85rem' }}>
              <span style={{ color: 'var(--fg-subtle)' }}>Resources</span>
              <span className="mono">{authority.resources.join(', ')}</span>
              <span style={{ color: 'var(--fg-subtle)' }}>Audience</span>
              <span className="mono">{authority.audience?.[0] ?? '—'}</span>
              <span style={{ color: 'var(--fg-subtle)' }}>Limit</span>
              <span style={{ fontWeight: 600 }}>
                {authority.limits?.amount !== undefined ? `≤ ${authority.limits.amount} ${authority.limits.currency ?? 'SAR'}` : 'no amount limit'}
              </span>
            </div>
            <div style={{ marginTop: 6 }}>
              <span className="badge badge--ok">ACTIVE · verified credential</span>
              <span className="badge badge--neutral" style={{ marginLeft: 6 }}>
                evidence sha256:{shortHash(authority.evidenceDigest).slice(0, 10)}…
              </span>
            </div>
          </div>
        )}
        <p style={{ margin: 0, color: 'var(--fg-subtle)', fontSize: '.8rem' }}>
          Authority comes from a verified delegation credential — not from this panel, and not from history.
        </p>
      </div>
    </div>
  );
}

function AttestationPanel({ profile }: { profile: ProfileDto | null }) {
  if (profile === null) return <SkeletonCard title="Attestations" />;
  const { trusted, rejected } = profile.profile.attestations;
  return (
    <div className="card">
      <h2>Attestations (evidence — never authority)</h2>
      {trusted.length === 0 && rejected.length === 0 && <p style={{ color: 'var(--fg-subtle)' }}>None.</p>}
      {trusted.map((t) => (
        <div key={t.credentialId} style={{ padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
          <span className="badge badge--ok">✓ {t.type}</span>
          <span style={{ marginLeft: 8, fontWeight: 600 }}>{t.statement}</span>
          <div className="mono" style={{ color: 'var(--fg-subtle)', fontSize: '.75rem', marginTop: 2 }}>{t.issuer}</div>
        </div>
      ))}
      {rejected.map((r, i) => (
        <div key={i} style={{ padding: '6px 0', opacity: 0.85 }}>
          <span className="badge badge--deny">✕ rejected</span>
          <span style={{ marginLeft: 8 }} className="mono">{r.reasonCodes.join(', ')}</span>
          {r.issuer !== undefined && <div className="mono" style={{ color: 'var(--fg-subtle)', fontSize: '.75rem' }}>{r.issuer}</div>}
        </div>
      ))}
      <p style={{ margin: '8px 0 0', color: 'var(--fg-subtle)', fontSize: '.8rem' }}>
        Counts are shown as separate evidence items and are never aggregated into a score.
      </p>
    </div>
  );
}

// ------------------------------------------------------------ decision side

function ComposerPanel(props: {
  amount: string;
  onAmount: (v: string) => void;
  running: string | null;
  onRun: () => void;
  onPreset: (id: string) => void;
  presets: typeof PRESETS;
}) {
  return (
    <div className="card">
      <h2>Evaluate a request</h2>
      <div style={{ display: 'flex', gap: 12, alignItems: 'end', flexWrap: 'wrap' }}>
        <label style={{ display: 'grid', gap: 4, fontSize: '.85rem' }}>
          <span>Amount (SAR)</span>
          <input
            className="mono"
            inputMode="numeric"
            value={props.amount}
            onChange={(e) => props.onAmount(e.target.value)}
            style={{ width: 110, padding: '8px 10px', background: 'var(--slate-950)', color: 'var(--fg)', border: '1px solid var(--border-strong)', borderRadius: 6 }}
          />
        </label>
        <button
          onClick={props.onRun}
          disabled={props.running !== null}
          style={{
            padding: '9px 18px',
            borderRadius: 6,
            border: 'none',
            background: 'var(--green-600)',
            color: 'white',
            fontWeight: 600,
            opacity: props.running !== null ? 0.6 : 1,
          }}
        >
          {props.running === 'custom' ? 'Evaluating…' : 'Run Request'}
        </button>
        <span className="mono" style={{ color: 'var(--fg-subtle)', fontSize: '.75rem' }}>
          actor: SupportAgent · action: refund:create · resource: order:ORD-918 · audience: RefundAgent
        </span>
      </div>

      <div style={{ marginTop: 14 }}>
        <div className="label">Preset scenarios — no typing needed</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 8 }}>
          {props.presets.map((preset) => (
            <button
              key={preset.id}
              onClick={() => props.onPreset(preset.id)}
              disabled={props.running !== null}
              style={{
                textAlign: 'left',
                padding: '10px 12px',
                background: 'var(--surface-raised)',
                color: 'var(--fg)',
                border: `1px solid ${preset.tone === 'ok' ? 'rgba(34,197,94,.4)' : preset.tone === 'deny' ? 'rgba(239,68,68,.4)' : 'rgba(245,158,11,.4)'}`,
                borderRadius: 8,
                opacity: props.running !== null ? 0.55 : 1,
                transition: 'transform .15s ease, box-shadow .15s ease',
              }}
            >
              <div style={{ fontWeight: 600, fontSize: '.88rem' }}>
                {props.running === preset.id ? 'Evaluating…' : preset.label}
              </div>
              <div style={{ color: 'var(--fg-subtle)', fontSize: '.75rem', marginTop: 2 }}>{preset.hint}</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

function DecisionPanel(props: {
  decision: DecisionDto;
  spoofed: boolean;
  requestedAmount?: number;
  stageViews: ReturnType<typeof stagesToView>;
  firstResult?: DecisionDto;
  note?: string;
  onEvidence: () => void;
  evidenceOpen: boolean;
}) {
  const { decision, stageViews } = props;
  const allowed = decision.effect === 'ALLOW' && decision.outcome === 'AUTHORIZED';
  const uncertain = decision.outcome === 'EXECUTION_UNCERTAIN';
  const tone = allowed ? 'ok' : uncertain ? 'warn' : 'deny';
  const primary = decision.reasonCodes[0];
  const delegated = 500;
  return (
    <div className="card" aria-live="polite">
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
        <div>
          <div style={{ fontSize: '1.35rem', fontWeight: 700, letterSpacing: '-.01em', color: `var(--${tone})` }}>
            {allowed ? 'AUTHORIZED' : uncertain ? 'EXECUTION UNCERTAIN' : 'DENIED'}
          </div>
          <div className="mono" style={{ marginTop: 2, fontWeight: 600, fontSize: '.95rem' }}>
            {allowed ? 'WITHIN_AUTHORITY' : (primary ?? decision.outcome)}
          </div>
          <div style={{ color: 'var(--fg-muted)', fontSize: '.85rem', marginTop: 4 }}>
            {allowed
              ? 'Every stage verified; the delegated scope covers this action, resource, audience, and amount.'
              : explainReason(primary, { amount: props.requestedAmount ?? '—', limit: delegated })}
          </div>
        </div>
        <div style={{ textAlign: 'right', minWidth: 200 }}>
          {props.requestedAmount !== undefined ? (
            <div
              aria-label={`${props.requestedAmount} of ${delegated} SAR`}
              style={{ display: 'grid', gap: 6 }}
            >
              <div className="mono" style={{ fontSize: '1.2rem', fontWeight: 700, color: `var(--${allowed ? 'ok' : 'deny'})` }}>
                {props.requestedAmount} / {delegated} SAR
              </div>
              <div style={{ height: 10, background: 'var(--neutral-bg)', borderRadius: 999, overflow: 'hidden', border: '1px solid var(--border)' }}>
                <div
                  style={{
                    height: '100%',
                    width: `${Math.min((props.requestedAmount / delegated) * 100, 100)}%`,
                    background: allowed ? 'var(--green-600)' : 'var(--red-600)',
                  }}
                />
              </div>
              <div style={{ color: 'var(--fg-subtle)', fontSize: '.75rem', letterSpacing: '.06em', textTransform: 'uppercase' }}>
                {allowed ? 'within delegated authority' : 'exceeds delegated authority'}
              </div>
            </div>
          ) : (
            <span className={`badge badge--${tone}`}>{decision.stages.execution}</span>
          )}
        </div>
      </div>

      {props.firstResult !== undefined && (
        <p style={{ margin: '8px 0 0', color: 'var(--warn)', fontSize: '.85rem' }}>
          first attempt: {props.firstResult.outcome} · replay attempt: {decision.outcome}
        </p>
      )}
      {props.note !== undefined && (
        <p style={{ margin: '6px 0 0', color: 'var(--fg-subtle)', fontSize: '.82rem' }}>{props.note}</p>
      )}

      <h3 style={{ marginTop: 18 }}>Trust decision pipeline</h3>
      <ol className="pipeline" style={{ listStyle: 'none', padding: 0, margin: 0, display: 'grid', gap: 6 }}>
        {stageViews.map((stage) => (
          <li
            key={stage.key}
            style={{
              display: 'grid',
              gridTemplateColumns: '22px 130px 1fr auto',
              gap: 10,
              alignItems: 'center',
              padding: '7px 10px',
              background: 'var(--surface-raised)',
              border: '1px solid var(--border)',
              borderLeft: `3px solid var(--${stage.tone === 'ok' ? 'ok' : stage.tone === 'deny' ? 'deny' : stage.tone === 'warn' ? 'warn' : 'neutral'})`,
              borderRadius: 6,
            }}
          >
            <span aria-hidden style={{ color: `var(--${stage.tone})`, fontWeight: 700 }}>
              {stage.tone === 'ok' ? '✓' : stage.tone === 'deny' ? '✕' : stage.tone === 'warn' ? '!' : '—'}
            </span>
            <span style={{ fontSize: '.82rem', color: 'var(--fg-subtle)' }}>{stage.label}</span>
            <span className="mono" style={{ fontWeight: 600, color: `var(--${stage.tone})`, fontSize: '.85rem' }}>
              {stage.value}
            </span>
            {stage.key === 'policy' && decision.stages.policy === 'ALLOW' && allowed && (
              <span className="mono" style={{ fontSize: '.72rem', color: 'var(--fg-subtle)' }}>
                agent-trust-refund@1.1.0
              </span>
            )}
          </li>
        ))}
      </ol>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 14, gap: 12, flexWrap: 'wrap' }}>
        <button
          onClick={props.onEvidence}
          style={{
            padding: '7px 14px',
            background: 'transparent',
            color: 'var(--info)',
            border: '1px solid var(--border-strong)',
            borderRadius: 6,
            fontWeight: 600,
          }}
        >
          {props.evidenceOpen ? 'Hide evidence' : 'Evidence & receipts →'}
        </button>
        <div className="mono" style={{ fontSize: '.72rem', color: 'var(--fg-subtle)' }}>
          {decision.decisionReceiptId !== undefined ? `decision ${decision.decisionReceiptId}` : 'no decision receipt'}
        </div>
      </div>
    </div>
  );
}

function EvidenceDrawer(props: { decision: DecisionDto; receipts: { eventHash: string; receiptId: string; sequence: number }[]; onClose: () => void }) {
  return (
    <div className="card" style={{ marginTop: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
        <h2 style={{ margin: 0 }}>Evidence for this evaluation</h2>
        <button onClick={props.onClose} style={{ background: 'transparent', color: 'var(--fg-subtle)', border: 'none', cursor: 'pointer' }}>✕ close</button>
      </div>
      <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: 12, fontSize: '.85rem' }}>
        <tbody>
          <Row k="Task" v={props.decision.taskId} />
          <Row k="Outcome" v={props.decision.outcome} />
          <Row k="Reason codes" v={props.decision.reasonCodes.join(', ') || '—'} />
          <Row k="Decision receipt" v={props.decision.decisionReceiptId ?? '—'} />
          <Row k="Execution receipt" v={props.decision.executionReceiptId ?? '—'} />
          {props.receipts.map((r) => (
            <Row key={`${r.sequence}`} v={`sha256:${r.eventHash}`} k={`Receipt #${r.sequence} hash`} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <tr style={{ borderBottom: '1px solid var(--border)' }}>
      <td style={{ padding: '6px 8px', color: 'var(--fg-subtle)', width: 200, verticalAlign: 'top' }}>{k}</td>
      <td className="mono" style={{ padding: '6px 8px', wordBreak: 'break-all' }}>{v}</td>
    </tr>
  );
}

// ------------------------------------------------------------ bottom side

function AuditPanel({ audit }: { audit: AuditDto | null }) {
  if (audit === null) return <SkeletonCard title="Audit trail" />;
  if (audit.error !== undefined) {
    return <div className="card" role="alert"><h2>Audit trail</h2><p style={{ color: 'var(--warn)' }} className="mono">{audit.error} — {audit.detail ?? 'unavailable'}</p></div>;
  }
  const last = audit.receipts.slice(-8).reverse();
  const integrityOk = audit.chain.valid && audit.checkpoint.signatureValid;
  return (
    <div className="card">
      <h2>Audit timeline</h2>
      <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
        <span className={`badge badge--${audit.chain.valid ? 'ok' : 'deny'}`}>
          Chain integrity: {audit.chain.valid ? `VERIFIED (${audit.receipts.length} receipts)` : 'BROKEN'}
        </span>
        <span className={`badge badge--${audit.checkpoint.signatureValid ? 'ok' : 'deny'}`}>
          Signed checkpoint: {audit.checkpoint.signatureValid ? 'VERIFIED' : 'INVALID'}
        </span>
        <span className="badge badge--neutral">head {shortHash(audit.checkpoint.headHash)}</span>
      </div>
      {last.length === 0 && <p style={{ color: 'var(--fg-subtle)' }}>No receipts yet — run a scenario.</p>}
      {last.map((r) => (
        <div key={`${r.sequence}`} style={{ display: 'grid', gridTemplateColumns: '36px 1fr auto', gap: 10, padding: '8px 0', borderTop: '1px solid var(--border)', fontSize: '.85rem' }}>
          <span className="mono" style={{ color: 'var(--fg-subtle)' }}>#{r.sequence}</span>
          <span>
            <span className="mono">{r.action}</span>{r.amount !== undefined && <span> · {r.amount} {r.currency}</span>}
            <div className="mono" style={{ color: 'var(--fg-subtle)', fontSize: '.72rem' }}>{r.recordedAt} · {r.taskId ?? ''}</div>
          </span>
          <span style={{ textAlign: 'right' }}>
            <span className={`badge badge--${r.effect === 'ALLOW' ? 'ok' : 'deny'}`}>{r.effect}</span>
            {r.executionState !== undefined && r.executionState !== 'NOT_EXECUTED' && (
              <span className={`badge badge--${r.executionState === 'SUCCEEDED' ? 'ok' : r.executionState === 'FAILED' ? 'deny' : 'warn'}`} style={{ marginLeft: 6 }}>
                {r.executionState}
              </span>
            )}
          </span>
        </div>
      ))}
    </div>
  );
}

function HistoryPanel({ profile }: { profile: ProfileDto | null }) {
  if (profile === null) return <SkeletonCard title="Recent history" />;
  const byAction = Object.entries(profile.profile.history.byAction);
  const integ = profile.profile.history.integrity;
  return (
    <div className="card">
      <h2>History summary</h2>
      <span className={`badge badge--${integ.verified ? 'ok' : 'warn'}`} style={{ marginBottom: 12 }}>
        {integ.verified ? 'verified against signed checkpoint' : `history fail-closed: ${integ.detail ?? 'integrity not verified'}`}
      </span>
      {byAction.length === 0 && <p style={{ color: 'var(--fg-subtle)' }}>No activity in this demo session yet.</p>}
      {byAction.map(([action, entry]) => (
        <div key={action} className="mono" style={{ padding: '6px 0', borderTop: '1px solid var(--border)', fontSize: '.85rem' }}>
          <strong>{action}</strong>
          <div style={{ display: 'flex', gap: 14, marginTop: 4, flexWrap: 'wrap' }}>
            <span style={{ color: 'var(--ok)' }}>ALLOW {entry.decisions.allow}</span>
            <span style={{ color: 'var(--deny)' }}>DENY {entry.decisions.deny}</span>
            <span style={{ color: 'var(--ok)' }}>SUCCEEDED {entry.execution.succeeded}</span>
            {entry.execution.failed > 0 && <span style={{ color: 'var(--deny)' }}>FAILED {entry.execution.failed}</span>}
            {entry.execution.uncertain > 0 && <span style={{ color: 'var(--warn)' }}>UNCERTAIN {entry.execution.uncertain}</span>}
          </div>
          {Object.entries(entry.reasonCodes).map(([code, n]) => (
            <div key={code} style={{ color: 'var(--fg-subtle)' }}>recent denial: {code} ×{n}</div>
          ))}
        </div>
      ))}
      <p style={{ color: 'var(--fg-subtle)', fontSize: '.78rem', marginTop: 8 }}>
        History describes what happened. It grants nothing: current authority is decided only by verified credentials + policy.
      </p>
    </div>
  );
}

function ArchitectureSnapshot() {
  const chain = ['Identity', 'Credentials', 'Authority', 'Status', 'Replay', 'Policy', 'Decision', 'Execution', 'Audit'];
  return (
    <section style={{ marginTop: 28 }}>
      <div className="card">
        <h2>Where trust is decided</h2>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          {chain.map((step, i) => (
            <span key={step} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span className="badge badge--neutral" style={{ fontSize: '.76rem' }}>{step}</span>
              {i < chain.length - 1 && <span aria-hidden style={{ color: 'var(--fg-subtle)' }}>→</span>}
            </span>
          ))}
        </div>
        <p style={{ color: 'var(--fg-subtle)', fontSize: '.82rem', marginBottom: 0, marginTop: 10 }}>
          Every stage runs in the trusted backend. The dashboard only renders the result.
        </p>
      </div>
    </section>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="label">{label}</div>
      <div className={mono ? 'value mono' : 'value'} style={{ wordBreak: 'break-all' }}>{value}</div>
    </div>
  );
}

function BadgeRow({ label, ok, text, warn, deny }: { label: string; ok: boolean; text: string; warn?: number; deny?: number }) {
  return (
    <div>
      <div className="label">{label}</div>
      <div>
        <span className={`badge badge--${ok ? 'ok' : 'deny'}`}>{text}</span>
        {(warn ?? 0) > 0 && <span className="badge badge--warn" style={{ marginLeft: 6 }}>suspended {warn}</span>}
        {(deny ?? 0) > 0 && <span className="badge badge--deny" style={{ marginLeft: 6 }}>revoked {deny}</span>}
      </div>
    </div>
  );
}

function SkeletonCard({ title }: { title: string }) {
  return (
    <div className="card" aria-busy="true">
      <h2>{title}</h2>
      <div style={{ height: 40, background: 'var(--neutral-bg)', borderRadius: 6 }} />
      <div className="mono" style={{ marginTop: 8, color: 'var(--fg-subtle)', fontSize: '.78rem' }}>
        Initializing secure demo…
      </div>
    </div>
  );
}
