'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

import {
  Architecture,
  Comparison,
  DecisionStage,
  EvidenceSection,
  FailureExamples,
  Footer,
  Hero,
  Lifecycle,
  SectionHead,
  TopBar,
  type DemoStatus,
  type RunRecord,
  type Runs,
} from '@/components/sections';
import type { AttackReportDto, AuditDto, EvaluationDto, ProfileDto } from '@/lib/dto';
import { limitFromProfile } from '@/lib/presentation';

type ApiError = { error?: string; detail?: string };
const PRIMARY = new Set(['valid-120', 'over-5000', 'custom']);

function prefersReducedMotion(): boolean {
  return typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/** Returns an error message for an invalid amount, or the parsed positive number. */
function parseAmount(raw: string): { ok: true; value: number } | { ok: false; message: string } {
  const cleaned = raw.trim().replace(/,/g, '');
  if (cleaned === '') return { ok: false, message: 'Enter an amount, for example 250.' };
  const n = Number(cleaned);
  if (!Number.isFinite(n) || n <= 0) return { ok: false, message: 'Amount must be a positive number, for example 250.' };
  return { ok: true, value: n };
}

export default function Page() {
  const [profile, setProfile] = useState<ProfileDto | null>(null);
  const [audit, setAudit] = useState<AuditDto | null>(null);
  const [status, setStatus] = useState<DemoStatus | null>(null);
  const [report, setReport] = useState<AttackReportDto | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);

  const [runs, setRuns] = useState<Runs>({});
  const [last, setLast] = useState<RunRecord | undefined>(undefined);
  const [running, setRunning] = useState<string | null>(null);
  const [errorPrimary, setErrorPrimary] = useState<string | null>(null);
  const [errorOther, setErrorOther] = useState<string | null>(null);
  const [amount, setAmount] = useState('250');
  const [amountError, setAmountError] = useState<string | null>(null);
  const [bootError, setBootError] = useState<string | null>(null);
  const evSeq = useRef(0);
  // One request at a time. Buttons use aria-disabled (not `disabled`) so keyboard focus is never lost.
  // Each run owns a token; only the owner can release the lock, so a late `finally`
  // from an earlier run can never free a newer run's lock.
  const activeRef = useRef<number | null>(null);
  const seqRef = useRef(0);
  const begin = useCallback((id: string): number | null => {
    if (activeRef.current !== null) return null;
    const token = ++seqRef.current;
    activeRef.current = token;
    setRunning(id);
    return token;
  }, []);
  const release = useCallback((token: number) => {
    if (activeRef.current !== token) return;
    activeRef.current = null;
    setRunning(null);
  }, []);
  const lastReq = useRef<{ id: string; amount?: number; step?: 1 | 2 } | null>(null);
  const [evidenceStale, setEvidenceStale] = useState(false);

  const refresh = useCallback(async (attempt = 0): Promise<void> => {
    const generation = evSeq.current; // a newer evidence refresh (after a run) must never be overwritten by this one
    try {
      const [pr, ar, sr] = await Promise.all([
        fetch('/api/agents/support/profile'),
        fetch('/api/audit/acme-demo'),
        fetch('/api/demo/status'),
      ]);
      if (!pr.ok || !ar.ok) throw new Error('backend initializing');
      const [prJson, arJson] = await Promise.all([pr.json(), ar.json()]);
      if (generation === evSeq.current) {
        setProfile(prJson);
        setAudit(arJson);
      }
      if (sr.ok) {
        const s = (await sr.json()) as DemoStatus;
        if (s.dids !== undefined) setStatus(s);
      }
      setBootError(null);
    } catch {
      // Free hosts cold-start: the first request can outlive the first render.
      // Retry with backoff while keeping the honest "loading" state visible.
      if (attempt < 8) setTimeout(() => void refresh(attempt + 1), 900 + attempt * 800);
      else setBootError('The demo backend did not respond. It may be starting up — try again in a minute.');
    }
  }, []);

  useEffect(() => {
    void refresh();
    fetch('/api/attacks/report')
      .then(async (r) => {
        const j = (await r.json()) as AttackReportDto & ApiError;
        if (!r.ok || j.error !== undefined) throw new Error(j.error ?? `HTTP ${r.status}`);
        setReport(j);
      })
      .catch((e: unknown) => setReportError(e instanceof Error ? e.message : String(e)));
  }, [refresh]);

  /** One real gateway call. Returns the backend's response; decides nothing. */
  const evaluate = useCallback(async (id: string, customAmount?: number): Promise<RunRecord | undefined> => {
    const body = id === 'custom' ? { amount: customAmount } : { preset: id };
    const res = await fetch('/api/trust/evaluate', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const json = (await res.json()) as EvaluationDto & ApiError;
    if (!res.ok || json.error !== undefined) {
      throw new Error(`${json.error ?? 'ERROR'}${json.detail ? `: ${json.detail}` : ''}`);
    }
    const rec: RunRecord = { evaluation: json, at: Date.now() };
    setRuns((prev) => ({ ...prev, [id]: rec }));
    return rec;
  }, []);

  const reloadEvidence = useCallback(async () => {
    const mine = ++evSeq.current; // only the newest refresh may update the panels
    try {
      const [pr, ar] = await Promise.all([fetch('/api/agents/support/profile'), fetch('/api/audit/acme-demo')]);
      if (!pr.ok || !ar.ok) throw new Error('evidence refresh failed');
      const [p, a] = await Promise.all([pr.json(), ar.json()]);
      if (mine !== evSeq.current) return;
      setProfile(p);
      setAudit(a);
      setEvidenceStale(false);
    } catch {
      // The panels keep their previous content, which no longer includes the latest run: say so.
      if (mine === evSeq.current) setEvidenceStale(true);
    }
  }, []);

  const scrollToVerdict = useCallback(() => {
    requestAnimationFrame(() => {
      // Stacked (phone/tablet) layout: the verdict sits below the buttons, so align it to the top of the screen.
      // Focus is never moved — it stays on the button that was pressed, so keyboard users keep their place.
      const stacked = window.matchMedia('(max-width: 899px)').matches;
      document.getElementById('verdict-anchor')?.scrollIntoView({ block: stacked ? 'start' : 'nearest', behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
    });
  }, []);

  const runPrimary = useCallback(
    async (id: string, customAmount?: number) => {
      const token = begin(id);
      if (token === null) return;
      lastReq.current = { id, amount: customAmount };
      setErrorPrimary(null);
      try {
        const rec = await evaluate(id, customAmount);
        if (rec !== undefined) setLast(rec);
        release(token); // the verdict is on screen; refresh the evidence panels in the background
        scrollToVerdict();
        await reloadEvidence();
      } catch (e) {
        setErrorPrimary(e instanceof Error ? e.message : String(e));
      } finally {
        release(token);
      }
    },
    [begin, release, evaluate, reloadEvidence, scrollToVerdict],
  );

  const runBoth = useCallback(
    async (startAt: 1 | 2 = 1) => {
      const token = begin('both');
      if (token === null) return;
      lastReq.current = { id: 'both', step: startAt };
      setErrorPrimary(null);
      try {
        if (startAt === 1) {
          await evaluate('valid-120');
          lastReq.current = { id: 'both', step: 2 }; // the 120 SAR leg succeeded: a retry must not repeat it
        }
        const second = await evaluate('over-5000');
        if (second !== undefined) setLast(second);
        release(token);
        scrollToVerdict();
        await reloadEvidence();
      } catch (e) {
        setErrorPrimary(e instanceof Error ? e.message : String(e));
        if (lastReq.current?.step === 2) void reloadEvidence(); // partial success: the first leg is already in the log
      } finally {
        release(token);
      }
    },
    [begin, release, evaluate, reloadEvidence, scrollToVerdict],
  );

  const runCustom = useCallback(() => {
    const parsed = parseAmount(amount);
    if (!parsed.ok) {
      setAmountError(parsed.message);
      return;
    }
    setAmountError(null);
    void runPrimary('custom', parsed.value);
  }, [amount, runPrimary]);

  const runOther = useCallback(
    async (id: string) => {
      const token = begin(id);
      if (token === null) return;
      setErrorOther(null);
      try {
        // Presets that belong to the main demo also update the main verdict.
        const rec = await evaluate(id);
        if (rec !== undefined && PRIMARY.has(id)) setLast(rec);
        release(token);
        await reloadEvidence();
      } catch (e) {
        setErrorOther(e instanceof Error ? e.message : String(e));
      } finally {
        release(token);
      }
    },
    [begin, release, evaluate, reloadEvidence],
  );

  const retryLast = useCallback(() => {
    const req = lastReq.current;
    setErrorPrimary(null);
    if (req === null) return;
    if (req.id === 'both') void runBoth(req.step ?? 1);
    else void runPrimary(req.id, req.amount);
  }, [runBoth, runPrimary]);

  const limit = limitFromProfile(profile);

  return (
    <div className="page">
      <TopBar />

      <main id="main">
        <Hero />

        {bootError !== null && (
          <div className="err" role="alert" style={{ marginBottom: 'var(--s5)' }}>
            <strong>Backend not ready.</strong> {bootError}{' '}
            <button type="button" className="btn btn--small" onClick={() => { setBootError(null); void refresh(); }}>Retry</button>
          </div>
        )}

        <DecisionStage
          profile={profile}
          status={status}
          runs={runs}
          last={last}
          running={running}
          error={errorPrimary}
          amount={amount}
          amountError={amountError}
          onAmount={(v) => { setAmount(v); setAmountError(null); }}
          onRun={(id) => void runPrimary(id)}
          onCustom={runCustom}
          onBoth={() => void runBoth()}
          onRetry={retryLast}
        />
        <Comparison runs={runs} />

        <section className="section" id="failures" aria-labelledby="failures-h">
          <SectionHead id="failures-h" eyebrow="Failure thinking" title="What if something is wrong?">
            Each case is a real request through the same gateway and must be denied. (In the replay case the first send is legitimate — one authorization, one execution — and only the identical re-send must be refused.)
          </SectionHead>
          {errorOther !== null && (
            <div className="err" role="alert" style={{ marginBottom: 'var(--s4)' }}>
              <strong>The request could not be completed.</strong> <span className="mono wrap-any">{errorOther}</span>
            </div>
          )}
          <FailureExamples runs={runs} running={running} onRun={(id) => void runOther(id)} limit={limit} />
        </section>

        <section className="section" id="lifecycle" aria-labelledby="life-h">
          <SectionHead id="life-h" eyebrow="Grant · scope · revoke" title="How trust is granted, narrowed and withdrawn">
            One delegation, three steps — each tied to something you can run or a test that proves it.
          </SectionHead>
          <Lifecycle profile={profile} runs={runs} running={running} onRun={(id) => void runOther(id)} />
        </section>

        <section className="section" id="evidence" aria-labelledby="ev-h">
          <SectionHead id="ev-h" eyebrow="Evidence" title="Proof you can check" />
          {evidenceStale && (
            <div className="callout" role="status" style={{ marginBottom: 'var(--s4)' }}>
              <strong>The evidence panels could not be refreshed after the last request,</strong> so they may not include it.{' '}
              <button type="button" className="btn btn--small" onClick={() => void reloadEvidence()}>Reload evidence</button>
            </div>
          )}
          <EvidenceSection profile={profile} audit={audit} status={status} report={report} reportError={reportError} />
        </section>

        <section className="section" id="architecture" aria-labelledby="arch-h">
          <SectionHead id="arch-h" eyebrow="Architecture" title="Identity → claims → verification → policy">
            Every step runs in the trusted backend. This page only renders what the gateway already decided.
          </SectionHead>
          <Architecture />
        </section>
      </main>

      <Footer />
    </div>
  );
}
