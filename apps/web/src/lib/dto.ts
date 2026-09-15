/** Safe DTO shapes the server sends to the browser. No private material,
 *  no full credentials — identifiers, digests, and decisions only. */

export interface DecisionDto {
  taskId: string;
  outcome: string;
  effect?: 'ALLOW' | 'DENY';
  reasonCodes: string[];
  stages: {
    identity: string;
    replay: string;
    credential: string;
    authority: string;
    policy: string;
    audit: string;
    execution: string;
  };
  decisionReceiptId?: string;
  executionReceiptId?: string;
}

export interface ReceiptDto {
  sequence: number;
  recordedAt: string;
  actorDid: string;
  action: string;
  resource: string;
  amount?: number;
  currency?: string;
  effect: string;
  reasonCodes: string[];
  executionState?: string;
  taskId?: string;
  eventHash: string;
  receiptId: string;
}

export interface EvaluationDto {
  result: DecisionDto;
  firstResult?: DecisionDto;
  runReceipts: ReceiptDto[];
  note?: string;
  error?: string;
  detail?: string;
}

export interface ProfileDto {
  profile: {
    agent: { did: string; controller?: string };
    generatedAt: string;
    identity: { resolved: boolean; verificationMethodCount?: number };
    authority: {
      active: {
        credentialId: string;
        issuer: string;
        actions: string[];
        resources: string[];
        audience?: string[];
        limits?: { amount?: number; currency?: string };
        applicable: boolean;
        evidenceDigest: string;
      }[];
    };
    credentials: { active: number; suspended: number; revoked: number };
    attestations: {
      trusted: { credentialId: string; issuer: string; type: string; statement: string; domain: string; validUntil?: string }[];
      rejected: { credentialId?: string; issuer?: string; reasonCodes: string[] }[];
    };
    history: {
      integrity: { verified: boolean; verifiedThroughSequence?: number; detail?: string };
      byAction: Record<
        string,
        {
          decisions: { allow: number; deny: number };
          execution: { succeeded: number; failed: number; uncertain: number };
          reasonCodes: Record<string, number>;
          lastObservedAt?: string;
        }
      >;
    };
  };
  error?: string;
}

export interface AuditDto {
  receipts: ReceiptDto[];
  chain: { valid: boolean; receipts?: number; reasonCodes?: string[]; firstBrokenSequence?: number };
  checkpoint: { id: string; sequence: number; signatureValid: boolean; chainMatches: boolean; headHash: string };
  error?: string;
  detail?: string;
}

export interface AttackScenarioDto {
  id: string;
  kind: 'ATTACK' | 'FAILURE_DEMO';
  category: string;
  title: string;
  status: 'PASS' | 'FAIL';
  expected: { outcome: string; reasonCode?: string };
  observed: { outcome: string; reasonCodes: string[]; invariants: Record<string, unknown> };
  durationMs: number;
  detail?: string;
}

export interface AttackReportDto {
  suite: string;
  baselineCommit: string;
  summary: {
    total: number;
    attacks: number;
    failureDemos: number;
    passed: number;
    failed: number;
    byCategory: Record<string, { total: number; passed: number }>;
  };
  scenarios: AttackScenarioDto[];
}
