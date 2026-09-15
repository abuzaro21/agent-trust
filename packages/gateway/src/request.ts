import type { AgentProof } from '@agent-trust/schemas';
import { requestBodyDigestOf } from '@agent-trust/crypto';

/**
 * AgentTaskRequest (Step 10B) — the wire contract reuses the EXISTING
 * AgentProof format (kid/jti/iat/exp/signature bound to htu +
 * requestBodyDigest) and the existing trust-evaluate-request JSON Schema.
 * No second proof format.
 *
 * The proof's requestBodyDigest covers the canonical TASK CONTENT below —
 * credentials included, so a captured request cannot be recombined with
 * different credentials. The gateway recomputes the digest from the
 * received fields; a wire mutation without re-signing fails PoP.
 */
export interface AgentTaskRequest {
  taskId: string;
  actor: string;
  audience: string;
  action: string;
  resource: string;
  parameters?: { amount?: number; currency?: string };
  nonce?: string;
  credentials: string[];
  proof: AgentProof;
}

/** The canonical task content the proof must bind to. */
export function taskContent(request: {
  taskId: string;
  actor: string;
  audience: string;
  action: string;
  resource: string;
  parameters?: { amount?: number; currency?: string };
  nonce?: string;
  credentials: string[];
}): Record<string, unknown> {
  const content: Record<string, unknown> = {
    action: request.action,
    actor: request.actor,
    audience: request.audience,
    credentials: request.credentials,
    resource: request.resource,
    taskId: request.taskId,
  };
  if (request.parameters !== undefined) content.parameters = request.parameters;
  if (request.nonce !== undefined) content.nonce = request.nonce;
  return content;
}

/** Digest the gateway recomputes from received fields. */
export function taskRequestDigest(request: AgentTaskRequest): string {
  return requestBodyDigestOf(taskContent(request));
}

/** Default htu the gateway's PoP proofs bind to. */
export const GATEWAY_HTU = 'https://trust-gateway.internal/v1/tasks';

/**
 * Agent-side helper: build a signed task request. Uses the SAME PoP
 * primitives as everything else — one proof format end to end.
 */
export async function createTaskRequest(input: {
  signer: import('@agent-trust/crypto').Signer;
  taskId: string;
  actor: string;
  audience: string;
  action: string;
  resource: string;
  parameters?: { amount?: number; currency?: string };
  nonce?: string;
  credentials: string[];
  now: number;
  ttlSeconds?: number;
  htu?: string;
}): Promise<AgentTaskRequest> {
  const request: AgentTaskRequest = {
    taskId: input.taskId,
    actor: input.actor,
    audience: input.audience,
    action: input.action,
    resource: input.resource,
    credentials: input.credentials,
    ...(input.parameters !== undefined ? { parameters: input.parameters } : {}),
    ...(input.nonce !== undefined ? { nonce: input.nonce } : {}),
    proof: {
      kid: '',
      jti: '',
      iat: 0,
      exp: 0,
      signature: '',
    },
  };
  const { createProof } = await import('@agent-trust/crypto');
  const proof = await createProof(input.signer, {
    htu: input.htu ?? GATEWAY_HTU,
    requestBodyDigest: taskRequestDigest(request),
    // JTI_PATTERN-safe: alphanumeric + separators only (Step 7N).
    jti: `jti-${input.taskId.replace(/[^A-Za-z0-9]/g, '').slice(0, 24)}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`,
    iat: input.now,
    exp: input.now + (input.ttlSeconds ?? 300),
    ...(input.nonce !== undefined ? { nonce: input.nonce } : {}),
  });
  request.proof = proof;
  return request;
}
