import type { AgentQuarantineStore } from '@agent-trust/vc';

/**
 * Emergency kill switch, per AGENT IDENTITY (not per credential):
 * quarantine(reason) blocks every credential the agent presents,
 * regardless of status; release() restores normal verification.
 *
 * Distinct semantics — revocation: "this credential is permanently
 * invalid"; suspension: "this credential is temporarily inactive";
 * quarantine: "this agent is temporarily blocked, full stop".
 */
export class InMemoryAgentQuarantineStore implements AgentQuarantineStore {
  readonly #quarantined = new Map<string, string>();

  quarantine(agentDid: string, reason: string): void {
    this.#quarantined.set(agentDid, reason);
  }

  release(agentDid: string): void {
    this.#quarantined.delete(agentDid);
  }

  reason(agentDid: string): string | undefined {
    return this.#quarantined.get(agentDid);
  }

  async isQuarantined(agentDid: string): Promise<boolean> {
    return this.#quarantined.has(agentDid);
  }
}
