import { randomUUID } from 'crypto';

export type Decision = 'ALLOW' | 'REVIEW' | 'BLOCK';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface AgentAction {
  /** Agent name as registered in Vulnify (or use agentId). */
  agent?: string;
  agentId?: string;
  action: 'READ_DATA' | 'WRITE_DATA' | 'DELETE_DATA' | 'EXPORT_DATA' | 'SEND_EMAIL';
  /** Resource name as registered in Vulnify (or use resourceId). */
  resource?: string;
  resourceId?: string;
  destination?: 'INTERNAL' | 'EXTERNAL_EMAIL' | 'EXTERNAL_API';
  recordsAffected?: number;
  /** Optional content to scan for sensitive data (CPF, cards, secrets...). Scanned server-side, never stored. */
  content?: string;
}

export interface CheckOptions {
  /** Reuse the same key to make a retry safe (default: a fresh random key per check). */
  idempotencyKey?: string;
}

export type ReviewStatus = 'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED';

export interface ReviewInfo {
  status: ReviewStatus;
  expiresAt: string | null;
  decidedAt: string | null;
  note: string | null;
}

export interface VulnifyDecision {
  id: string | null;
  /** What you must obey. In monitor mode this is ALLOW even when evaluatedDecision is BLOCK. */
  decision: Decision;
  /** What would happen with full enforcement (differs from `decision` in monitor mode). */
  evaluatedDecision: Decision;
  /** True when Vulnify is in monitor mode and the action was recorded but not enforced. */
  monitored: boolean;
  /** Present when decision is REVIEW: a human must approve. */
  review: ReviewInfo | null;
  riskLevel: RiskLevel | null;
  riskScore: number | null;
  reasons: string[];
  policy: { id: string; name: string } | null;
  /** Sensitive data types found in `content` (the content itself is never stored). */
  dlpFindings: string[];
  /** LGPD data categories of the findings (IDENTIFICATION, CONTACT, LOCATION, FINANCIAL, HEALTH, COMPANY, CREDENTIALS). */
  lgpdCategories: string[];
  /** True when the organization is over its plan quota (decisions are still made). */
  quotaExceeded: boolean;
  /** True when the API key is a TEST key: the event is a sandbox event. */
  sandbox: boolean;
  /** True when Vulnify could not be reached and the failMode fallback was used. */
  degraded: boolean;
}

/** Older servers may omit the newer fields; defaults are filled in by the SDK. */
type ServerDecision = Omit<VulnifyDecision, 'degraded' | 'dlpFindings' | 'lgpdCategories' | 'quotaExceeded' | 'sandbox'> &
  Partial<Pick<VulnifyDecision, 'dlpFindings' | 'lgpdCategories' | 'quotaExceeded' | 'sandbox'>>;

export interface VulnifyOptions {
  apiKey: string;
  /** Defaults to http://localhost:3000 */
  baseUrl?: string;
  /** Request timeout in ms (default 3000). */
  timeoutMs?: number;
  /**
   * What to do when Vulnify is unreachable or times out.
   * 'closed' (default) blocks the action; 'open' allows it.
   */
  failMode?: 'open' | 'closed';
  /** Network retries with the same Idempotency-Key (default 2). Retries never create duplicate events. */
  retries?: number;
}

export interface WaitForReviewOptions {
  /** Give up after this many ms (default 5 minutes). */
  timeoutMs?: number;
  /** Poll interval in ms (default 2000). */
  pollMs?: number;
}

export type ReviewOutcome = ReviewStatus | 'TIMEOUT';

export class VulnifyBlockedError extends Error {
  constructor(public readonly result: VulnifyDecision) {
    super(`Vulnify ${result.decision}: ${result.reasons.join('; ') || 'no reason given'}`);
    this.name = 'VulnifyBlockedError';
  }
}

class VulnifyRequestError extends Error {}

export class Vulnify {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly failMode: 'open' | 'closed';
  private readonly retries: number;

  constructor(private readonly options: VulnifyOptions) {
    if (!options.apiKey) throw new Error('Vulnify: apiKey is required');
    this.baseUrl = (options.baseUrl ?? 'http://localhost:3000').replace(/\/$/, '');
    this.timeoutMs = options.timeoutMs ?? 3000;
    this.failMode = options.failMode ?? 'closed';
    this.retries = options.retries ?? 2;
  }

  /** Asks Vulnify for a decision. Network problems never throw; see failMode. */
  async check(action: AgentAction, options: CheckOptions = {}): Promise<VulnifyDecision> {
    const idempotencyKey = options.idempotencyKey ?? randomUUID();
    let lastError = 'network error';
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const res = await fetch(`${this.baseUrl}/v1/events`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this.options.apiKey}`, 'Idempotency-Key': idempotencyKey },
          body: JSON.stringify(action),
          signal: controller.signal,
        });
        if (res.status === 401 || res.status === 400 || res.status === 403 || res.status === 404) {
          // Configuration errors must be loud, never silently "fail open".
          const body = await res.json().catch(() => ({}));
          throw new VulnifyRequestError(`Vulnify request rejected (${res.status}): ${JSON.stringify(body.message ?? body)}`);
        }
        if (!res.ok) {
          lastError = `Vulnify responded ${res.status}`;
          continue;
        }
        const body = (await res.json()) as ServerDecision;
        return { dlpFindings: [], lgpdCategories: [], quotaExceeded: false, sandbox: false, ...body, degraded: false };
      } catch (err) {
        if (err instanceof VulnifyRequestError) throw err;
        lastError = err instanceof Error ? err.message : 'network error';
      } finally {
        clearTimeout(timer);
      }
    }
    return this.fallback(lastError);
  }

  /** Fetches the current state of a previous decision (used to poll a REVIEW). */
  async getEvent(id: string): Promise<VulnifyDecision> {
    const res = await fetch(`${this.baseUrl}/v1/events/${id}`, {
      headers: { Authorization: `Bearer ${this.options.apiKey}` },
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok) throw new VulnifyRequestError(`Vulnify request rejected (${res.status})`);
    return { dlpFindings: [], lgpdCategories: [], quotaExceeded: false, sandbox: false, ...((await res.json()) as ServerDecision), degraded: false };
  }

  /** Polls until a human approves or denies the review, it expires, or the timeout elapses. */
  async waitForReview(id: string, options: WaitForReviewOptions = {}): Promise<ReviewOutcome> {
    const deadline = Date.now() + (options.timeoutMs ?? 5 * 60_000);
    const pollMs = options.pollMs ?? 2000;
    for (;;) {
      const status = (await this.getEvent(id)).review?.status ?? 'PENDING';
      if (status !== 'PENDING') return status;
      if (Date.now() + pollMs > deadline) return 'TIMEOUT';
      await new Promise((r) => setTimeout(r, pollMs));
    }
  }

  /**
   * Runs `fn` only if Vulnify allows the action.
   * BLOCK throws VulnifyBlockedError. REVIEW throws too, unless `wait` is set: then it waits for a human
   * and runs `fn` only if the review is approved.
   */
  async guard<T>(action: AgentAction, fn: () => Promise<T> | T, wait?: WaitForReviewOptions): Promise<T> {
    const result = await this.check(action);
    if (result.decision === 'ALLOW') return fn();
    if (result.decision === 'REVIEW' && wait && result.id) {
      const outcome = await this.waitForReview(result.id, wait);
      if (outcome === 'APPROVED') return fn();
      throw new VulnifyBlockedError({ ...result, reasons: [...result.reasons, `Review ${outcome.toLowerCase()}`] });
    }
    throw new VulnifyBlockedError(result);
  }

  private fallback(reason: string): VulnifyDecision {
    return {
      id: null,
      decision: this.failMode === 'open' ? 'ALLOW' : 'BLOCK',
      evaluatedDecision: this.failMode === 'open' ? 'ALLOW' : 'BLOCK',
      monitored: false,
      review: null,
      riskLevel: null,
      riskScore: null,
      reasons: [`Vulnify unavailable (${reason}); failMode=${this.failMode}`],
      policy: null,
      dlpFindings: [],
      lgpdCategories: [],
      quotaExceeded: false,
      sandbox: false,
      degraded: true,
    };
  }
}

export * from './adapters';
export * from './webhooks';
