import { randomUUID } from 'crypto';

export type Decision = 'ALLOW' | 'REVIEW' | 'BLOCK';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type LgpdCategory = 'IDENTIFICATION' | 'CONTACT' | 'LOCATION' | 'FINANCIAL' | 'HEALTH' | 'COMPANY' | 'CREDENTIALS';

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
  /**
   * Outcome recorded on the event. It does not change when a review is resolved.
   * In monitor mode this is ALLOW even when evaluatedDecision is BLOCK.
   */
  decision: Decision;
  /**
   * Effective outcome. REVIEW while a review is pending, ALLOW after approval,
   * BLOCK after denial or expiry. Equals `decision` when there is no review.
   * Omitted on idempotent replays of decisions stored before this field existed.
   * When it is absent, obey `decision`.
   */
  finalDecision?: Decision;
  /** What would happen with full enforcement (differs from `decision` in monitor mode). */
  evaluatedDecision: Decision;
  /** True when Vulnify is in monitor mode and the action was recorded but not enforced. */
  monitored: boolean;
  /** Present when the event has a human review. */
  review: ReviewInfo | null;
  riskLevel: RiskLevel | null;
  riskScore: number | null;
  reasons: string[];
  policy: { id: string; name: string } | null;
  /** Sensitive data types found in `content` (the content itself is never stored). */
  dlpFindings: string[];
  /** LGPD data categories of the findings. */
  lgpdCategories: LgpdCategory[];
  /** True when the organization is over its plan quota (decisions are still made). */
  quotaExceeded: boolean;
  /** True when the API key is a TEST key: the event is a sandbox event. */
  sandbox: boolean;
  /** True when Vulnify could not be reached and the failMode fallback was used. */
  degraded: boolean;
}

/** Older servers and old idempotent replays may omit the newer fields. `finalDecision` is left absent. */
type ServerDecision = Omit<VulnifyDecision, 'degraded' | 'dlpFindings' | 'lgpdCategories' | 'quotaExceeded' | 'sandbox' | 'finalDecision'> &
  Partial<Pick<VulnifyDecision, 'dlpFindings' | 'lgpdCategories' | 'quotaExceeded' | 'sandbox' | 'finalDecision'>>;

function fromServer(body: ServerDecision): VulnifyDecision {
  return { dlpFindings: [], lgpdCategories: [], quotaExceeded: false, sandbox: false, ...body, degraded: false };
}

/** Outcome to obey. Falls back to the stored decision when `finalDecision` was not sent. */
function effectiveDecision(result: Pick<VulnifyDecision, 'decision' | 'finalDecision'>): Decision {
  return result.finalDecision ?? result.decision;
}

export interface VulnifyOptions {
  apiKey: string;
  /** Defaults to https://api.vulnify.io. Pass another URL for local development or a private deployment. */
  baseUrl?: string;
  /** Request timeout in ms (default 3000). */
  timeoutMs?: number;
  /**
   * What to do when Vulnify is unreachable or returns a transient status (408, 429, or 5xx).
   * 'closed' (default) blocks the action; 'open' allows it.
   * Any other 4xx is a rejected request and throws. failMode does not apply to it.
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
    const outcome = result.finalDecision ?? result.decision;
    super(`Vulnify ${outcome}: ${result.reasons.join('; ') || 'no reason given'}`);
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
    this.baseUrl = (options.baseUrl ?? 'https://api.vulnify.io').replace(/\/$/, '');
    this.timeoutMs = options.timeoutMs ?? 3000;
    this.failMode = options.failMode ?? 'closed';
    this.retries = options.retries ?? 2;
  }

  /**
   * Asks Vulnify for a decision.
   * Network errors, timeouts, 408, 429, and 5xx follow failMode and do not throw.
   * Any other 4xx throws. failMode never turns a rejected request into a decision.
   */
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
        // 408 and 429 are transient. Every other 4xx rejected the request, so retrying or
        // failing open would let an action through that Vulnify never evaluated.
        if (res.status >= 400 && res.status < 500 && res.status !== 408 && res.status !== 429) {
          const body = await res.json().catch(() => ({}));
          throw new VulnifyRequestError(`Vulnify request rejected (${res.status}): ${JSON.stringify(body.message ?? body)}`);
        }
        if (!res.ok) {
          lastError = `Vulnify responded ${res.status}`;
          continue;
        }
        return fromServer((await res.json()) as ServerDecision);
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
    return fromServer((await res.json()) as ServerDecision);
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
    const outcome = effectiveDecision(result);
    if (outcome === 'ALLOW') return fn();
    if (outcome === 'REVIEW' && wait && result.id) {
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
