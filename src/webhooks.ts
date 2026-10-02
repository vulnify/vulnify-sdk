import { createHmac, timingSafeEqual } from 'crypto';

/** `t=<unix seconds>,v1=<64 lowercase hex HMAC-SHA256>`. */
export const WEBHOOK_SIGNATURE_HEADER = 'x-vulnify-signature';
/** Delivery attempt, starting at 1. Retries reuse the delivery id and increase this. */
export const WEBHOOK_ATTEMPT_HEADER = 'x-vulnify-attempt';
/** Primary event type. Same as `body.type`. */
export const WEBHOOK_EVENT_HEADER = 'x-vulnify-event';
/** Delivery id. Same as `body.id`. */
export const WEBHOOK_DELIVERY_HEADER = 'x-vulnify-delivery';

const SIGNATURE = /^t=([0-9]+),v1=([0-9a-f]{64})$/;
const ATTEMPT = /^[1-9][0-9]*$/;
const DECISIONS = ['ALLOW', 'REVIEW', 'BLOCK'] as const;
const DECISION_EVENTS = ['BLOCK', 'REVIEW', 'CRITICAL'] as const;
const ACTIONS = ['READ_DATA', 'WRITE_DATA', 'DELETE_DATA', 'EXPORT_DATA', 'SEND_EMAIL'] as const;
const RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
const ANOMALY_KINDS = ['VOLUME_SPIKE', 'NEW_ACTION', 'NEW_EXTERNAL_DEST', 'RATE_SPIKE'] as const;
const ANOMALY_CODES = [
  'anomaly.volume_spike',
  'anomaly.new_action',
  'anomaly.new_external_destination',
  'anomaly.rate_spike',
] as const;

export type WebhookDecisionEvent = (typeof DECISION_EVENTS)[number];
export type WebhookAnomalyKind = (typeof ANOMALY_KINDS)[number];
export type WebhookAnomalyCode = (typeof ANOMALY_CODES)[number];

export interface WebhookDecisionData {
  /** Security event id. Same as the envelope `eventId`. */
  id: string;
  agent: string;
  action: (typeof ACTIONS)[number];
  resource: string;
  riskScore: number;
  riskLevel: (typeof RISK_LEVELS)[number];
  /** Recorded on the event. It does not change when a review is resolved. */
  decision: (typeof DECISIONS)[number];
  /** Effective outcome when the webhook was sent. */
  finalDecision: (typeof DECISIONS)[number];
}

export interface WebhookAnomalyData {
  /** Anomaly id. Same as the envelope `eventId`. */
  id: string;
  kind: WebhookAnomalyKind;
  severity: (typeof RISK_LEVELS)[number];
  /** English fallback. Render `messageCode` and `messageParams` for other languages. */
  message: string;
  agentId: string;
  messageCode: WebhookAnomalyCode;
  /** Values are strings, numbers, or null. */
  messageParams: { [key: string]: string | number | null };
}

export interface WebhookTestData {
  message: 'Test event from Vulnify';
  /** Webhook endpoint id. */
  webhookId: string;
  organizationId: string;
}

export interface WebhookDecisionPayload {
  /** Delivery id. The same value is sent on every retry. */
  id: string;
  /** Primary type. The first entry of `types`, and `X-Vulnify-Event`. */
  type: WebhookDecisionEvent;
  types: WebhookDecisionEvent[];
  /** Security event id. Same as `data.id`. */
  eventId: string;
  createdAt: string;
  data: WebhookDecisionData;
}

export interface WebhookAnomalyPayload {
  id: string;
  type: 'ANOMALY';
  types: 'ANOMALY'[];
  /** Anomaly id. Same as `data.id`. */
  eventId: string;
  createdAt: string;
  data: WebhookAnomalyData;
}

export interface WebhookTestPayload {
  id: string;
  type: 'TEST';
  types: 'TEST'[];
  /** `test-` followed by the delivery id. */
  eventId: string;
  createdAt: string;
  data: WebhookTestData;
}

/** Decision, anomaly, and test deliveries, distinguished by `type`. */
export type WebhookPayload = WebhookDecisionPayload | WebhookAnomalyPayload | WebhookTestPayload;

export type WebhookHeaders = { [name: string]: string | string[] | undefined };

export interface VerifyWebhookOptions {
  /** Maximum clock difference accepted, in seconds. Default 300. */
  toleranceSeconds?: number;
  /** Current time in ms (tests). */
  now?: number;
}

export class WebhookVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WebhookVerificationError';
  }
}

/**
 * Verifies a Vulnify webhook signature. Returns false when the header is missing, malformed,
 * expired, or does not match. Prefer {@link verifyWebhook}, which also parses the body.
 *
 * The header must be `t=<unix seconds>,v1=<64 lowercase hex>`. The MAC is HMAC-SHA256 of
 * `t.` + the raw body, keyed with the endpoint secret as UTF-8 (the whole `whsec_` value).
 */
export function verifyWebhookSignature(
  secret: string,
  signatureHeader: string | undefined,
  rawBody: string | Buffer | Uint8Array,
  options?: VerifyWebhookOptions,
): boolean {
  return signatureError(secret, signatureHeader, rawBody, options) === null;
}

/**
 * Verifies the signature and returns the parsed delivery.
 * Pass the raw body bytes exactly as received. Pass either the `X-Vulnify-Signature` value
 * or the request headers (`X-Vulnify-Event` and `X-Vulnify-Delivery` are checked when present).
 * Throws {@link WebhookVerificationError} when the signature or body is rejected.
 */
export function verifyWebhook(
  secret: string,
  rawBody: string | Buffer | Uint8Array,
  headersOrSignature: string | WebhookHeaders | { get(name: string): string | null | undefined } | undefined,
  options?: VerifyWebhookOptions,
): WebhookPayload {
  const signature = typeof headersOrSignature === 'string' || headersOrSignature == null
    ? headersOrSignature
    : headerValue(headersOrSignature, WEBHOOK_SIGNATURE_HEADER);
  const error = signatureError(secret, signature, rawBody, options);
  if (error) throw error;

  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText(rawBody));
  } catch {
    throw new WebhookVerificationError('Webhook body is not JSON');
  }
  if (!isWebhookPayload(parsed)) throw new WebhookVerificationError('Webhook body does not match a documented event');

  if (headersOrSignature && typeof headersOrSignature !== 'string') {
    const event = headerValue(headersOrSignature, WEBHOOK_EVENT_HEADER);
    if (event !== undefined && event !== parsed.type) {
      throw new WebhookVerificationError('X-Vulnify-Event does not match the signed body');
    }
    const delivery = headerValue(headersOrSignature, WEBHOOK_DELIVERY_HEADER);
    if (delivery !== undefined && delivery !== parsed.id) {
      throw new WebhookVerificationError('X-Vulnify-Delivery does not match the signed body');
    }
    const attempt = headerValue(headersOrSignature, WEBHOOK_ATTEMPT_HEADER);
    if (attempt !== undefined && !ATTEMPT.test(attempt)) {
      throw new WebhookVerificationError('X-Vulnify-Attempt is malformed');
    }
  }
  return parsed;
}

function signatureError(
  secret: string,
  signatureHeader: string | undefined,
  rawBody: string | Buffer | Uint8Array,
  { toleranceSeconds = 300, now = Date.now() }: VerifyWebhookOptions = {},
): WebhookVerificationError | null {
  if (!signatureHeader) return new WebhookVerificationError('Webhook signature is missing');
  const match = SIGNATURE.exec(signatureHeader);
  if (!match) return new WebhookVerificationError('Webhook signature is malformed');
  const timestamp = match[1];
  const skew = Math.abs(Math.floor(now / 1000) - Number(timestamp));
  if (skew > toleranceSeconds) {
    const direction = Number(timestamp) > Math.floor(now / 1000) ? 'in the future' : 'expired';
    return new WebhookVerificationError(`Webhook signature is ${direction} (tolerance ${toleranceSeconds}s)`);
  }
  const expected = createHmac('sha256', secret).update(`${timestamp}.${bodyText(rawBody)}`).digest();
  const given = Buffer.from(match[2], 'hex');
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
    return new WebhookVerificationError('Webhook signature does not match');
  }
  return null;
}

function bodyText(rawBody: string | Buffer | Uint8Array): string {
  if (typeof rawBody === 'string') return rawBody;
  return Buffer.from(rawBody).toString('utf8');
}

function headerValue(
  source: WebhookHeaders | { get(name: string): string | null | undefined },
  name: string,
): string | undefined {
  if (typeof (source as { get?: unknown }).get === 'function') {
    const value = (source as { get(name: string): string | null | undefined }).get(name);
    return value ?? undefined;
  }
  const record = source as WebhookHeaders;
  const key = Object.keys(record).find((item) => item.toLowerCase() === name);
  if (!key) return undefined;
  const value = record[key];
  return Array.isArray(value) ? value[0] : value;
}

function isWebhookPayload(value: unknown): value is WebhookPayload {
  if (!isRecord(value) || typeof value.id !== 'string' || typeof value.eventId !== 'string' || typeof value.createdAt !== 'string') {
    return false;
  }
  if (!Array.isArray(value.types) || value.types.length === 0 || value.types[0] !== value.type) return false;
  if (isDecisionEvent(value.type)) return value.types.every(isDecisionEvent) && isDecisionData(value.data);
  if (value.type === 'ANOMALY') return value.types.length === 1 && isAnomalyData(value.data);
  if (value.type === 'TEST') return value.types.length === 1 && isTestData(value.data);
  return false;
}

function isDecisionData(value: unknown): value is WebhookDecisionData {
  if (!isRecord(value)) return false;
  return (
    typeof value.id === 'string' &&
    typeof value.agent === 'string' &&
    isOneOf(value.action, ACTIONS) &&
    typeof value.resource === 'string' &&
    typeof value.riskScore === 'number' &&
    isOneOf(value.riskLevel, RISK_LEVELS) &&
    isOneOf(value.decision, DECISIONS) &&
    isOneOf(value.finalDecision, DECISIONS)
  );
}

function isAnomalyData(value: unknown): value is WebhookAnomalyData {
  if (!isRecord(value) || !isRecord(value.messageParams)) return false;
  return (
    typeof value.id === 'string' &&
    isOneOf(value.kind, ANOMALY_KINDS) &&
    isOneOf(value.severity, RISK_LEVELS) &&
    typeof value.message === 'string' &&
    typeof value.agentId === 'string' &&
    isOneOf(value.messageCode, ANOMALY_CODES) &&
    Object.values(value.messageParams).every((item) => item === null || typeof item === 'string' || typeof item === 'number')
  );
}

function isTestData(value: unknown): value is WebhookTestData {
  if (!isRecord(value)) return false;
  return value.message === 'Test event from Vulnify' && typeof value.webhookId === 'string' && typeof value.organizationId === 'string';
}

function isDecisionEvent(value: unknown): value is WebhookDecisionEvent {
  return isOneOf(value, DECISION_EVENTS);
}

function isOneOf<T extends string>(value: unknown, allowed: readonly T[]): value is T {
  return typeof value === 'string' && (allowed as readonly string[]).includes(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
