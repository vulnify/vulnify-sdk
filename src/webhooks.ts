import { createHmac, timingSafeEqual } from 'crypto';

/** Header carrying `t=<unix seconds>,v1=<hex HMAC-SHA256(secret, `${t}.${rawBody}`)>`. */
export const WEBHOOK_SIGNATURE_HEADER = 'x-vulnify-signature';

export interface VerifyWebhookOptions {
  /** Maximum clock difference accepted, in seconds (replay protection). Default 300. */
  toleranceSeconds?: number;
  /** Current time in ms (tests). */
  now?: number;
}

/**
 * Verifies a Vulnify webhook. Pass the raw request body exactly as received (not re-serialized JSON)
 * and the secret shown when the endpoint was created or its secret rotated.
 */
export function verifyWebhookSignature(
  secret: string,
  signatureHeader: string | undefined,
  rawBody: string | Buffer,
  { toleranceSeconds = 300, now = Date.now() }: VerifyWebhookOptions = {},
): boolean {
  if (!signatureHeader) return false;
  let timestamp = NaN;
  const candidates: string[] = [];
  for (const part of signatureHeader.split(',')) {
    const [k, v] = part.trim().split('=', 2);
    if (k === 't') timestamp = Number(v);
    else if (k === 'v1' && v) candidates.push(v);
  }
  if (!Number.isInteger(timestamp) || !candidates.length) return false;
  if (Math.abs(Math.floor(now / 1000) - timestamp) > toleranceSeconds) return false;
  const body = typeof rawBody === 'string' ? rawBody : rawBody.toString('utf8');
  const expected = createHmac('sha256', secret).update(`${timestamp}.${body}`).digest();
  return candidates.some((sig) => {
    const given = Buffer.from(sig, 'hex');
    return given.length === expected.length && timingSafeEqual(given, expected);
  });
}
