import { createHmac } from 'crypto';
import { verifyWebhookSignature } from './webhooks';

const sign = (secret: string, t: number, body: string) => `t=${t},v1=${createHmac('sha256', secret).update(`${t}.${body}`).digest('hex')}`;

describe('verifyWebhookSignature', () => {
  const body = '{"id":"d1","type":"BLOCK"}';
  const now = 1_800_000_000_000;
  const t = now / 1000;

  it('accepts a valid signature (string or Buffer body)', () => {
    expect(verifyWebhookSignature('whsec_a', sign('whsec_a', t, body), body, { now })).toBe(true);
    expect(verifyWebhookSignature('whsec_a', sign('whsec_a', t, body), Buffer.from(body), { now })).toBe(true);
  });

  it('rejects wrong secret, tampered body, stale timestamp and malformed headers', () => {
    expect(verifyWebhookSignature('whsec_b', sign('whsec_a', t, body), body, { now })).toBe(false);
    expect(verifyWebhookSignature('whsec_a', sign('whsec_a', t, body), body.replace('BLOCK', 'ALLOW'), { now })).toBe(false);
    expect(verifyWebhookSignature('whsec_a', sign('whsec_a', t - 301, body), body, { now })).toBe(false);
    expect(verifyWebhookSignature('whsec_a', undefined, body, { now })).toBe(false);
    expect(verifyWebhookSignature('whsec_a', 'v1=abc', body, { now })).toBe(false);
  });
});
