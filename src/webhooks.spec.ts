import { createHmac } from 'crypto';
import {
  WEBHOOK_ATTEMPT_HEADER,
  WEBHOOK_DELIVERY_HEADER,
  WEBHOOK_EVENT_HEADER,
  WEBHOOK_SIGNATURE_HEADER,
  WebhookVerificationError,
  verifyWebhook,
  verifyWebhookSignature,
} from './webhooks';

const sign = (secret: string, t: number, body: string) => `t=${t},v1=${createHmac('sha256', secret).update(`${t}.${body}`).digest('hex')}`;

const now = 1_800_000_000_000;
const t = now / 1000;
const secret = 'whsec_test_secret';

const decision = {
  id: '11111111-1111-4111-8111-111111111111',
  type: 'BLOCK',
  types: ['BLOCK'],
  eventId: '22222222-2222-4222-8222-222222222222',
  createdAt: '2026-10-02T20:00:00.000Z',
  data: {
    id: '22222222-2222-4222-8222-222222222222',
    agent: 'SalesBot',
    action: 'EXPORT_DATA',
    resource: 'Customer Database',
    riskScore: 90,
    riskLevel: 'HIGH',
    decision: 'BLOCK',
    finalDecision: 'BLOCK',
  },
};

const anomaly = {
  id: '33333333-3333-4333-8333-333333333333',
  type: 'ANOMALY',
  types: ['ANOMALY'],
  eventId: '44444444-4444-4444-8444-444444444444',
  createdAt: '2026-10-02T20:00:00.000Z',
  data: {
    id: '44444444-4444-4444-8444-444444444444',
    kind: 'VOLUME_SPIKE',
    severity: 'MEDIUM',
    message: 'Volume spike',
    agentId: '55555555-5555-4555-8555-555555555555',
    messageCode: 'anomaly.volume_spike',
    messageParams: { count: 12, note: null },
  },
};

const testEvent = {
  id: '66666666-6666-4666-8666-666666666666',
  type: 'TEST',
  types: ['TEST'],
  eventId: 'test-66666666-6666-4666-8666-666666666666',
  createdAt: '2026-10-02T20:00:00.000Z',
  data: {
    message: 'Test event from Vulnify',
    webhookId: '77777777-7777-4777-8777-777777777777',
    organizationId: '88888888-8888-4888-8888-888888888888',
  },
};

const headersFor = (body: { id: string; type: string }, signature: string) => ({
  [WEBHOOK_SIGNATURE_HEADER]: signature,
  [WEBHOOK_ATTEMPT_HEADER]: '1',
  [WEBHOOK_EVENT_HEADER]: body.type,
  [WEBHOOK_DELIVERY_HEADER]: body.id,
});

describe('verifyWebhookSignature', () => {
  const body = JSON.stringify(decision);

  it('accepts a valid signature for a string, Buffer, or Uint8Array body', () => {
    const signature = sign(secret, t, body);
    expect(verifyWebhookSignature(secret, signature, body, { now })).toBe(true);
    expect(verifyWebhookSignature(secret, signature, Buffer.from(body), { now })).toBe(true);
    expect(verifyWebhookSignature(secret, signature, new Uint8Array(Buffer.from(body)), { now })).toBe(true);
  });

  it('rejects a wrong secret, a tampered body, an expired or future timestamp, and a malformed header', () => {
    expect(verifyWebhookSignature('whsec_other', sign(secret, t, body), body, { now })).toBe(false);
    expect(verifyWebhookSignature(secret, sign(secret, t, body), body.replace('BLOCK', 'ALLOW'), { now })).toBe(false);
    expect(verifyWebhookSignature(secret, sign(secret, t - 301, body), body, { now })).toBe(false);
    expect(verifyWebhookSignature(secret, sign(secret, t + 301, body), body, { now })).toBe(false);
    expect(verifyWebhookSignature(secret, sign(secret, t - 300, body), body, { now })).toBe(true);
    expect(verifyWebhookSignature(secret, undefined, body, { now })).toBe(false);
    expect(verifyWebhookSignature(secret, 'v1=abc', body, { now })).toBe(false);
    expect(verifyWebhookSignature(secret, sign(secret, t, body).toUpperCase(), body, { now })).toBe(false);
  });
});

describe('verifyWebhook', () => {
  it.each([
    ['BLOCK', decision],
    ['REVIEW', { ...decision, type: 'REVIEW', types: ['REVIEW'], data: { ...decision.data, decision: 'REVIEW', finalDecision: 'REVIEW' } }],
    ['CRITICAL', { ...decision, type: 'CRITICAL', types: ['CRITICAL'], data: { ...decision.data, decision: 'ALLOW', finalDecision: 'ALLOW', riskLevel: 'CRITICAL' } }],
    ['ANOMALY', anomaly],
    ['TEST', testEvent],
  ] as const)('accepts a %s delivery', (_label, payload) => {
    const body = JSON.stringify(payload);
    const signature = sign(secret, t, body);
    const event = verifyWebhook(secret, body, headersFor(payload, signature), { now });
    expect(event).toEqual(payload);
    expect(verifyWebhook(secret, new Uint8Array(Buffer.from(body)), signature, { now })).toEqual(payload);
  });

  it('rejects a tampered body, a wrong secret, and an expired or future timestamp', () => {
    const body = JSON.stringify(decision);
    const signature = sign(secret, t, body);
    expect(() => verifyWebhook(secret, body.replace('BLOCK', 'ALLOW'), signature, { now })).toThrow(WebhookVerificationError);
    expect(() => verifyWebhook(secret, body.replace('BLOCK', 'ALLOW'), signature, { now })).toThrow('does not match');
    expect(() => verifyWebhook('whsec_other', body, signature, { now })).toThrow('does not match');
    expect(() => verifyWebhook(secret, body, sign(secret, t - 301, body), { now })).toThrow('expired');
    expect(() => verifyWebhook(secret, body, sign(secret, t + 301, body), { now })).toThrow('future');
  });

  it('rejects a missing or malformed signature and a header that disagrees with the body', () => {
    const body = JSON.stringify(decision);
    const signature = sign(secret, t, body);
    expect(() => verifyWebhook(secret, body, undefined, { now })).toThrow('missing');
    expect(() => verifyWebhook(secret, body, 't=1,v1=abcd', { now })).toThrow('malformed');
    expect(() => verifyWebhook(secret, body, { ...headersFor(decision, signature), [WEBHOOK_EVENT_HEADER]: 'REVIEW' }, { now })).toThrow('X-Vulnify-Event');
    expect(() => verifyWebhook(secret, body, { ...headersFor(decision, signature), [WEBHOOK_DELIVERY_HEADER]: 'other' }, { now })).toThrow('X-Vulnify-Delivery');
  });
});
