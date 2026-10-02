import { Vulnify, VulnifyBlockedError } from './index';

const action = { agent: 'SalesBot', action: 'EXPORT_DATA', resource: 'Customer Database' } as const;
const reply = (status: number, body: unknown) =>
  jest.fn().mockResolvedValue({ ok: status < 400, status, json: async () => body });
const allow = { id: '1', decision: 'ALLOW', evaluatedDecision: 'ALLOW', monitored: false, review: null, riskLevel: 'LOW', riskScore: 5, reasons: [], policy: null, dlpFindings: [], quotaExceeded: false, sandbox: false };

describe('Vulnify SDK', () => {
  it('defaults baseUrl to the production API', async () => {
    const fetchMock = reply(200, allow);
    global.fetch = fetchMock as never;
    await new Vulnify({ apiKey: 'k' }).check(action);
    expect(fetchMock.mock.calls[0][0]).toBe('https://api.vulnify.io/v1/events');
  });

  it('sends the API key and returns the decision', async () => {
    const fetchMock = reply(200, allow);
    global.fetch = fetchMock as never;
    const r = await new Vulnify({ apiKey: 'vln_live_x', baseUrl: 'http://api.test/' }).check(action);
    expect(r).toMatchObject({ decision: 'ALLOW', degraded: false });
    expect(fetchMock.mock.calls[0][0]).toBe('http://api.test/v1/events');
    expect(fetchMock.mock.calls[0][1].headers.Authorization).toBe('Bearer vln_live_x');
  });

  it('guard() runs the function only when allowed', async () => {
    const v = new Vulnify({ apiKey: 'k' });
    global.fetch = reply(200, { ...allow, decision: 'BLOCK', riskLevel: 'CRITICAL', reasons: ['External destination'] }) as never;
    const fn = jest.fn();
    await expect(v.guard(action, fn)).rejects.toBeInstanceOf(VulnifyBlockedError);
    expect(fn).not.toHaveBeenCalled();

    global.fetch = reply(200, allow) as never;
    await expect(v.guard(action, async () => 'done')).resolves.toBe('done');
  });

  it('REVIEW is not allowed to proceed', async () => {
    global.fetch = reply(200, { ...allow, decision: 'REVIEW' }) as never;
    await expect(new Vulnify({ apiKey: 'k' }).guard(action, () => 1)).rejects.toThrow('REVIEW');
  });

  it('fails closed by default and does not run the export', async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('ECONNREFUSED')) as never;
    const exportCustomers = jest.fn();
    const decision = await new Vulnify({ apiKey: 'k' }).check({
      agent: 'SalesBot',
      action: 'EXPORT_DATA',
      resource: 'Customer Database',
      destination: 'EXTERNAL_EMAIL',
      recordsAffected: 12000,
    });
    expect(decision).toMatchObject({ decision: 'BLOCK', degraded: true, id: null });
    expect(decision.reasons[0]).toContain('failMode=closed');
    if (decision.decision === 'ALLOW') exportCustomers();
    expect(exportCustomers).not.toHaveBeenCalled();

    const open = await new Vulnify({ apiKey: 'k', failMode: 'open' }).check(action);
    expect(open).toMatchObject({ decision: 'ALLOW', degraded: true });
  });

  it('retries network errors with the same Idempotency-Key, then follows failMode', async () => {
    const fetchMock = jest.fn().mockRejectedValueOnce(new Error('ECONNRESET')).mockResolvedValueOnce({ ok: true, status: 200, json: async () => allow });
    global.fetch = fetchMock as never;
    const r = await new Vulnify({ apiKey: 'k' }).check(action);
    expect(r.decision).toBe('ALLOW');
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const keys = fetchMock.mock.calls.map((c) => c[1].headers['Idempotency-Key']);
    expect(keys[0]).toBeTruthy();
    expect(keys[0]).toBe(keys[1]);

    global.fetch = jest.fn().mockRejectedValue(new Error('down')) as never;
    expect((await new Vulnify({ apiKey: 'k', retries: 1 }).check(action)).degraded).toBe(true);
  });

  it('sends content for DLP and rejects a forbidden bound key loudly', async () => {
    const fetchMock = reply(200, { ...allow, dlpFindings: ['CPF'] });
    global.fetch = fetchMock as never;
    const r = await new Vulnify({ apiKey: 'k' }).check({ ...action, content: 'CPF 529.982.247-25' });
    expect(r.dlpFindings).toEqual(['CPF']);
    expect(r.lgpdCategories).toEqual([]); // older servers: filled in by the SDK
    expect(JSON.parse(fetchMock.mock.calls[0][1].body).content).toContain('CPF');
    global.fetch = reply(403, { message: 'bound to a different agent' }) as never;
    await expect(new Vulnify({ apiKey: 'k', failMode: 'open' }).check(action)).rejects.toThrow('rejected (403)');
  });

  it('server 5xx follows failMode but a bad API key is always loud', async () => {
    global.fetch = reply(503, {}) as never;
    expect((await new Vulnify({ apiKey: 'k', failMode: 'open' }).check(action)).degraded).toBe(true);
    global.fetch = reply(401, { message: 'Invalid API key' }) as never;
    await expect(new Vulnify({ apiKey: 'bad', failMode: 'open' }).check(action)).rejects.toThrow('rejected (401)');
  });

  it('rejects client errors even when failMode is open, and does not retry them', async () => {
    for (const status of [400, 403, 404, 409, 413, 422]) {
      const fetchMock = reply(status, { message: `rejected ${status}` });
      global.fetch = fetchMock as never;
      await expect(new Vulnify({ apiKey: 'k', failMode: 'open', retries: 2 }).check(action)).rejects.toThrow(`rejected (${status})`);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    }
  });

  it('does not fail open on 413 when the body is over the API limit', async () => {
    const fetchMock = reply(413, { message: 'request entity too large' });
    global.fetch = fetchMock as never;
    await expect(new Vulnify({ apiKey: 'k', failMode: 'open' }).check(action)).rejects.toThrow('rejected (413)');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('treats 408 and 429 as transient and then follows failMode', async () => {
    global.fetch = reply(429, { message: 'slow down' }) as never;
    const limited = await new Vulnify({ apiKey: 'k', failMode: 'open', retries: 1 }).check(action);
    expect(limited).toMatchObject({ decision: 'ALLOW', degraded: true });
    expect(limited.reasons[0]).toContain('429');

    global.fetch = reply(408, {}) as never;
    const timedOut = await new Vulnify({ apiKey: 'k', failMode: 'closed', retries: 0 }).check(action);
    expect(timedOut).toMatchObject({ decision: 'BLOCK', degraded: true });
    expect(timedOut.reasons[0]).toContain('408');
  });

  it('returns finalDecision and leaves it absent when the server omits it', async () => {
    global.fetch = reply(200, { ...allow, decision: 'REVIEW', finalDecision: 'ALLOW' }) as never;
    const approved = await new Vulnify({ apiKey: 'k' }).check(action);
    expect(approved.finalDecision).toBe('ALLOW');
    expect(approved.decision).toBe('REVIEW');

    global.fetch = reply(200, allow) as never;
    const replay = await new Vulnify({ apiKey: 'k' }).check(action);
    expect(replay.decision).toBe('ALLOW');
    expect(Object.hasOwn(replay, 'finalDecision')).toBe(false);
  });

  it('guard() obeys finalDecision when a stored REVIEW was later approved or denied', async () => {
    global.fetch = reply(200, { ...allow, decision: 'REVIEW', finalDecision: 'ALLOW' }) as never;
    await expect(new Vulnify({ apiKey: 'k' }).guard(action, async () => 'ran')).resolves.toBe('ran');

    global.fetch = reply(200, { ...allow, decision: 'REVIEW', finalDecision: 'BLOCK', reasons: ['denied'] }) as never;
    const fn = jest.fn();
    await expect(new Vulnify({ apiKey: 'k' }).guard(action, fn)).rejects.toThrow('BLOCK');
    expect(fn).not.toHaveBeenCalled();

    global.fetch = reply(200, { ...allow, decision: 'REVIEW' }) as never;
    await expect(new Vulnify({ apiKey: 'k' }).guard(action, fn)).rejects.toThrow('REVIEW');
  });

  it('reads a decision at GET /v1/events/:id with the bearer API key', async () => {
    const fetchMock = reply(200, { ...allow, id: 'evt_1' });
    global.fetch = fetchMock as never;
    const event = await new Vulnify({ apiKey: 'vln_live_x', baseUrl: 'https://api.vulnify.io' }).getEvent('evt_1');
    expect(event).toMatchObject({ id: 'evt_1', decision: 'ALLOW', degraded: false, quotaExceeded: false, sandbox: false, lgpdCategories: [] });
    expect(Object.hasOwn(event, 'finalDecision')).toBe(false);
    expect(fetchMock.mock.calls[0][0]).toBe('https://api.vulnify.io/v1/events/evt_1');
    expect(fetchMock.mock.calls[0][1].method ?? 'GET').toBe('GET');
    expect(fetchMock.mock.calls[0][1].headers.Authorization).toBe('Bearer vln_live_x');

    global.fetch = reply(401, { message: 'Invalid API key' }) as never;
    await expect(new Vulnify({ apiKey: 'bad', failMode: 'open' }).getEvent('evt_1')).rejects.toThrow('rejected (401)');

    const full = {
      ...allow,
      id: 'evt_2',
      decision: 'REVIEW',
      finalDecision: 'BLOCK',
      lgpdCategories: ['IDENTIFICATION'],
      quotaExceeded: true,
      sandbox: true,
    };
    global.fetch = reply(200, full) as never;
    const polled = await new Vulnify({ apiKey: 'k' }).getEvent('evt_2');
    expect(polled).toMatchObject({
      id: 'evt_2',
      decision: 'REVIEW',
      finalDecision: 'BLOCK',
      lgpdCategories: ['IDENTIFICATION'],
      quotaExceeded: true,
      sandbox: true,
      degraded: false,
    });
  });

  describe('review flow', () => {
    const pending = { ...allow, id: 'r1', decision: 'REVIEW', review: { status: 'PENDING', expiresAt: null, decidedAt: null, note: null } };
    const withStatus = (status: string) => ({ ...pending, review: { ...pending.review, status } });

    it('guard() with wait runs fn after approval', async () => {
      global.fetch = jest
        .fn()
        .mockResolvedValueOnce({ ok: true, status: 200, json: async () => pending })
        .mockResolvedValueOnce({ ok: true, status: 200, json: async () => withStatus('PENDING') })
        .mockResolvedValueOnce({ ok: true, status: 200, json: async () => withStatus('APPROVED') }) as never;
      const fn = jest.fn().mockResolvedValue('sent');
      await expect(new Vulnify({ apiKey: 'k' }).guard(action, fn, { pollMs: 1, timeoutMs: 1000 })).resolves.toBe('sent');
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('guard() with wait blocks when the review is denied', async () => {
      global.fetch = jest
        .fn()
        .mockResolvedValueOnce({ ok: true, status: 200, json: async () => pending })
        .mockResolvedValueOnce({ ok: true, status: 200, json: async () => withStatus('DENIED') }) as never;
      const fn = jest.fn();
      await expect(new Vulnify({ apiKey: 'k' }).guard(action, fn, { pollMs: 1 })).rejects.toThrow('denied');
      expect(fn).not.toHaveBeenCalled();
    });

    it('waitForReview returns TIMEOUT when nobody answers', async () => {
      global.fetch = jest.fn().mockResolvedValue({ ok: true, status: 200, json: async () => withStatus('PENDING') }) as never;
      await expect(new Vulnify({ apiKey: 'k' }).waitForReview('r1', { pollMs: 5, timeoutMs: 20 })).resolves.toBe('TIMEOUT');
    });
  });
});
