# @vulnify/sdk

Runtime authorization for AI agents. Before the agent exports or sends customer records, your app asks Vulnify. The decision is `ALLOW`, `REVIEW`, or `BLOCK`. The score is an integer from 0 to 100 and comes back with reasons.

Vulnify sees action metadata — agent, action, resource, destination, and record count — not the records. In monitor mode the event is stored and not enforced: obey `decision`. `evaluatedDecision` is what enforcement would have returned, and `monitored` is `true`. If Vulnify cannot be reached, the default is fail-closed.

Production API: https://api.vulnify.io

## Install

```bash
npm install @vulnify/sdk
```

Node.js 18 or newer.

## Production scenario

An agent is about to export customer records to an external destination. Call `check()` first.

- `ALLOW` runs the export.
- `REVIEW` stops and tells the caller a human must approve. The export does not run.
- `BLOCK` does not run the export.
- If Vulnify cannot be reached, `check()` returns `BLOCK` with `degraded: true`. The export does not run.

Set `VULNIFY_API_KEY`. `VULNIFY_BASE_URL` overrides the host; when it is unset this example uses `https://api.vulnify.io`. Omitting `baseUrl` in the constructor falls back to `http://localhost:3000`.

```ts
import { Vulnify } from '@vulnify/sdk';

const apiKey = process.env.VULNIFY_API_KEY;
if (!apiKey) {
  throw new Error('Set VULNIFY_API_KEY');
}

const vulnify = new Vulnify({
  apiKey,
  baseUrl: process.env.VULNIFY_BASE_URL ?? 'https://api.vulnify.io',
});

/** Replace the body with the real export. It runs only after ALLOW. */
async function exportCustomerRecords(): Promise<void> {
  console.log('exporting customer records to the external destination');
}

async function main(): Promise<void> {
  const decision = await vulnify.check({
    agent: 'SalesBot',
    action: 'EXPORT_DATA',
    resource: 'Customer Database',
    destination: 'EXTERNAL_EMAIL',
    recordsAffected: 12000,
  });

  if (decision.decision === 'ALLOW') {
    await exportCustomerRecords();
    return;
  }

  const reasons = decision.reasons.join('; ') || 'no reason given';

  if (decision.decision === 'REVIEW') {
    const score = decision.riskScore == null ? 'unknown' : String(decision.riskScore);
    throw new Error(
      `A human must approve this export before it runs (event ${decision.id ?? 'none'}, score ${score}). ${reasons}`,
    );
  }

  throw new Error(
    decision.degraded
      ? `Vulnify could not be reached. The export was not run. ${reasons}`
      : `Export blocked. The export was not run. ${reasons}`,
  );
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
```

A `REVIEW` is approved on the Vulnify server (Slack, an MFA step-up, or a separate approver). This process does not approve it and does not poll. A separate MCP or HTTP gateway injects secrets only after `ALLOW`.

`guard(action, fn)` runs `fn` only for `ALLOW` and throws `VulnifyBlockedError` for `REVIEW` and `BLOCK`. Pass `wait` only when you mean to poll until someone approves. Retries reuse the same `Idempotency-Key`, so a retry does not create a second event.

## Decisions

- `ALLOW` — run the action. `riskScore` is 0–100. `reasons` explains the score.
- `REVIEW` — do not run the action. `review.status` starts as `PENDING`. Tell the caller a human must approve.
- `BLOCK` — do not run the action.

Follow `decision` in monitor mode as well. An invalid API key, an unknown agent or resource, or a rejected payload throws. `failMode: 'open'` does not swallow those errors.

Optional `content` is scanned for sensitive data and is not stored. Matches return on `dlpFindings`.

## Fail-closed

`failMode` defaults to `'closed'`. A timeout or a network error becomes `decision: 'BLOCK'`, `degraded: true`, and a reason beginning with `Vulnify unavailable`. The scenario above does not call `exportCustomerRecords()`. Set `failMode: 'open'` only when an outage should let the action through.

Audit events are hash-chained. SIEM export is JSON or CEF. Evidence in the product maps to LGPD, ISO/IEC 42001, NIST AI RMF, and the EU AI Act. That mapping is not a certification.

Adapters in `src/adapters.ts` wrap LangChain, MCP, OpenAI Agents, and Vercel AI SDK tools without taking those packages as dependencies. `verifyWebhookSignature()` checks webhook deliveries. Longer samples are in `examples/`.

## Development

```bash
npm install
npm test
npm run build
```

## License

MIT. Copyright 2026 Vulnify.
