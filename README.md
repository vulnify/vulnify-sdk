# @vulnify/sdk

Runtime authorization for AI agents. Ask Vulnify whether an action is allowed before the agent runs it.

A check returns one of three decisions:

- `ALLOW` — the action may run.
- `REVIEW` — a person must approve it. `guard()` does not run the action unless you pass `wait` and the review is approved.
- `BLOCK` — the action must not run.

The default is fail-closed. If Vulnify cannot be reached or times out, the SDK returns `BLOCK` and sets `degraded` to `true`. Pass `failMode: 'open'` to allow the action in that case. Configuration errors (invalid API key, unknown agent or resource, rejected payload) always throw.

Optional `content` is scanned for sensitive data. The content is not stored. Matches come back on the decision as `dlpFindings`.

`baseUrl` defaults to `http://localhost:3000`. The production API is `https://api.vulnify.io`.

This package is not published to npm yet. Install it from this repository.

## Install

```bash
npm install github:vulnify/vulnify-sdk
```

Node.js 18 or newer.

## Usage

```ts
import { Vulnify, VulnifyBlockedError } from '@vulnify/sdk';

const vulnify = new Vulnify({
  apiKey: process.env.VULNIFY_API_KEY!,
  baseUrl: 'https://api.vulnify.io',
});

try {
  await vulnify.guard(
    {
      agent: 'SalesBot',
      action: 'EXPORT_DATA',
      resource: 'Customer Database',
      destination: 'EXTERNAL_EMAIL',
      recordsAffected: 12000,
      content: emailBody, // scanned, not stored
    },
    () => exportCustomers(),
    { timeoutMs: 120_000 }, // REVIEW waits for a person; runs only if approved
  );
} catch (err) {
  if (err instanceof VulnifyBlockedError) {
    console.error(err.result.decision, err.result.reasons);
  } else {
    throw err;
  }
}
```

`check()` returns the decision without running anything. Adapters in `src/adapters.ts` wrap LangChain, MCP, OpenAI Agents, and Vercel AI SDK tools without depending on those packages. `verifyWebhookSignature()` checks Vulnify webhook deliveries. Examples are in `examples/`.

Network retries reuse the same `Idempotency-Key`, so a retry does not create a duplicate event.

## Development

```bash
npm install
npm test
npm run build
```

## License

MIT. Copyright 2026 Vulnify.
