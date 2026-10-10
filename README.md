<p align="center">
  <img src="https://raw.githubusercontent.com/vulnify/vulnify-sdk/main/.github/assets/og-1200x630.png" alt="Vulnify. Decide every AI agent action before it runs. ALLOW, REVIEW, or BLOCK, with the reasons and the proof." width="800">
</p>

<h1 align="center">@vulnify/sdk</h1>

<p align="center">Runtime authorization for AI agents. Ask before the action runs. The answer is ALLOW, REVIEW, or BLOCK.</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@vulnify/sdk"><img src="https://img.shields.io/npm/v/@vulnify/sdk" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/@vulnify/sdk"><img src="https://img.shields.io/npm/dm/@vulnify/sdk" alt="npm downloads"></a>
  <a href="https://github.com/vulnify/vulnify-sdk/blob/main/LICENSE"><img src="https://img.shields.io/npm/l/@vulnify/sdk" alt="license"></a>
  <a href="https://github.com/vulnify/vulnify-sdk/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/vulnify/vulnify-sdk/ci.yml?branch=main&label=CI" alt="CI status"></a>
</p>

<p align="center">
  <a href="https://docs.vulnify.io">Docs</a>
  ·
  <a href="https://github.com/vulnify/vulnify-mcp">MCP</a>
  ·
  <a href="https://github.com/vulnify/vulnify-sdk/blob/main/CHANGELOG.md">Changelog</a>
</p>

Vulnify sees action metadata — agent, action, resource, destination, and record count — not the records. The score is an integer from 0 to 100 and comes back with reasons. The default API is `https://api.vulnify.io`. Node.js 18 or newer.

## Install

```bash
npm install @vulnify/sdk
```

## Quickstart

An agent is about to export customer records. Call `check()` first. Set `VULNIFY_API_KEY`. Set `VULNIFY_BASE_URL` only when the client should talk to a host other than `https://api.vulnify.io`.

- `ALLOW` runs the export.
- `REVIEW` stops and tells the caller a human must approve. The export does not run.
- `BLOCK` does not run the export.
- If Vulnify cannot be reached, `check()` returns `BLOCK` with `degraded: true`. The export does not run.

```ts
import { Vulnify } from '@vulnify/sdk';

const apiKey = process.env.VULNIFY_API_KEY;
if (!apiKey) {
  throw new Error('Set VULNIFY_API_KEY');
}

const vulnify = new Vulnify({
  apiKey,
  baseUrl: process.env.VULNIFY_BASE_URL,
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

  const outcome = decision.finalDecision;

  if (outcome === 'ALLOW') {
    await exportCustomerRecords();
    return;
  }

  const reasons = decision.reasons.join('; ') || 'no reason given';

  if (outcome === 'REVIEW') {
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

A `REVIEW` is approved on the Vulnify server. This process does not approve it and does not poll. `guard(action, fn)` runs `fn` only for `ALLOW` and throws `VulnifyBlockedError` for `REVIEW` and `BLOCK`. Pass `wait` only when you mean to poll until someone approves. Retries reuse the same `Idempotency-Key`, so a retry does not create a second event.

## How it works

Obey `finalDecision`. `decision` is the outcome recorded on the event and does not change when a review is resolved. `finalDecision` is the effective outcome: `REVIEW` while a review is pending, `ALLOW` after approval, and `BLOCK` after denial or expiry. Current responses always include it, including idempotent replays.

<p align="center">
  <img src="https://raw.githubusercontent.com/vulnify/vulnify-sdk/main/.github/assets/how-it-works.svg" alt="An agent action goes to check(). The result is ALLOW (run the action), REVIEW (wait for a person), or BLOCK (do not run it)." width="800">
</p>

- `ALLOW` — run the action. `riskScore` is 0–100. `reasons` explains the score.
- `REVIEW` — do not run the action. `review.status` starts as `PENDING`. Tell the caller a human must approve.
- `BLOCK` — do not run the action. A denied or expired review keeps the stored `decision` (often `REVIEW`) and sets `finalDecision` to `BLOCK`.

`evaluatedDecision` is what enforcement would have returned. In monitor mode the event is stored and not enforced (`monitored` is `true`): still obey `finalDecision`. `getEvent()` returns the same body as `check()`, including `quotaExceeded`, `sandbox`, and `lgpdCategories`.

`failMode` defaults to `'closed'`. A timeout, a network error, or a transient response (408, 429, or 5xx) becomes `decision: 'BLOCK'`, `degraded: true`, and a reason beginning with `Vulnify unavailable`. Set `failMode: 'open'` only when an outage should let the action through. Any other 4xx throws, including 413 when the body is over the API limit, so a rejected request is not treated as an outage.

An evidence or audit export is a JSON or CSV download that includes a SHA-256 checksum. In settings, SIEM export is JSON or CEF lines. Evidence in the product maps to LGPD, ISO/IEC 42001, NIST AI RMF, and the EU AI Act. That mapping is not a certification.

Optional `content` is scanned for sensitive data and is not stored. Matches return on `dlpFindings`.

## Product

<p align="center">
  <img src="https://raw.githubusercontent.com/vulnify/vulnify-sdk/main/.github/assets/audit-logs.webp" alt="Audit log of SalesBot and SupportBot decisions, each marked allowed." width="800">
</p>

## MCP server

The MCP server is public at [github.com/vulnify/vulnify-mcp](https://github.com/vulnify/vulnify-mcp). Its npm package, `@vulnify/mcp`, is being published. That server is separate from this package and from `POST /v1/gateway/mcp`.

Hosted server: `https://mcp.vulnify.io/mcp`. Send the API key as `Authorization: Bearer <key>` or as `X-Vulnify-Key`.

Local stdio server:

```bash
VULNIFY_API_KEY=vln_live_... npx -y @vulnify/mcp
```

If the API key uses an IP allowlist, calls from the hosted server come from that server's egress address. Use `npx` so the calls come from your own network.

`POST /v1/gateway/mcp` evaluates one MCP tool call. The tool name is mapped to an action, and the response is the same decision body as `POST /v1/events`. It is not an MCP server. `guardMcpHandler()` in this package wraps a local tool handler and calls `check()` before the handler runs.

## Configuration

| Option | Default | |
| --- | --- | --- |
| `apiKey` | required | `Authorization: Bearer`. The API also accepts `X-API-Key`. |
| `baseUrl` | `https://api.vulnify.io` | No trailing slash required. |
| `timeoutMs` | `3000` | Per request. |
| `failMode` | `'closed'` | `'open'` or `'closed'`. Applies to timeouts, network errors, 408, 429, and 5xx. |
| `retries` | `2` | Same `Idempotency-Key`. A retry does not create a second event. |

| Environment variable | |
| --- | --- |
| `VULNIFY_API_KEY` | API key for the SDK client and the CLI. Overrides `~/.config/vulnify/credentials.json`. |
| `VULNIFY_BASE_URL` | API origin. Overrides the credentials file. Default `https://api.vulnify.io`. |
| `VULNIFY_WEBHOOK_SECRET` | Endpoint secret (`whsec_…`) for `verifyWebhook()`. |

| Method | |
| --- | --- |
| `check(action)` | `POST /v1/events`. Returns the decision. |
| `getEvent(id)` | `GET /v1/events/{id}`. Same body as `check()`. |
| `waitForReview(id)` | Polls until the review is approved, denied, expired, or the wait times out. |
| `guard(action, fn)` | Runs `fn` only when `finalDecision` is `ALLOW`. |

| Webhook helper | |
| --- | --- |
| `verifyWebhook(secret, rawBody, headers)` | Checks the signature and returns a typed payload. Throws `WebhookVerificationError`. |
| `verifyWebhookSignature(secret, rawBody, signature)` | Same signature check as a boolean. Does not parse the body. |

Header names: `WEBHOOK_SIGNATURE_HEADER` (`x-vulnify-signature`), `WEBHOOK_ATTEMPT_HEADER`, `WEBHOOK_EVENT_HEADER`, `WEBHOOK_DELIVERY_HEADER`.

Adapters in `src/adapters.ts` wrap LangChain, MCP, OpenAI Agents, and Vercel AI SDK tools without taking those packages as dependencies: `guardFunction`, `guardedTools`, `guardLangChainTool`, `guardMcpHandler`, `guardOpenAIAgentsTool`, `guardAiSdkTools`. Longer samples are in `examples/`.

## Webhooks

`verifyWebhook()` checks `X-Vulnify-Signature` and returns the delivery. The signature is `t=<unix seconds>,v1=<64 lowercase hex>`. The MAC is HMAC-SHA256 of `t.` plus the raw body, keyed with the endpoint secret as UTF-8 (the whole `whsec_` value, not base64-decoded). The default clock tolerance is 300 seconds.

The body must be the exact bytes Vulnify sent. Canonical JSON has sorted keys. Parsing the body and stringifying it again changes those bytes and the signature will not match. Read the raw body first, then call `verifyWebhook`.

```ts
import { WebhookVerificationError, verifyWebhook } from '@vulnify/sdk';
import type { IncomingMessage, ServerResponse } from 'http';

export function handleVulnifyWebhook(req: IncomingMessage, res: ServerResponse, rawBody: Buffer): void {
  try {
    const event = verifyWebhook(process.env.VULNIFY_WEBHOOK_SECRET ?? '', rawBody, req.headers);
    if (event.type === 'BLOCK' || event.type === 'REVIEW' || event.type === 'CRITICAL') {
      console.log(event.data.finalDecision, event.eventId);
    }
    res.writeHead(204);
    res.end();
  } catch (err) {
    if (err instanceof WebhookVerificationError) {
      res.writeHead(400);
      res.end(err.message);
      return;
    }
    throw err;
  }
}
```

With Express, mount `express.raw({ type: 'application/json' })` on this route so `req.body` is a `Buffer`. Do not use `express.json()` on the same route: it parses the body before your handler runs, and the signature is over the original bytes.

`X-Vulnify-Event` matches `type`. `X-Vulnify-Delivery` matches `id` (the delivery id; dedupe retries on it). `X-Vulnify-Attempt` starts at 1. A decision delivery is `BLOCK`, `REVIEW`, or `CRITICAL` (`CRITICAL` can be combined with `BLOCK` or `REVIEW` in `types`). Anomaly deliveries use `ANOMALY`. A test delivery uses `TEST` and is not a security decision. A `TEST` `eventId` must start with `test-`.

## CLI

`@vulnify/sdk` ships a `vulnify` binary.

```bash
npx -p @vulnify/sdk vulnify --help
```

`vulnify init` creates `vulnify/policies/example.yaml` and `vulnify/tests/example.test.yaml`. `vulnify login` checks the key with `GET /v1/events/{id}` and stores it in `~/.config/vulnify/credentials.json` with mode `0600`. `VULNIFY_API_KEY` and `VULNIFY_BASE_URL` override that file.

`vulnify check` calls `check()` (`POST /v1/events`). The exit code is `0` for `ALLOW`, `2` for `REVIEW`, and `3` for `BLOCK`, using `finalDecision`. A LIVE key (`vln_live_…`) prints a warning because the call records a real event. If Vulnify cannot be reached, the command exits `1` instead of treating the fail-closed fallback as a policy `BLOCK`.

`vulnify policies validate` checks `kind: Policy` documents offline against `schema/policies.v1.json` and prints `file:line` errors. That file is the policies-as-code contract (also exported as `@vulnify/sdk/schema/policies.v1.json`). `spec.action` is the action family (`ANY`, `READ`, `WRITE`, `DELETE`, `EXPORT`). `spec.resource` is a resource type (`CUSTOMER_PII` and the other types the app stores), or null. A condition is the policy-engine object: `minRecords` means `recordsAffected >= n`, `maxRecords` means `recordsAffected <= n`, plus `minRiskScore`, `destination` (`EXTERNAL` or `INTERNAL`), `destinationContains`, `containsSensitiveData`, `outsideBusinessHours`, `agentIds`, `allOf`, and `anyOf`. A specific event action such as `EXPORT_DATA` belongs in `condition.action`. `recordsAffected: { gt: 1000 }` is not valid; more than 1000 records is `minRecords: 1001`.

`vulnify policies pull` writes one YAML file per policy from `GET /v1/policies`. `vulnify policies apply` sends those files to `POST /v1/policies/apply` (`--dry-run`, `--prune`). `vulnify test` sends `kind: PolicyTest` cases to `POST /v1/policies/test` and exits `1` when any case fails. `--local` includes the policies in `vulnify/policies`. Test `input.action` is the event action and `input.resource` is the resource name.

When pull, apply, or test receives HTTP 404, the CLI prints `This Vulnify server does not support policies as code yet` and exits `4`. An auth failure exits `5`. Every command accepts `--json`. The CLI does not send telemetry.

## Development

```bash
npm install
npm test
npm run build
npm run check:package
```

## Support

Questions and bug reports: [GitHub issues](https://github.com/vulnify/vulnify-sdk/issues). Product documentation: [docs.vulnify.io](https://docs.vulnify.io).

## Security

Report a vulnerability to [security@vulnify.io](mailto:security@vulnify.io). The disclosure process is at [vulnify.io/disclosure](https://www.vulnify.io/disclosure). See [SECURITY.md](SECURITY.md).

## License

MIT. Copyright 2026 Vulnify.
