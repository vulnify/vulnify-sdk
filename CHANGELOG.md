# Changelog

## 0.2.2

- `check()` and `getEvent()` include optional `finalDecision`: `REVIEW` while a review is pending, `ALLOW` after approval, `BLOCK` after denial or expiry. The stored `decision` does not change. Idempotent replays of older decisions may omit `finalDecision`; obey `finalDecision ?? decision`. `guard()` follows that same rule.
- `getEvent()` returns the same decision body as `check()`, including `quotaExceeded`, `sandbox`, and `lgpdCategories`.
- `lgpdCategories` is the LGPD category union from the API (`IDENTIFICATION`, `CONTACT`, `LOCATION`, `FINANCIAL`, `HEALTH`, `COMPANY`, `CREDENTIALS`) instead of `string[]`. Reading the field is unchanged. Constructing a `VulnifyDecision` with any other category no longer typechecks.
- Commit `spec/openapi.json` (fetched from `https://api.vulnify.io/openapi.json`) and generate `src/generated/openapi.ts`. CI regenerates those types from the committed spec and fails on drift. `tsc` fails if the public decision types diverge from that generated event body. The live document does not define webhook payloads, so the SDK still only verifies webhook signatures.

## 0.2.1

- Client errors (4xx other than 408 and 429) throw, including 413 when the body is over the API limit. `failMode: 'open'` no longer returns a degraded `ALLOW` for a request Vulnify rejected without evaluating. 408, 429, 5xx, timeouts, and network errors still follow `failMode`.
- The release workflow no longer asks `actions/setup-node` for a registry auth token, so npm trusted publishing can use GitHub OIDC. `0.2.0` was not published; this is the first release that includes the 4xx fix.

## 0.2.0

Not published. Tag `v0.2.0` points at this changelog, and that commit still treats some 4xx responses as outages. Do not publish it. Release `0.2.1` instead.

- The default `baseUrl` is `https://api.vulnify.io`. Pass `baseUrl` to use another host, including local development.
- Ship ESM and CommonJS builds. The `exports` map resolves `types`, `import`, and `require` to the matching files.
- Add a tag-triggered release workflow (npm trusted publishing, provenance, CycloneDX SBOM) and release notes in `RELEASING.md`.

## 0.1.1

- Document a production export check a caller can copy: `ALLOW` runs the export, `REVIEW` stops and asks for a human, and `BLOCK` or an unreachable API does not run it.

## 0.1.0

Initial standalone release of `@vulnify/sdk`.

- Ask Vulnify for a runtime decision before an AI agent action runs: `ALLOW`, `REVIEW`, or `BLOCK`.
- Fail closed by default when Vulnify cannot be reached.
- Optional content is scanned for sensitive data and is not stored.
- `baseUrl` defaults to `http://localhost:3000`. The production API is `https://api.vulnify.io`.
