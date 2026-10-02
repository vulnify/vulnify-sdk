# Changelog

## 0.2.0

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
