# Releasing @vulnify/sdk

Publish by pushing a git tag. The [release workflow](.github/workflows/release.yml) installs, tests, builds, checks the package, publishes to npm, and attaches a CycloneDX SBOM to the GitHub release. Do not run `npm publish` from a laptop, and do not create the GitHub release by hand.

This repository uses **npm trusted publishing** (GitHub Actions OIDC). There is no `NPM_TOKEN` secret. The workflow has `permissions: id-token: write` and runs `npm publish --provenance --access public` on a GitHub-hosted runner. Provenance is requested with `--provenance` and is also generated automatically when the publish authenticates with OIDC from this public repository.

## One-time setup on npmjs.com

A maintainer of `@vulnify/sdk` (the package already exists; it was published by the npm user `giozadi`) adds a trusted publisher. npm does not check the form until a publish runs.

1. Open the package settings: https://www.npmjs.com/package/@vulnify/sdk/access (Trusted Publisher is under package settings).
2. Add a GitHub Actions publisher with these values exactly. They are case-sensitive. The workflow filename is only the file name, not the path.
   - Organization or user: `vulnify`
   - Repository: `vulnify-sdk`
   - Workflow filename: `release.yml`
   - Environment name: leave empty. The workflow does not set a GitHub environment.
   - Allowed actions: allow direct `npm publish`. Configurations created after 3 September 2026 default to staged publish only, which this workflow does not use.
3. Confirm `repository.url` in `package.json` stays `git+https://github.com/vulnify/vulnify-sdk.git`. Provenance rejects a mismatch.
4. After one successful trusted publish, package settings can require two-factor authentication and disallow tokens. Do that only after the workflow has published once.

No GitHub secret is required for publish. Do not add `NPM_TOKEN` for this workflow. The package has no private dependencies, so `npm ci` does not need a read token either.

Self-hosted runners cannot use trusted publishing. The workflow uses `ubuntu-latest`.

## Cutting a release

1. On `main`, set `package.json` `"version"` to the new version and add a `CHANGELOG.md` entry. Land that change through a pull request.
2. Check the version out locally and tag **that** commit. The tag must be `v` plus the exact `package.json` version. The workflow refuses to publish when they differ.

   ```bash
   git checkout main
   git pull origin main
   git tag -a v0.2.2 -m "v0.2.2"
   git push origin v0.2.2
   ```

3. Watch the Release workflow. It publishes `@vulnify/sdk@<version>` and opens the GitHub release for that tag with `sbom.cdx.json` attached. The same file is a workflow artifact named `sbom`.
4. Do not push another tag for a version that is already on npm. npm will reject the publish, and the version cannot be reused.

`v0.2.1` is the first version this workflow published. `v0.2.0` is already tagged and must stay unpublished. See below.

## Existing tags and npm history

Checked on 2 October 2026:

| Version | npm | Git tag |
| --- | --- | --- |
| 0.1.0 | Published 2026-09-30. npm `gitHead` `9d28839` is not in this repo. | `v0.1.0` → `f51532db032e46d2f69fe33d6e03c48cb13af494`. Do not move it. |
| 0.1.1 | Published 2026-10-01 from `ccf67f56837508507a46baad74d58e3d2f3f471d`. | Annotated tag `v0.1.1` is on that commit. The release workflow is not in it, so the tag did not publish. |
| 0.2.0 | Not published. | Annotated tag `v0.2.0` → `99eae03d666e4f3471d7d11a1553caf22d32f4b1`. Leave this tag where it is. Do not delete it, move it, or re-run its workflow. That commit still fails open on some 4xx responses, including 413. |
| 0.2.1 | Published 2026-10-02 from `41c47503bf0aa2be0e7da518e596e51325e0cf4e`. | Annotated tag `v0.2.1` is on that commit. |
| 0.2.2 | Not published until the merge commit is tagged. | Tag `v0.2.2` only after `package.json` on `main` is `0.2.2`. |

The `v0.2.0` publish failed because `actions/setup-node` was given `registry-url`. That writes `//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}` and, with no token configured, sets `NODE_AUTH_TOKEN` to the placeholder `XXXXX-XXXXX-XXXXX-XXXXX`. npm used that placeholder instead of the GitHub OIDC exchange, and the registry answered `E404` for `PUT /@vulnify%2fsdk`. The workflow no longer sets `registry-url`. No `NPM_TOKEN` secret is required.
