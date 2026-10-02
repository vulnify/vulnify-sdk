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
   git tag -a v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```

3. Watch the Release workflow. It publishes `@vulnify/sdk@<version>` and opens the GitHub release for that tag with `sbom.cdx.json` attached. The same file is a workflow artifact named `sbom`.
4. Do not push another tag for a version that is already on npm. npm will reject the publish, and the version cannot be reused.

`v0.2.0` is the first release this workflow should publish. The commands above are the ones to run after this change is on `main`.

## Existing tags and npm history

Checked on 2 October 2026:

| Version | npm publish | npm `gitHead` | Git tag in this repo |
| --- | --- | --- | --- |
| 0.1.0 | 2026-09-30 | `9d288394540d55a5ae8e415f25f123437dea68c2` | `v0.1.0` → `f51532db032e46d2f69fe33d6e03c48cb13af494` (`docs: install the SDK from npm`) |
| 0.1.1 | 2026-10-01 | `ccf67f56837508507a46baad74d58e3d2f3f471d` | no `v0.1.1` tag |

`v0.1.1` should be tagged retroactively on `ccf67f56837508507a46baad74d58e3d2f3f471d`. That commit is `Document a production export check in 0.1.1. (#2)`, its `package.json` version is `0.1.1`, and it is the `gitHead` npm recorded for the published 0.1.1 tarball.

```bash
git tag -a v0.1.1 ccf67f56837508507a46baad74d58e3d2f3f471d -m "v0.1.1"
git push origin v0.1.1
```

Push that tag only at that commit. The release workflow file is not in that commit, so GitHub will not run it for `v0.1.1`, and npm will not try to publish 0.1.1 again. Tagging `v0.1.1` on a later commit (where `package.json` is `0.2.0`) would start the workflow and fail the version check.

Do not move `v0.1.0`. The tag already points at `f51532d` in this repository, but the 0.1.0 tarball's `gitHead` (`9d28839`) is not in this history. Retagging would be a force-update of a tag that is already on the remote, and it still could not point at a commit this repo does not contain.
