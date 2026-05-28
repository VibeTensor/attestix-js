# Contributing to `attestix`

This is the JS/TS verifier package for [Attestix](https://attestix.io).
The Python core (issuance, MCP server, REST API, blockchain anchoring) lives
at [VibeTensor/attestix](https://github.com/VibeTensor/attestix); broader
project conventions and the architectural bar are documented there in
[CONTRIBUTING.md](https://github.com/VibeTensor/attestix/blob/main/CONTRIBUTING.md).

## Quick start

```bash
git clone https://github.com/VibeTensor/attestix-js.git
cd attestix-js
npm ci
npm run lint   # tsc --noEmit
npm test       # vitest run (31 tests vs Python-generated vectors)
npm run build  # tsup -> dist/
```

Node >= 18 is required. CI runs on Node 20 and 22 (Ubuntu).

## Filing issues

- **Bugs**: include a minimal reproduction, the Node version, and the
  package version (`npm ls attestix`).
- **Cross-engine verification mismatches** (Python issues, JS rejects, or
  vice versa): include both the issuing Python version and the failing
  bundle / credential JSON. These are highest-priority because they break
  the package's core contract.
- **Security issues**: do not file public issues - see
  [SECURITY.md](./SECURITY.md).

## Pull requests

- Keep PRs focused on one fix or feature.
- Update or add tests in `tests/` for any verifier behaviour change.
- Run `npm run lint && npm test && npm run build` before pushing.
- New test vectors are regenerated from the Python core via
  `tests/vectors/generate_vectors.py` to preserve cross-engine parity.

## Releases

- npm publishes are gated by OIDC trusted publishing (no `NPM_TOKEN`).
  Cutting a GitHub Release triggers `.github/workflows/publish.yml`.
- Tag format: `v<semver>` (e.g. `v0.2.0`).
