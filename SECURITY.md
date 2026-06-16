# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4   | :x:                |

## Reporting a Vulnerability

`attestix` is the JS/TS verifier package for the Attestix
attestation infrastructure. Because it is used to verify cryptographic
identity, credential, and delegation evidence, all security reports are
triaged on the same channel as the core Python project at
[VibeTensor/attestix](https://github.com/VibeTensor/attestix).

### Please Do

- **Report privately**: Use [GitHub Security Advisories](https://github.com/VibeTensor/attestix-js/security/advisories/new) on this repo
  to report vulnerabilities privately.
- **Email us**: Send details to `info@vibetensor.com` and `pkd@vibetensor.com`.
- **Provide details**: Include steps to reproduce, potential impact, and
  suggested fixes if any.
- **Give us time**: Allow reasonable time before public disclosure.

### Please Don't

- Don't open public issues for security vulnerabilities.
- Don't exploit the vulnerability beyond what's necessary to demonstrate it.
- Don't attempt to access other users' data, credentials, or signing keys.

## Response Timeline

- Triage acknowledgement within **5 business days**.
- High-severity issues are targeted for a fix within **30 days**.
- Lower-severity issues are scheduled into the next release cycle.

Optional: we may publish a GitHub Security Advisory and request a CVE for
qualifying issues.

## Scope

In-scope for this package:

- The offline verifier modules under `src/verify/` (Ed25519, JCS, did:key,
  W3C VC, UCAN delegation chain attenuation).
- The REST client under `src/client.ts` (limited to bugs that affect
  cryptographic or authentication correctness, not transport-layer issues
  outside the package).

Out-of-scope (route to the parent project):

- Issues in the Python core, MCP server, REST API, EAS/Base anchoring,
  or the marketing website -> see
  [VibeTensor/attestix SECURITY.md](https://github.com/VibeTensor/attestix/blob/main/SECURITY.md).

## Contact

- **Security email**: `info@vibetensor.com`, `pkd@vibetensor.com`
- **GitHub Security Advisories**: [Report here](https://github.com/VibeTensor/attestix-js/security/advisories/new)
- **Parent project policy**: [VibeTensor/attestix](https://github.com/VibeTensor/attestix/blob/main/SECURITY.md)
