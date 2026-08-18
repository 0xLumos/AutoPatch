# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in AutoPatch, please **do not** open
a public GitHub issue. Instead, report it privately via:

- **Email:** nalhouse@depaul.edu (subject line: `[AutoPatch-SEC]`)
- **GitHub Security Advisory:** use the "Report a vulnerability" button on
  https://github.com/0xLumos/AutoPatch/security/advisories

Please include:
- A description of the vulnerability and its impact
- Steps to reproduce (a minimal Dockerfile or scan input is ideal)
- Affected version(s) and commit hash
- Your suggested fix, if any

You will receive an acknowledgement within 5 business days. We will work with
you to assess the severity, develop a fix, and coordinate disclosure.

## Threat Model

AutoPatch operates between the build and push stages of a CI/CD pipeline.
Its threat model is documented in Section III of the accompanying paper.
Items explicitly **in scope** for reports:

- Sandbox escape from the scanned image into the AutoPatch runner.
- Command injection or path traversal in any subprocess call.
- Forged Cosign signatures or attestations that AutoPatch incorrectly accepts.
- Acceptance-gate bypasses (false positives that allow a more-vulnerable
  image to be marked accepted).
- Supply chain attacks against AutoPatch's own dependencies.
- Privacy or credential leakage in the report outputs.

Out of scope (handled by orthogonal defenses):

- Zero-day CVEs that are not yet in the public vulnerability databases
  consumed by Trivy / Grype.
- Compromise of the CI runner itself.
- Kernel-level container escapes.
- Vulnerabilities in upstream base images that AutoPatch reports
  faithfully (those are the input data, not AutoPatch bugs).

## Security-Critical Configuration

For production use, please review:

1. **Cosign signing.** `COSIGN_PASSWORD` must be set for `key` mode. The
   tool refuses unsealed keys unless `AUTOPATCH_ALLOW_UNSEALED_KEY=1` is
   explicitly set.
2. **Keyless identity.** For `keyless` mode, set
   `COSIGN_CERTIFICATE_IDENTITY_REGEXP` to a specific OIDC subject regex
   (do **not** use `.*`). The tool refuses `.*` unless
   `AUTOPATCH_ALLOW_ANY_KEYLESS_IDENTITY=1`.
3. **Scanner integrity.** Pass `--scanner-checksums` with a pinned SHA256
   manifest and enable `--strict-integrity` so a tampered Trivy/Grype
   binary fails the run.
4. **Tag verification.** `verify_tag` fails closed on registry errors. If
   you need to run offline (e.g. cache-warming), pass `fail_open=True`
   explicitly.
5. **EOL upgrades.** Off by default to preserve user-pinned versions. Pass
   `--eol-upgrade` when running aggressive remediation experiments.

## Audit Reports

The audit findings that motivated this hardening are tracked in
`docs/audit-findings.md` (when available).
