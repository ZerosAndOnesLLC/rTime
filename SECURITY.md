# Security Policy

## Supported Versions

rTime is pre-1.0. Security fixes are released against the latest published version
only; please upgrade to the newest release before reporting.

| Version | Supported |
|---------|-----------|
| latest (0.14.x) | ✅ |
| older | ❌ |

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability):

1. Go to the [**Security**](https://github.com/ZerosAndOnesLLC/rTime/security) tab of this repository.
2. Click **Report a vulnerability**.
3. Provide a description, affected version(s), and reproduction steps.

We aim to acknowledge reports within 72 hours and to provide a remediation timeline
after triage. Because rTime disciplines the system clock and can bind privileged ports,
please flag any issue touching time-stepping, privilege handling, or NTS/TLS
authentication as high severity.

Thank you for helping keep rTime and its users safe.
