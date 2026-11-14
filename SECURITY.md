# Security Policy

## Supported versions

The current 1.x line receives security fixes.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository
(Security → Report a vulnerability). Do not open a public issue for a
vulnerability that could put users at risk.

Include:

- a description of the issue and its impact,
- the affected version or commit,
- reproduction steps or a minimal proof of concept,
- any suggested mitigation.

Do not include real credentials, private keys, or personal data in a report.

## Scope note

`proxhunt` intentionally communicates with untrusted public proxies. Findings
about proxy behavior itself (logging, injection, TLS interception) are expected
properties of the public-proxy ecosystem, not vulnerabilities in this project.
Report issues in `proxhunt` itself: argument handling, the local rotator,
parsing, storage, privilege boundaries, or dependency handling.
