# Security Policy

PII Leak Radar is a defensive OSINT and incident review tool. It must not be used for unauthorized access, credential use, bypass, exploit activity, closed-group intrusion, illegal market activity, or raw sensitive data redistribution.

## Supported Security Defaults

- Default pipeline is offline-safe.
- Live public feed scans require explicit flags.
- Alerts are disabled by default.
- Raw sensitive output is disabled.
- Safe connector dry-runs do not read credentials or perform network calls.
- Paste-like sources are manual-review only.

## Reporting a Security Issue

Do not include raw credentials, tokens, personal data, or exploit details in public issues.

Use a private disclosure channel for sensitive reports. If no private channel is configured, open a public issue with only high-level metadata and request a private contact path.

## Handling Findings

When a possible leak is found:

1. Keep raw sensitive data out of reports.
2. Preserve masked evidence and hashes.
3. Validate scope before further review.
4. Do not try, replay, validate, or use exposed credentials.
5. Follow notification, takedown, rotation, and incident-response workflow.
