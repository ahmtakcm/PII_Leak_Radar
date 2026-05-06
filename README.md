# PII Leak Radar

PII Leak Radar is a defensive OSINT, asset match, and leak-indicator reporting toolkit. It is designed to run safely by default: alerts are disabled, raw sensitive output is disabled, and live public feed access is opt-in.

## Quick Start

```powershell
cd "C:\Users\328271\Desktop\PII_Leak_Radar"
py .\pii_radar.py health
py .\pii_radar.py pipeline
```

Open the dashboard:

```powershell
start .\reports\dashboard.html
```

## Main Commands

```powershell
py .\pii_radar.py health
py .\pii_radar.py policy
py .\pii_radar.py connectors
py .\pii_radar.py assets
py .\pii_radar.py pipeline
py .\pii_radar.py registry
py .\pii_radar.py verify
```

Live public feed scans are explicit:

```powershell
py .\pii_radar.py pipeline --with-network-feeds
py .\pii_radar.py registry --with-network
```

Scope management:

```powershell
py .\pii_radar.py scope show
py .\pii_radar.py scope validate
py .\pii_radar.py scope add-domain example.com
py .\pii_radar.py scope add-keyword AcmeCorp
py .\pii_radar.py scope add-paste-source pastebin
```

Evidence package:

```powershell
py .\pii_radar.py evidence package --case CASE-2026-001
```

## Verification

```powershell
py -m unittest discover -s tests
py .\pii_radar.py verify
py .\pii_radar.py health
```

GitHub Actions runs the same verify gate on Windows:

```powershell
py -m pip install -r requirements.txt
py .\pii_radar.py verify
```

The release package workflow can be run manually from GitHub Actions or by pushing a `v*` tag. It builds a clean ZIP artifact after the verify gate and excludes local data, reports, logs, inboxes, backups, and cache folders.

## Reports

- `reports/dashboard.html`
- `reports/full_pipeline_report.html`
- `reports/health_check.html`
- `reports/source_registry_policy_validate_report.html`
- `reports/safe_connectors_dry_run_report.html`

## Operating Notes

- Default mode is offline-safe.
- Public feed network access is opt-in.
- Credentials are not read or used by safe connector dry-runs.
- Raw sensitive output should remain disabled.
- Local assets, reports, databases, logs, and backups are intentionally ignored by source control.
