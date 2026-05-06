# PII Leak Radar - Current Status

Generated: 2026-05-06

## Runtime Status

- Health check: ok
- Secret scan: 0 active findings
- Source registry policy validation: ok
- Safe connectors dry-run: ok
- Full pipeline: ok in default offline-safe mode
- Unit tests: ok
- Verify gate: available via `py .\pii_radar.py verify`

The default full pipeline no longer attempts live public feed fetches. Live feed scanning is available only when explicitly requested with `--with-network-feeds` or `--with-network`.

## Current Structure

- `core/`: shared registry, matching, masking, scoring, dashboard, reporting, policy, dedup logic
- `connectors/`: policy-aware connector skeletons and dry-run adapter decisions
- `adapters/`: live feed adapters used only by explicit network-enabled registry scans
- `config/`: source activation and safety policy
- `assets/`: local/sample asset registry inputs
- `reports/`: generated HTML/JSON reports
- `tests/`: focused unit tests for report status and pipeline behavior
- `pii_radar.py`: unified command entrypoint
- `run_full_pipeline.py`: default offline-safe daily pipeline
- `run_safe_connectors_dry_run.py`: safety-first connector readiness report
- `run_source_registry_policy_validate.py`: policy/schema validation gate

## Completed Improvements

- Fixed source registry policy HTML report generation.
- Added policy validation and safe connector dry-run gates to the full pipeline.
- Added pipeline status classification for warning/error signals in child command output.
- Changed default full pipeline behavior to offline-safe mode.
- Moved live public feed scan behind explicit `--with-network-feeds` / `--with-network` flags.
- Added unified CLI commands in `pii_radar.py`.
- Added shared report helper in `core/reporting.py`.
- Added unit tests under `tests/`.
- Added retention cleanup options to `run_maintenance.py`.
- Added dashboard operation cards for policy gate, connector readiness, connector warnings, and network feed mode.
- Added dashboard retention cards for DB observations, source runs, last observation, and retention hint.
- Added `docs/archive/README.md` as the archive target for historical sprint notes.
- Added Pastebin-like manual review source candidates: Pastebin, GitHub Gist, Rentry, Ghostbin, and ControlC.
- Added `PASTE_SOURCE_ONBOARDING.md` with safe paste-source workflow and guardrails.
- Added paste URL reference normalization and source-site summaries to paste manual review.
- Added connector regression tests for paste manual review sources.
- Added `verify` command for compile, unit tests, health, policy, connectors, and pipeline.
- Added scope management commands for show, validate, domains, keywords, names, and paste sources.
- Added sanitized evidence package generation.
- Added `report_schema` envelope to safe connector dry-run output as the first shared report schema migration step.
- Added `report_schema` envelopes to export parser, manual import, and asset scope validation outputs.
- Added helper tests for scope duplicate handling and evidence package case-name sanitization.
- Added `report_schema` envelopes to full pipeline and asset match pipeline/combined outputs.
- Updated asset match scanning to prefer `hits`/`events` payloads over report metadata when reading schema-wrapped JSON.
- Added tests for schema-wrapped asset match payload extraction.
- Added tests for masking, sample asset registry loading, retention cleanup, and evidence package manifest/zip generation.
- Refactored evidence package creation into a testable `create_package` function.
- Changed `verify` to targeted source compilation so generated reports, backups, and stale temp folders do not affect the quality gate.
- Refactored scope validation and updates into testable helpers.
- Added scope mutation and unsafe-scope validation tests.
- Moved live public-feed adapter execution behind the policy-aware `SafeConnector` interface.
- Updated `run_registry_dry_scan.py` to build connectors through `ConnectorRegistry` instead of using direct legacy adapter mappings.
- Added live-fetch policy gates for network, auth, credential use, and manual-review-only connectors.
- Added regression tests for legacy registry IDs, wrapped public-feed adapters, and auth-blocked OTX live fetch.
- Added GitHub Actions CI, PR template, issue templates, and `SECURITY.md`.
- Added GitHub release packaging workflow for clean sanitized source artifacts.
- Moved historical sprint/step notes into `docs/archive/`.
- Added CLI release note generation from Git history.
- Added offline connector parser fixture validation for live feed adapters.
- Expanded `.gitignore` for generated reports, local data, cache, logs, backups, and local secrets.

## Recommended Operating Flow

1. Run `py .\pii_radar.py health` before packaging or sharing.
2. Run `py .\pii_radar.py policy` after policy edits.
3. Run `py .\pii_radar.py connectors` before enabling any source.
4. Run `py .\pii_radar.py pipeline` for daily offline-safe reporting.
5. Run `py .\pii_radar.py pipeline --with-network-feeds` only when live public feed access is intentionally needed.
6. Run `py .\pii_radar.py verify` before larger refactors.
7. Run retention cleanup with `py .\pii_radar.py maintenance --keep-observations-days 90 --keep-source-runs-days 30 --vacuum`.

## Next Improvements

- Add optional branch protection in GitHub requiring the CI workflow before merge.
- Add GitHub release publishing after the package artifact workflow is validated on tags.
- Add parser fixture coverage for future enabled connectors as they graduate from placeholders.
