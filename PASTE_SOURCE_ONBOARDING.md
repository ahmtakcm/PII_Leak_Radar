# Paste Source Onboarding

Paste-like public sites can be useful for defensive leak review, but they must stay manual-review by default.

## Added Source Candidates

- `pastebin_manual_review` - Pastebin
- `github_gist_manual_review` - GitHub Gist
- `rentry_manual_review` - Rentry
- `ghostbin_manual_review` - Ghostbin-style paste source
- `controlc_manual_review` - ControlC

## Guardrails

- Keep these sources disabled in `registry.yml` unless a scoped, documented review is needed.
- Do not bulk scrape paste sites.
- Do not join closed groups, bypass access controls, buy access, or use credentials.
- Do not try, validate, or replay leaked credentials.
- Do not write raw sensitive content into reports.
- Prefer user-provided URLs/files, official takedown notices, or scoped public search metadata.

## Safe Workflow

1. Define organization scope in `config/scope.yml`.
2. Save user-provided paste exports, URLs, or notes under `paste_manual_review_inbox`.
3. Run `py .\run_paste_manual_review.py`.
4. Review `reports/paste_manual_review_report.html`.
5. If an asset match appears, preserve masked evidence and follow notification/rotation workflow.

## Activation Model

These sources are registered as `paste_manual_review` in `config/source_registry_policy.json`. They are intentionally `scope_required` and `manual_review_only`.
