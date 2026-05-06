# PII Leak Radar - Step 47

## Safe Connector Adapter Skeleton

This patch adds the first connector adapter skeleton for Sprint 3.

Safety posture:

- dry-run only
- network disabled
- alerts disabled
- auth disabled
- credential use disabled
- sanitized metadata-only report
- no closed-group joining
- no illegal market crawling
- no bypass or exploit logic
- no raw sensitive output

## Files

```text
connectors/
  __init__.py
  base.py
  registry.py
  adapters/
    __init__.py
    cisa_kev.py
    nvd_recent.py
    urlhaus_recent.py
    vendor_advisories.py
    manual_import.py
    paste_manual_review.py

run_safe_connectors_dry_run.py
inspect_safe_connectors_report.py
```

## Run

```powershell
cd "$env:USERPROFILE\Desktop\PII_Leak_Radar"

python .\run_safe_connectors_dry_run.py
python .\inspect_safe_connectors_report.py
Start-Process .\reports\safe_connectors_dry_run_report.html
```

## Outputs

```text
reports\safe_connectors_dry_run_results.json
reports\safe_connectors_dry_run_report.html
```
