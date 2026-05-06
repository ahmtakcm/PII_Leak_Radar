# Scope Hardening

The active `config/scope.yml` should contain only local, authorized organization scope. Keep real organization values out of chat, issues, PRs, and release packages.

Recommended flow:

```powershell
Copy-Item .\config\scope.local.example.yml .\config\scope.yml
py .\pii_radar.py scope add-domain example.com
py .\pii_radar.py scope add-keyword example-product
py .\pii_radar.py scope add-name "Example Organization"
py .\pii_radar.py scope add-paste-source pastebin
py .\pii_radar.py scope validate
py .\pii_radar.py policy
py .\pii_radar.py connectors
```

Safety gates that must remain false:

- `unauthorized_access_allowed`
- `credential_use_allowed`
- `bypass_allowed`
- `exploit_allowed`
- `illegal_market_transaction_allowed`
- `closed_group_intrusion_allowed`
- `raw_sensitive_output_allowed`
- `alerts_enabled`
- `paste_scope.automatic_crawling_enabled`

Public code search and paste review should remain scoped/manual until explicit authorization is present.
