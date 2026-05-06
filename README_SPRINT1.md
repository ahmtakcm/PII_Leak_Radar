# PII Leak Radar — Sprint 1 Final Notu

## Amaç

PII Leak Radar, açık kaynak tehdit istihbaratı, leak/PII göstergeleri, manuel kaynak kayıtları ve kullanıcı tarafından sağlanan export dosyaları üzerinden savunma, OSINT ve adli bilişim amaçlı risk izleme ve raporlama yapar.

Sprint 1 hedefi, mevcut projeyi bozmadan Source Registry, adapter tabanı, SQLite dedup, maskeleme ve HTML dashboard omurgasını kurmaktı.

## Sprint 1 ile Kurulan Kabiliyetler

- CISA KEV adapter
- NVD CVE adapter
- URLhaus malware URL adapter
- AlienVault OTX adapter
- GitHub Public Code Search adapter
  - Varsayılan kapalıdır.
  - Scope gerektirir.
  - Token gerektirir.
  - Dosya içeriği çekmez.
  - Credential veya secret denemez.
- Telegram / Discord user-provided export parser
- Manuel kaynak import modülü
- Source catalog review
- Unified HTML dashboard
- SQLite duplicate suppression
- Sensitive data masking / sanitizer
- Risk score ve recommended action policy
- Full pipeline runner
- Health check
- Clean package script

## Ana Komutlar

Full pipeline:

    cd "C:\Users\328271\Desktop\PII_Leak_Radar"
    py .\run_full_pipeline.py
    start .\reports\dashboard.html

PowerShell full scan:

    cd "C:\Users\328271\Desktop\PII_Leak_Radar"
    .\run_full_scan.ps1 -OpenReports

Health check:

    cd "C:\Users\328271\Desktop\PII_Leak_Radar"
    py .\run_health_check.py
    start .\reports\health_check.html

Temiz paket:

    cd "C:\Users\328271\Desktop\PII_Leak_Radar"
    .\make_clean_package.ps1

## Üretilen Ana Raporlar

- reports/dashboard.html
- reports/source_catalog.html
- reports/export_parse_report.html
- reports/manual_import_report.html
- reports/full_pipeline_report.html
- reports/health_check.html

## Güvenli Varsayılanlar

- dry_run: true
- alerts_enabled: false
- store_raw_sensitive: false
- mask_sensitive: true
- dedup_enabled: true
- dashboard_enabled: true

## Sprint 1 Sonucu

Sprint 1 sonunda proje çalışan, rapor üreten, dedup yapan, hassas veriyi maskeleyen, full pipeline ile tek komutta çalışan ve temiz paketlenebilen stabil bir tabana ulaştı.
