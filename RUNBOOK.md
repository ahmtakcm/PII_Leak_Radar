# PII Leak Radar — Operasyon Runbook

## 1. Günlük Full Scan

    cd "C:\Users\328271\Desktop\PII_Leak_Radar"
    py .\run_full_pipeline.py
    start .\reports\dashboard.html

Tek CLI alternatifi:

    py .\pii_radar.py pipeline

Kalite kapısı:

    py .\pii_radar.py verify

Canlı public feed taraması günlük akışta kapalıdır. Gerekirse açıkça:

    py .\pii_radar.py pipeline --with-network-feeds

Alternatif:

    cd "C:\Users\328271\Desktop\PII_Leak_Radar"
    .\run_full_scan.ps1 -OpenReports

## 2. Sadece Açık Threat Feed Taraması

    cd "C:\Users\328271\Desktop\PII_Leak_Radar"
    py .\run_registry_dry_scan.py --with-network
    start .\reports\dashboard.html

Offline metadata-only kontrol:

    py .\pii_radar.py registry

Aktif kaynaklar:

- CISA KEV
- NVD Recent CVE
- URLhaus Recent Malware URLs
- OTX Subscribed Pulses

OTX API key yoksa sistem hata patlatmaz; config notice üretir.

## 3. Telegram / Discord Export Parse

Export dosyaları şu klasöre konur:

    C:\Users\328271\Desktop\PII_Leak_Radar\exports_inbox

Desteklenen formatlar:

- json
- html
- htm
- txt
- log
- csv

Çalıştırma:

    cd "C:\Users\328271\Desktop\PII_Leak_Radar"
    py .\run_export_parse.py
    start .\reports\export_parse_report.html

Bu parser yalnızca kullanıcı tarafından sağlanan export dosyalarını offline analiz eder.

## 4. Manuel Kaynak Import

Manuel kaynak dosyaları şu klasöre konur:

    C:\Users\328271\Desktop\PII_Leak_Radar\manual_sources_inbox

Şablon:

    manual_sources_inbox\_templates\manual_source_template.csv

Çalıştırma:

    cd "C:\Users\328271\Desktop\PII_Leak_Radar"
    py .\run_manual_import.py
    start .\reports\manual_import_report.html

Desteklenen kategoriler:

- vendor_advisory
- breach_notification
- paste_leak_review
- manual_review
- high_risk_intel

## 5. Source Catalog Review

    cd "C:\Users\328271\Desktop\PII_Leak_Radar"
    py .\run_source_catalog_review.py
    start .\reports\source_catalog.html

Kaynak durumları:

- active
- placeholder
- scope_required
- legal_review_required
- needs_adapter
- catalog_only

## 6. GitHub Public Code Search

Varsayılan kapalıdır.

Önce kapsam girilir:

    notepad .\config\scope.yml

Token sadece geçici PowerShell oturumuna girilir:

    $env:GITHUB_TOKEN = "TOKEN_BURAYA"

Sonra registry.yml içinde github_public_code_search için enabled: true yapılır.

Önemli:

Bulunan token, secret veya credential denenmez, kullanılmaz, yayılmaz. Sadece doğrulama, repo sahibine bildirim, rotasyon ve delil kaydı akışı işletilir.

## 7. Health Check

    cd "C:\Users\328271\Desktop\PII_Leak_Radar"
    py .\run_health_check.py
    start .\reports\health_check.html

Beklenen:

    Durum: ok
    Secret finding: 0

## 7.1 Paste Source Manual Review

Pastebin benzeri açık kaynaklar varsayılan olarak manuel review kaynağıdır; otomatik scrape edilmez.

Eklenen kaynak adayları:

- pastebin_manual_review
- github_gist_manual_review
- rentry_manual_review
- ghostbin_manual_review
- controlc_manual_review

Çalıştırma:

    cd "C:\Users\328271\Desktop\PII_Leak_Radar"
    py .\run_paste_manual_review.py
    start .\reports\paste_manual_review_report.html

Detaylı onboarding:

    PASTE_SOURCE_ONBOARDING.md

## 8. Temiz Paket

    cd "C:\Users\328271\Desktop\PII_Leak_Radar"
    .\make_clean_package.ps1

Varsayılan paket dışı kalanlar:

- data
- logs
- reports
- exports_inbox
- manual_sources_inbox
- .env
- token/secret dosyaları

Rapor dahil paket:

    .\make_clean_package.ps1 -IncludeReports

Data ve rapor dahil paket:

    .\make_clean_package.ps1 -IncludeData -IncludeReports

## 9. Sorun Giderme

PyYAML eksikse:

    py -m pip install -r requirements.txt

Dashboard yenile:

    py .\run_dashboard_refresh.py
    start .\reports\dashboard.html

GitHub token oturumdan temizle:

    Remove-Item Env:\GITHUB_TOKEN -ErrorAction SilentlyContinue

Test/noise kayıtlarını temizle:

    py .\run_maintenance.py --purge-github-test --purge-test-export --vacuum

Retention temizliği:

    py .\pii_radar.py maintenance --keep-observations-days 90 --keep-source-runs-days 30 --vacuum

Unit test:

    py -m unittest discover -s tests

## 10. Scope Yönetimi

Scope özeti:

    py .\pii_radar.py scope show

Scope güvenlik doğrulaması:

    py .\pii_radar.py scope validate

Lokal scope ekleme:

    py .\pii_radar.py scope add-domain example.com
    py .\pii_radar.py scope add-keyword AcmeCorp
    py .\pii_radar.py scope add-paste-source pastebin

## 11. Evidence Package

Maskelenmiş rapor ve config snapshot paketi:

    py .\pii_radar.py evidence package --case CASE-2026-001

Paket veri tabanı, raw inbox, log ve local asset dosyalarını içermez.
