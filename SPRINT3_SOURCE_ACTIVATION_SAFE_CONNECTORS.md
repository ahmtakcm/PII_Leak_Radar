# Sprint 3 — Source Activation & Safe Connectors

## Amaç

Pasif kaynaklarý kontrollü þekilde aktif hale getirmek ve PII Leak Radar'ýn kaynak kapsama alanýný geniþletmek.

Projenin amacý hukuk dýþý, riskli, leak/dump/market/bot/panel/davet/credential baðlamlarýný tespit etmek ve raporlamaktýr.

Bu sprintte yetkisiz eriþim, kapalý gruba sýzma, credential kullanýmý, bypass, exploit veya illegal market iþlemi yapýlmaz.

## Aktifleþtirilecek güvenli kaynak sýnýflarý

- user_provided_exports: Kullanýcý tarafýndan saðlanan Telegram/Discord export dosyalarý.
- manual_import_sources: Kullanýcý tarafýndan manuel saðlanan OSINT/metin/JSON/HTML kaynaklarý.
- public_feeds: Açýk threat intelligence feedleri.
- public_code_search: Scope tanýmlý public code search.
- vendor_advisories: Vendor güvenlik duyurularý.
- owned_telegram_ingest: Kullanýcýnýn yönettiði/izinli Telegram kanal veya grup ingest akýþý.
- owned_discord_ingest: Kullanýcýnýn yönettiði/izinli Discord sunucu ingest akýþý.

## High-risk kaynak yaklaþýmý

- Illegal market, kapalý grup, darkweb, panel, dump satýþ alanlarý doðrudan otomatik taranmaz.
- Bu kaynaklar manual_review_required veya legal_review_required statüsünde tutulur.
- Kullanýcý tarafýndan saðlanan açýk/izinli veri üzerinde risk baðlamý sýnýflandýrmasý yapýlabilir.
- Sistem bu alanlarý tespit eder, sýnýflandýrýr, raporlar; eriþim veya iþlem yapmaz.

## Planlanan adýmlar

- Step 42: Sprint 3 plan dosyasý oluþtur.
- Step 43: config/scope.yml oluþtur veya güçlendir.
- Step 44: source registry safe activation policy ekle.
- Step 45: paste/manual review connector tasarla.
- Step 46: Telegram/Discord export parser geniþlet.
- Step 47: bot/scam/market-context classifier ekle.
- Step 48: owned Telegram ingest tasarým notu.
- Step 49: owned Discord ingest tasarým notu.
- Step 50: dashboard source activation kartý.

## Güvenlik sýnýrý

- Alarm kapalý kalýr.
- Dry-run ve sanitized çýktý korunur.
- Ham hassas veri maskelenir.
- Yetkisiz eriþim, credential kullanýmý, exploit, bypass veya illegal market iþlemi yoktur.
- Riskli baðlamlar tespit edilir ve raporlanýr.
