# Sprint 2.1 — Pipeline Match Integration

## Amaç

Sprint 2.1 amacý, Sprint 2'de oluþturulan Asset Scope & Match Engine katmanýný mevcut pipeline raporlarýna güvenli/offline þekilde baðlamaktýr.

Bu aþamada canlý alarm açýlmaz, yeni dýþ kaynak eriþimi eklenmez, credential veya kapalý kaynak kullanýlmaz.

## Baðlanacak raporlar

- reports/export_parse_results.json
- reports/manual_import_results.json
- reports/source_registry_dry_run.json

## Üretilecek yeni çýktý

- reports/asset_match_report.json
- reports/asset_match_report.html

## Planlanan adýmlar

- Step 25: Sprint 2.1 plan dosyasý oluþtur.
- Step 26: export_parse_results.json üzerinde offline asset match denemesi yap.
- Step 27: manual_import_results.json üzerinde offline asset match denemesi yap.
- Step 28: source_registry_dry_run.json üzerinde offline asset match denemesi yap.
- Step 29: birleþik asset_match_report.json üret.
- Step 30: dashboard için Asset Matches özet kartý hazýrla.

## Güvenlik sýnýrý

- Proje OSINT, savunma, adli biliþim ve risk izleme amaçlýdýr.
- Illegal grup, market, davet veya eriþim izleri sadece risk baðlamý olarak deðerlendirilir.
- Yetkisiz eriþim, credential kullanýmý, bypass, exploit veya kapalý kaynak eriþimi yapýlmaz.

## Kabul kriterleri

- Mevcut full pipeline bozulmayacak.
- Alarm kapalý kalacak.
- Ham hassas deðerler rapora açýk yazýlmayacak.
- Eksik JSON rapor varsa iþlem fail yerine skip dönecek.
- Asset match sonuçlarý tek birleþik JSON raporda toplanacak.
