# Paste / Manual Review Connector Design

## Amaç

Kullanýcý tarafýndan lokal klasöre konulan paste/metin/JSON/HTML kaynaklarýný güvenli þekilde analiz etmek.

Bu connector otomatik paste sitesi kazýmasý yapmaz.
Credential toplamaz.
Illegal market veya kapalý grup eriþimi yapmaz.

## Klasör yapýsý

- paste_manual_review_inbox/
- reports/paste_manual_review_results.json
- reports/paste_manual_review_report.html

## Desteklenecek dosya tipleri

- .txt
- .log
- .json
- .html
- .csv

## Analiz alanlarý

- leak/dump/combo/database baðlamý
- market/panel/credential/stealer baðlamý
- telegram/discord/invite/davet baðlamý
- bot/scam/spam sinyali
- asset match sonucu
- maskeli snippet

## Güvenlik sýnýrý

- Ham hassas veri rapora açýk yazýlmaz.
- Output sanitized olur.
- Alarm kapalý kalýr.
- Yetkisiz eriþim, bypass, exploit veya credential kullanýmý yapýlmaz.
- Bu connector user-provided/manual review kaynaklar içindir.
