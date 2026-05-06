# Sprint 2.2 — Dashboard Asset Match Card

## Amaç

reports/asset_match_report.json özetini reports/dashboard.html içine güvenli bir kart olarak eklemek.

## Güvenli yaklaþým

- Mevcut dashboard generator doðrudan bozulmaz.
- Dashboard üretildikten sonra post-process injector çalýþýr.
- Kart idempotent marker ile eklenir; tekrar tekrar çoðalmaz.
- Alarm açýlmaz.
- Ham hassas deðer gösterilmez.

## Kartta gösterilecek alanlar

- status
- record_count
- match_count
- asset_count
- max_risk_score
- kaynak bazlý özet
