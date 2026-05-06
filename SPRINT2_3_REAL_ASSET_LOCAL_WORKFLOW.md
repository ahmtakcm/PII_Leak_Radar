# Sprint 2.3 — Real Asset Local Workflow

## Amaç

Gerçek izlenecek assetleri güvenli þekilde assets/assets.local.json içinde yönetmek.

Bu sprintte gerçek kiþi, telefon, e-posta, kurum, domain veya kullanýcý adý gibi deðerler sohbete yazýlmaz.
Gerçek deðerler yalnýzca lokal assets/assets.local.json dosyasýnda tutulur.

## Planlanan adýmlar

- Step 35: Sprint 2.3 plan dosyasý oluþtur.
- Step 36: assets.local.template.json üret.
- Step 37: gerçek asset ekleme rehberi oluþtur.
- Step 38: local asset validator güçlendir.
- Step 39: local asset dry-run match testi oluþtur.
- Step 40: dashboard içinde registry mode göstergesi ekle.
- Step 41: Sprint 2.3 kapanýþ raporu oluþtur.

## Güvenlik sýnýrý

- Proje OSINT, savunma, adli biliþim ve risk izleme amaçlýdýr.
- Illegal grup, market, davet veya eriþim izleri yalnýzca risk baðlamý olarak deðerlendirilir.
- Yetkisiz eriþim, credential kullanýmý, bypass, exploit veya kapalý kaynak eriþimi yapýlmaz.
- Ham hassas deðerler rapora açýk yazýlmaz.
- Alarm kapalý kalýr.

## Kabul kriterleri

- assets.local.template.json oluþur.
- assets.local.json validator hassas deðerleri terminale açýk basmaz.
- assets.local.json boþsa sistem sample moda döner.
- assets.local.json doluysa sistem local moda geçer.
- Dashboard registry mode bilgisini gösterir.
- Full pipeline bozulmaz.
