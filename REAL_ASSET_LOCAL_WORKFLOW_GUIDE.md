# Real Asset Local Workflow Guide

Bu rehber gerçek takip varlýklarýnýn assets/assets.local.json dosyasýnda güvenli þekilde yönetilmesi içindir.

## Çok önemli

- Gerçek kiþi adý, telefon, e-posta, kullanýcý adý, kurum adý veya domain bilgisini sohbet ekranýna yapýþtýrma.
- Gerçek deðerleri yalnýzca kendi bilgisayarýndaki assets/assets.local.json dosyasýna yaz.
- assets/assets.local.json git, public repo, zip paylaþýmý veya ekran görüntüsü içine açýk þekilde girmemeli.
- assets/assets.local.template.json sadece þablondur; gerçek veri içermez.

## Baþlangýç akýþý

1. assets/assets.local.template.json dosyasýný aç.
2. Ýçeriði assets/assets.local.json dosyasýna kopyala.
3. PLACEHOLDER deðerleri kendi lokal gerçek deðerlerinle deðiþtir.
4. Kullanmadýðýn asset bloklarýnda enabled=false yap veya bloðu sil.
5. Kaydet.
6. Validator çalýþtýr: python .\run_asset_scope_validate.py
7. Health check çalýþtýr: python .\run_sprint2_health_check.py
8. Full pipeline çalýþtýr: .\run_full_scan.ps1

## Asset alanlarý

- asset_id: benzersiz kýsa kimlik. Örn: person_001, org_001
- asset_kind: person, organization, digital_identity, domain, custom_keyword
- display_name: ekranda görünen ad. Raporlarda maskelenebilir.
- sensitivity: low, medium, high, critical
- aliases: rumuzlar veya alternatif yazýmlar
- emails: izlenecek e-posta adresleri
- phones: izlenecek telefonlar
- usernames: kullanýcý adlarý veya handle deðerleri
- domains: alan adlarý
- subdomains: alt alan adlarý
- profile_urls: açýk profil URL deðerleri
- keywords: özel takip kelimeleri
- enabled: true veya false

## Önerilen sensitivity

- low: genel keyword veya düþük hassasiyetli domain
- medium: kurum, domain, genel dijital kimlik
- high: kiþi, telefon, kiþisel e-posta
- critical: kritik kurum hesabý, yüksek öncelikli kiþi veya özel operasyonel iz

## Çýktý güvenliði

- Validator ham deðer basmamalý.
- Match raporlarý matched_value_masked kullanmalý.
- Snippet alanlarý maskeli olmalý.
- Terminalde gerçek deðer görünürse test durdurulmalý ve masking kontrol edilmeli.

## Yasal ve operasyonel sýnýr

- Proje OSINT, savunma, adli biliþim ve risk izleme amaçlýdýr.
- Illegal grup, market, davet veya eriþim izleri sadece risk baðlamý olarak deðerlendirilir.
- Yetkisiz eriþim, credential kullanýmý, bypass, exploit veya kapalý kaynaklara sýzma yapýlmaz.
- Alarm kapalý kalýr; bu aþama raporlama ve doðrulama içindir.
