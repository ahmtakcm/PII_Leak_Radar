# Sprint 2 — Asset Scope & Match Engine

## Amaç

Sprint 2'nin amacı PII Leak Radar sistemine izlenecek varlık kapsamını ve güvenli eşleşme motorunu eklemektir.

Bu sprintte sistem:
- Hangi kişi, kurum, domain, e-posta, telefon, kullanıcı adı veya özel anahtar kelimelerin izleneceğini bilir.
- Gelen içeriklerde bu varlıkları exact, normalized, regex ve basit fuzzy mantıkla arar.
- Eşleşmeleri risk skoru, kaynak, bağlam ve maskeli çıktı ile üretir.
- Ham hassas veriyi loglarda ve raporlarda açık göstermemeye çalışır.
- İlk aşamada alarm üretmez; dry-run/test çıktısı verir.

## Güvenli kullanım sınırı

Bu proje OSINT, savunma, adli bilişim ve risk izleme amaçlıdır.

Illegal grup, market, davet veya erişim izleri yalnızca risk sinyali olarak değerlendirilir.

Şunlar yapılmaz:
- Yetkisiz erişim
- Kapalı gruba sızma
- Credential kullanımı
- Exploit veya bypass
- Illegal market işlemi
- GSM, panel veya bot üzerinden kişisel veri sorgulama

Bu çerçeve, proje notundaki kısa yasal uyarı yapıp teknik akışı gereksiz kısıtlamama yaklaşımıyla uyumludur.

## Eklenecek bileşenler

- assets/assets.sample.json
- assets/assets.local.json
- core/masking.py
- core/asset_registry.py
- core/match_engine.py
- run_asset_match_test.py
- ASSET_SCOPE.md
- MATCH_ENGINE_SPEC.md

## Sprint 2 kabul kriterleri

1. Asset dosyası JSON olarak okunabilir.
2. Asset değerleri normalize edilebilir.
3. E-posta, telefon, domain, username ve keyword eşleşmeleri bulunabilir.
4. Eşleşmeler maskeli şekilde raporlanır.
5. Risk skoru üretilebilir.
6. Dry-run test dış bağlantı gerektirmez.
7. Sprint 1 dosyaları bozulmaz.
