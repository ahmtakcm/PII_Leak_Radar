# PII Leak Radar — V5 Sonraki Adımlar

## Mevcut Sprint 1 Durumu

Sprint 1 tamamlandı.

Kurulan taban:

- Source registry
- Açık threat feed adapterleri
- SQLite dedup
- Masking / sanitizer
- Risk score
- Recommended action policy
- Export parser
- Manual import
- Source catalog
- Unified dashboard
- Full pipeline
- Health check
- Clean package

## 1. Asset Scope Yönetimi

Amaç:

Kurum domainleri, marka adları, e-posta domainleri, ürün/vendor listesi ve kritik varlıkları merkezi scope dosyasında yönetmek.

Önerilen dosyalar:

- config/scope.yml
- config/assets.yml

Örnek alanlar:

- domains
- brands
- emails
- vendors
- products
- critical_ips
- business_units

## 2. GitHub Public Code Search Kontrollü Aktivasyon

Şartlar:

- Gerçek izinli scope girilecek.
- Token sadece env var olarak kullanılacak.
- Dosya içeriği varsayılan çekilmeyecek.
- Sadece metadata ve risk sinyali üretilecek.
- Secret/credential denenmeyecek.

Geliştirme:

- Query builder iyileştirilecek.
- Rate limit handling eklenecek.
- Pagination kontrollü hale getirilecek.
- Asset match skorlaması eklenecek.

## 3. Vendor Advisory Adapterleri

Katalogda pasif duran vendor_advisories için açık advisory kaynakları eklenebilir.

Örnek kaynak tipleri:

- Microsoft Security Response Center
- Cisco Security Advisories
- Fortinet PSIRT
- Palo Alto Security Advisories
- VMware/Broadcom advisories
- CISA Alerts

Her vendor için önce resmi ve açık endpoint tercih edilmeli.

## 4. Manual Review Queue

Amaç:

Yüksek riskli veya yasal review gerektiren bulgular için ayrı bir kuyruk oluşturmak.

Önerilen yapı:

- review_queue/
- reports/review_queue.html
- core/review_queue.py

Durumlar:

- new
- in_review
- confirmed
- false_positive
- escalated
- closed

## 5. Evidence Vault Lite

Amaç:

Delil referanslarını kontrollü ve hash’li şekilde tutmak.

Önerilen yapı:

- evidence/
- core/evidence_vault.py

Varsayılan:

Ham hassas veri saklanmaz. Sadece hash, referans, maskeleme ve raporlanabilir özet tutulur.

## 6. Dashboard V2

Eklenebilecekler:

- Risk filtreleri
- Kaynak filtreleri
- Arama kutusu
- Critical/high özet kartları
- Son 24 saat / son 7 gün grafikleri
- Kaynak sağlık trendi
- Export/manual/feed ayrımı
- Review queue bölümü

## 7. Alert Engine Hazırlığı

Şu an alarm kapalıdır.

Gelecekte alarm açılmadan önce:

- dedup kesin çalışmalı
- false positive azaltılmalı
- risk threshold belirlenmeli
- manuel onay opsiyonu eklenmeli
- test ortamında denenmeli

Önerilen varsayılan:

- alerts_enabled: false
- alert_threshold: critical
- manual_approval_required: true

## 8. Telegram Bildirimleri

İleride Telegram bildirimleri eklenebilir.

Güvenli varsayımlar:

- Sadece masked summary gönderilir.
- Ham PII gönderilmez.
- Token env var üzerinden yönetilir.
- Health check token sızıntısını kontrol eder.
- Bildirimlerde source, risk, title ve action olur.

## 9. Export Parser V2

İyileştirmeler:

- Telegram Desktop JSON ayrıntılı field parse
- DiscordChatExporter format iyileştirme
- HTML mesaj bloklarını daha doğru ayırma
- Attachment metadata tespiti
- Mesaj bazlı timestamp/author doğruluğu
- Büyük dosyada streaming parse

## 10. PII Detector İyileştirme

Eklenebilecekler:

- IBAN
- kredi kartı Luhn validasyonu
- pasaport benzeri pattern
- adres pattern
- vergi no pattern
- özel keyword sözlükleri
- Türkçe leak/dump kelime seti genişletme

## 11. Risk Score V2

İyileştirme başlıkları:

- source reliability
- asset match bonus
- recency bonus
- repeated seen bonus
- ransomware indicator bonus
- credential keyword bonus
- PII count bonus
- legal review blocker
- false positive suppression

## 12. Stabil Paketleme Disiplini

Her önemli sprint sonunda:

    py .\run_full_pipeline.py
    py .\run_health_check.py
    .\make_clean_package.ps1

Paket adı formatı:

    PII_Leak_Radar_CLEAN_SPRINTX_YYYYMMDD_HHMMSS.zip

## Önerilen Sprint 2

En mantıklı sıra:

1. assets.yml ekle
2. Asset match engine kur
3. Vendor advisory adapter tabanı ekle
4. Review queue kur
5. Dashboard V2 filtre/özet kartları ekle
6. Alert engine hazırlığını yap ama alarmı kapalı tut

## Kısa Sonuç

Sprint 1 çalışan altyapıyı kurdu.

Sprint 2 artık projeyi daha akıllı hale getirecek:

    Kaynak izleme
    Asset match
    Risk önceliklendirme
    Review queue
    Daha güçlü dashboard
