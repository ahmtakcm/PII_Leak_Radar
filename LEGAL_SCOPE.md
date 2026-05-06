# PII Leak Radar — Yasal ve Operasyonel Kapsam

## Proje Amacı

PII Leak Radar savunma, OSINT, adli bilişim, risk analizi ve raporlama amaçlıdır.

Proje; PII, leak, credential, IOC, CVE, malware URL, breach notification, vendor advisory ve riskli kaynak göstergelerini tespit etmek, sınıflandırmak, maskelemek, dedup yapmak ve raporlamak için kullanılır.

## Desteklenen Kullanım Alanları

- Açık kaynak tehdit feedlerini izleme
- CISA KEV, NVD, URLhaus ve OTX verilerini analiz etme
- Kullanıcı tarafından sağlanan Telegram / Discord export dosyalarını offline parse etme
- Manuel vendor advisory / breach notification / paste-leak kayıtlarını import etme
- PII / IOC / CVE / leak göstergelerini tespit etme
- Hassas verileri maskeleme
- SQLite dedup ile tekrar kayıtları bastırma
- HTML dashboard raporlama
- Delil referansı, zaman damgası, hash ve risk skoru mantığı geliştirme
- Kurum varlıklarıyla izinli kapsamda eşleştirme
- Manuel review kuyruğu oluşturma

## Yapılmayacak İşlemler

Bu proje kapsamında aşağıdaki işlemler yapılmaz:

- Yetkisiz erişim sağlama
- Kapalı illegal gruba sızma
- Davet satın alma veya davet kullanma
- Credential deneme veya kullanma
- Hesap ele geçirme
- Exploit veya bypass uygulama
- Illegal markette işlem yapma
- GSM’den TC sorgu veya yasa dışı panel/bot kullanımı
- Yetkisiz veri çekme
- Ham hassas veriyi gereksiz paylaşma veya yayma

## Riskli Kaynaklarda Yaklaşım

Riskli kaynaklar proje mantığında tespit ve risk değerlendirmesi açısından modellenebilir.

Yaklaşım:

    Tespit et
    Sınıflandır
    Maskele
    Delil referansı oluştur
    Risk skoru ver
    Manuel/yetkili incelemeye yönlendir

Aktif yasa dışı katılım veya erişim yapılmaz.

## High-Risk Kaynak Tipleri

Yüksek riskli kabul edilen kaynak tipleri:

- Dark web / hidden service kaynakları
- Illegal market göstergeleri
- Kapalı grup davetleri
- Paste/leak dump kaynakları
- Credential paylaşım alanları
- Bot/panel/checker kaynakları
- Carding/CVV/fullz benzeri içerikler

Bu alanlarda sistem yalnızca kaynak tipini tanımlar, metadatasını kaydeder, risk seviyesini belirler, delil referansını tutar ve manuel yasal/operasyonel inceleme notu üretir.

## Veri Saklama İlkesi

Varsayılanlar:

- store_raw_sensitive: false
- mask_sensitive: true
- alerts_enabled: false
- dry_run: true

Hassas veri maskelemeden raporlanmamalı, gereksiz loglanmamalı ve temiz ZIP paketlerine alınmamalıdır.

## Paketleme İlkesi

Varsayılan temiz paket şunları dışarıda bırakır:

- data
- logs
- reports
- exports_inbox
- manual_sources_inbox
- .env
- token/secret dosyaları
- çalışma DB’si

## GitHub Public Code Search Notu

GitHub public code search yalnızca izinli kurum/domain/marka kapsamı ile kullanılmalıdır.

Bulunan token, secret veya credential:

- denenmez
- kullanılmaz
- yayımlanmaz
- bildirim / rotasyon / kaldırma / delil kaydı sürecine alınır

## Özet İlke

PII Leak Radar illegal alanları ve leak göstergelerini tanıyabilir, sınıflandırabilir ve raporlayabilir.

Ancak sistem illegal alana aktif katılım, yetkisiz erişim veya istismar aracı olarak kullanılmaz.
