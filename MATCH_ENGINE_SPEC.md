# Match Engine Spec

Bu dosya Sprint 2 match engine davranışını tarif eder.

## Girdi

Match engine aşağıdaki girdileri alır:

- text: Taranacak içerik
- source_id: Kaynak kimliği
- source_type: Kaynak tipi
- asset_registry: Yüklü asset listesi

## Çıktı

Her eşleşme aşağıdaki yapıya benzer şekilde döner:

```json
{
  "asset_id": "person_001",
  "asset_type": "email",
  "match_type": "exact",
  "risk_score": 75,
  "matched_value_masked": "a***@example.com",
  "context": "telegram leak dump bağlamında geçti",
  "source_id": "dry_run"
}
```

## Match türleri

### exact

Asset değeri içerikte birebir geçerse kullanılır.

### normalized

Büyük/küçük harf, Türkçe karakter, boşluk ve noktalama farkları normalize edilerek eşleşme aranır.

### regex

Telefon, e-posta, URL, domain ve benzeri yapılar pattern ile yakalanır.

### fuzzy

Küçük yazım farkları için düşük riskli yardımcı eşleşme türüdür.

İlk sürümde basit benzerlik oranı kullanılabilir.

## Risk skoru

Risk skoru şu faktörlerle artar:

- Asset tipi hassasiyeti
- Kaynak tipi
- Bağlam kelimeleri
- Exact match olup olmaması
- Birden fazla asset aynı içerikte geçmesi
- Illegal market/grup/davet ifadesiyle beraber geçmesi

## Masking

Ham hassas değerler çıktıda açık gösterilmez.

Örnekler:

- ahmet@example.com -> a****@example.com
- 05551234567 -> 0555***4567
- username123 -> use****123

## İlk sürüm sınırları

Sprint 2 ilk sürümde:

- Dış bağlantı yapmaz.
- Gerçek tarama başlatmaz.
- Alarm göndermez.
- Sadece dry-run test üretir.
- SQLite entegrasyonu sonraki adıma bırakılabilir.
