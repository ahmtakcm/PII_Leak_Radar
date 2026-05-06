# assets.local.json Kullaným Rehberi

Bu dosya gerçek takip varlýklarýnýn assets/assets.local.json içine nasýl yazýlacaðýný açýklar.

Önemli:
- Gerçek kiþi, telefon, e-posta veya kurum bilgilerini sohbet ekranýna yapýþtýrma.
- Gerçek deðerleri sadece kendi bilgisayarýndaki assets/assets.local.json dosyasýna yaz.
- assets/assets.local.json git veya public repo içine eklenmemelidir.
- Validator ve match engine çýktý verirken ham hassas deðerleri maskelemelidir.

Desteklenen asset alanlarý:
- asset_id
- asset_kind
- display_name
- sensitivity
- aliases
- emails
- phones
- usernames
- domains
- subdomains
- profile_urls
- urls
- keywords
- enabled

asset_kind örnekleri:
- person
- organization
- digital_identity
- domain
- custom_keyword

sensitivity örnekleri:
- low
- medium
- high
- critical

Örnek asset yapýsý:
{
  "asset_id": "person_001",
  "asset_kind": "person",
  "display_name": "Kisi Adi",
  "sensitivity": "high",
  "aliases": ["rumuz1", "rumuz2"],
  "emails": ["ornek@example.com"],
  "phones": ["+905551112233"],
  "usernames": ["kullaniciadi"],
  "keywords": ["ozel izleme kelimesi"],
  "enabled": true
}

Yasal ve operasyonel sýnýr:
- Proje savunma, OSINT, adli biliþim ve risk izleme amaçlýdýr.
- Illegal grup, market, davet veya eriþim izleri sadece risk baðlamý olarak deðerlendirilir.
- Yetkisiz eriþim, credential kullanýmý, bypass, exploit veya kapalý kaynaklara sýzma yapýlmaz.
