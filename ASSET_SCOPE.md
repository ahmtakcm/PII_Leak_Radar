# Asset Scope

Bu dosya PII Leak Radar tarafından izlenecek varlık tiplerini açıklar.

## Desteklenecek asset tipleri

### person

Kişi veya kimlik bağlantılı izleme kapsamı.

Örnek alanlar:
- display_name
- aliases
- emails
- phones
- usernames
- keywords

### organization

Kurum, şirket, ekip veya marka izleme kapsamı.

Örnek alanlar:
- name
- domains
- emails
- keywords
- aliases

### digital_identity

Dijital hesap, kullanıcı adı, handle veya profil bağlantılı izleme kapsamı.

Örnek alanlar:
- usernames
- profile_urls
- emails
- keywords

### domain

Alan adı ve alt alan adı izleme kapsamı.

Örnek alanlar:
- domain
- subdomains
- related_keywords

### custom_keyword

Özel risk anahtar kelimeleri.

Örnek alanlar:
- keyword
- weight
- category

## Hassas veri ilkesi

Gerçek asset değerleri mümkün olduğunca assets.local.json içinde tutulmalıdır.

assets.local.json git'e eklenmemelidir.

Raporlarda:
- telefonlar maskelenir
- e-postalar maskelenir
- kullanıcı adları kısmen maskelenir
- uzun token, key, hash veya credential benzeri değerler açık gösterilmez

## Risk sinyalleri

Aşağıdaki bağlamlar eşleşme riskini artırır:

- leak
- dump
- combo
- database
- telegram
- discord
- market
- satış
- satılık
- paylaşım
- data
- breach
- sızıntı
- panel
- log
- stealer
