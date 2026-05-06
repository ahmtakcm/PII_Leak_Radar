# STEP 47B - OTX Placeholder Adapter

Bu patch `otx_subscribed` için güvenli adapter iskeleti ekler.

## Eklenenler

- `connectors/adapters/otx_subscribed.py`
- `connectors/registry.py` içinde `otx_subscribed` source mapping
- `connectors/registry.py` içinde `open_api_requires_key` class fallback mapping

## Güvenlik durumu

- Network çağrısı yapılmaz.
- API key/credential okunmaz veya kullanılmaz.
- Alert gönderilmez.
- Ham hassas veri basılmaz.
- OTX adapter sadece dry-run readiness metadata üretir.

## Beklenen çıktı

`adapter_missing_for_allowed_source: otx_subscribed` warning'i kaybolmalıdır.

Muhtemel özet:

- `source_count=11`
- `allowed_count=8`
- `manual_review_count=3`
- `adapter_available_count=9`
- `adapter_missing_count=2`
- `can_run_count=7`
- `warning_count=0`

`otx_subscribed` için `can_run=False` normaldir; çünkü auth/credential kullanımı kapalıdır.
