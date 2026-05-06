from __future__ import annotations

from typing import Any, Dict, Optional, Type

from connectors.base import SafeConnector
from connectors.adapters.cisa_kev import CisaKevConnector
from connectors.adapters.nvd_recent import NvdRecentConnector
from connectors.adapters.urlhaus_recent import UrlHausRecentConnector
from connectors.adapters.vendor_advisories import VendorAdvisoriesConnector
from connectors.adapters.otx_subscribed import OtxSubscribedConnector
from connectors.adapters.manual_import import ManualImportConnector
from connectors.adapters.paste_manual_review import PasteManualReviewConnector


class ConnectorRegistry:
    """Maps source_registry_policy source IDs to safe dry-run adapters."""

    SOURCE_ADAPTERS: Dict[str, Type[SafeConnector]] = {
        "cisa_kev": CisaKevConnector,
        "nvd_recent": NvdRecentConnector,
        "urlhaus_recent": UrlHausRecentConnector,
        "vendor_advisories": VendorAdvisoriesConnector,
        "otx_subscribed": OtxSubscribedConnector,
        "manual_osint_sources": ManualImportConnector,
        "breach_notification_manual": ManualImportConnector,
        "telegram_discord_exports": ManualImportConnector,
        "paste_leak_manual_review": PasteManualReviewConnector,
        "pastebin_manual_review": PasteManualReviewConnector,
        "github_gist_manual_review": PasteManualReviewConnector,
        "rentry_manual_review": PasteManualReviewConnector,
        "ghostbin_manual_review": PasteManualReviewConnector,
        "controlc_manual_review": PasteManualReviewConnector,
    }

    CLASS_FALLBACK_ADAPTERS: Dict[str, Type[SafeConnector]] = {
        "public_open_feed": CisaKevConnector,
        "open_api_requires_key": OtxSubscribedConnector,
        "vendor_advisory": VendorAdvisoriesConnector,
        "manual_import": ManualImportConnector,
        "user_provided_export": ManualImportConnector,
        "paste_manual_review": PasteManualReviewConnector,
    }

    @classmethod
    def get_adapter_class(cls, source_id: str, class_id: str = "") -> Optional[Type[SafeConnector]]:
        return cls.SOURCE_ADAPTERS.get(source_id) or cls.CLASS_FALLBACK_ADAPTERS.get(class_id or "")

    @classmethod
    def build(cls, source_record: Dict[str, Any], runtime_policy: Dict[str, Any]) -> Optional[SafeConnector]:
        source_id = str(source_record.get("source_id") or "")
        class_id = str(source_record.get("class_id") or "")
        adapter_class = cls.get_adapter_class(source_id, class_id)
        if not adapter_class:
            return None
        return adapter_class(source_record=source_record, runtime_policy=runtime_policy)

    @classmethod
    def adapter_name_for(cls, source_id: str, class_id: str = "") -> Optional[str]:
        adapter_class = cls.get_adapter_class(source_id, class_id)
        return adapter_class.__name__ if adapter_class else None
