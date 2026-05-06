from typing import Any, Dict, List

from adapters.base_adapter import BaseAdapter


class VendorAdvisoryAdapter(BaseAdapter):
    def fetch(self) -> List[Dict[str, Any]]:
        url = self.get("url")
        if not url:
            raise ValueError("vendor advisory source requires a url before live fetch")
        limit = int(self.get("limit", 50))
        data = self.fetch_json(url)
        return self.parse_payload(data, limit)

    def parse_payload(self, data: Dict[str, Any], limit: int = 50) -> List[Dict[str, Any]]:
        items = data.get("advisories") or data.get("items") or []
        events = []

        for item in items[:limit]:
            advisory_id = item.get("id") or item.get("advisory_id") or item.get("url") or item.get("title")
            title = item.get("title") or advisory_id or "Vendor advisory"
            severity = str(item.get("severity") or "medium").lower()

            events.append(
                {
                    "source_id": self.get("id"),
                    "source_name": self.get("name"),
                    "source_category": self.get("category"),
                    "risk_base": self.get("risk_base", 55),
                    "external_id": str(advisory_id or title),
                    "type": "vendor_advisory",
                    "title": title,
                    "published": item.get("published") or item.get("date"),
                    "vendor": item.get("vendor"),
                    "product": item.get("product"),
                    "cve": item.get("cve"),
                    "url": item.get("url"),
                    "description": str(item.get("description", ""))[:1000],
                    "severity": severity,
                }
            )

        return events
