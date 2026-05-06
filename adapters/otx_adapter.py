import os
from typing import List, Dict, Any
from adapters.base_adapter import BaseAdapter


class OtxAdapter(BaseAdapter):
    def fetch(self) -> List[Dict[str, Any]]:
        env_key = self.get("env_api_key", "OTX_API_KEY")
        api_key = os.environ.get(env_key)

        if not api_key:
            return [{
                "source_id": self.get("id"),
                "source_name": self.get("name"),
                "source_category": self.get("category"),
                "risk_base": 10,
                "external_id": "otx_api_key_missing",
                "type": "config_notice",
                "title": "OTX API key tanımlı değil; OTX taraması atlandı.",
                "severity": "low",
            }]

        limit = int(self.get("limit", 25))
        base_url = self.get("base_url", "https://otx.alienvault.com").rstrip("/")
        url = f"{base_url}/api/v1/pulses/subscribed?limit={limit}"

        data = self.fetch_json(url, headers={"X-OTX-API-KEY": api_key})
        return self.parse_payload(data, limit)

    def parse_payload(self, data: Dict[str, Any], limit: int = 25) -> List[Dict[str, Any]]:
        results = data.get("results", [])[:limit]

        events = []
        for p in results:
            pulse_id = p.get("id") or p.get("name")
            events.append({
                "source_id": self.get("id"),
                "source_name": self.get("name"),
                "source_category": self.get("category"),
                "risk_base": self.get("risk_base", 70),
                "external_id": pulse_id,
                "type": "otx_pulse",
                "title": p.get("name") or "OTX Pulse",
                "created": p.get("created"),
                "modified": p.get("modified"),
                "author_name": p.get("author_name"),
                "tags": p.get("tags"),
                "indicator_count": len(p.get("indicators", []) or []),
                "description": str(p.get("description", ""))[:1000],
                "severity": "medium",
            })
        return events
