from typing import List, Dict, Any
from adapters.base_adapter import BaseAdapter


class CisaKevAdapter(BaseAdapter):
    def fetch(self) -> List[Dict[str, Any]]:
        url = self.get("url")
        limit = int(self.get("limit", 100))
        data = self.fetch_json(url)
        return self.parse_payload(data, limit)

    def parse_payload(self, data: Dict[str, Any], limit: int = 100) -> List[Dict[str, Any]]:
        vulns = data.get("vulnerabilities", [])[:limit]

        events = []
        for v in vulns:
            cve = v.get("cveID", "")
            title = v.get("vulnerabilityName") or cve
            events.append({
                "source_id": self.get("id"),
                "source_name": self.get("name"),
                "source_category": self.get("category"),
                "risk_base": self.get("risk_base", 85),
                "external_id": cve,
                "type": "known_exploited_vulnerability",
                "title": title,
                "cve": cve,
                "vendor_project": v.get("vendorProject"),
                "product": v.get("product"),
                "date_added": v.get("dateAdded"),
                "due_date": v.get("dueDate"),
                "known_ransomware_campaign_use": v.get("knownRansomwareCampaignUse"),
                "required_action": v.get("requiredAction"),
                "description": v.get("shortDescription"),
                "severity": "high",
            })
        return events
