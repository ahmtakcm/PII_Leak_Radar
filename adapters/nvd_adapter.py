from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from urllib.parse import urlencode
from adapters.base_adapter import BaseAdapter


class NvdAdapter(BaseAdapter):
    def fetch(self) -> List[Dict[str, Any]]:
        base_url = self.get("base_url")
        limit = int(self.get("limit", 50))
        days_back = int(self.get("days_back", 7))

        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days_back)

        params = {
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": min(limit, 2000),
            "startIndex": 0,
        }

        url = base_url + "?" + urlencode(params)
        data = self.fetch_json(url)
        items = data.get("vulnerabilities", [])[:limit]

        events = []
        for item in items:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            cvss, severity = self._extract_cvss(cve)

            events.append({
                "source_id": self.get("id"),
                "source_name": self.get("name"),
                "source_category": self.get("category"),
                "risk_base": self.get("risk_base", 65),
                "external_id": cve_id,
                "type": "cve",
                "title": cve_id,
                "cve": cve_id,
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "description": desc[:1000],
                "cvss": cvss,
                "severity": severity,
            })
        return events

    def _extract_cvss(self, cve: Dict[str, Any]):
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            values = metrics.get(key) or []
            if values:
                first = values[0]
                cvss_data = first.get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = first.get("baseSeverity") or cvss_data.get("baseSeverity")
                return score, severity
        return None, ""
