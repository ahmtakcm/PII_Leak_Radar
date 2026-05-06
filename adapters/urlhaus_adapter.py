import csv
import hashlib
from typing import List, Dict, Any
from adapters.base_adapter import BaseAdapter


class UrlhausAdapter(BaseAdapter):
    def fetch(self) -> List[Dict[str, Any]]:
        url = self.get("url")
        limit = int(self.get("limit", 50))
        text = self.fetch_text(url)
        return self.parse_text(text, limit)

    def parse_text(self, text: str, limit: int = 50) -> List[Dict[str, Any]]:
        csv_lines = self._extract_csv_lines(text)
        if not csv_lines:
            return []

        reader = csv.DictReader(csv_lines)
        events = []

        for raw_row in reader:
            if len(events) >= limit:
                break

            row = self._normalize_row(raw_row)

            item_id = (
                row.get("id")
                or row.get("urlhaus_link")
                or row.get("url")
                or self._stable_hash(row)
            )

            threat = row.get("threat") or "malware_url"
            url_value = row.get("url") or ""
            status = row.get("url_status") or ""

            title_parts = ["URLhaus", threat]
            if status:
                title_parts.append(status)
            if url_value:
                title_parts.append(url_value[:120])

            events.append({
                "source_id": self.get("id"),
                "source_name": self.get("name"),
                "source_category": self.get("category"),
                "risk_base": self.get("risk_base", 75),
                "external_id": str(item_id),
                "type": "malware_url",
                "title": " | ".join(title_parts),
                "date_added": row.get("dateadded"),
                "url_status": status,
                "threat": threat,
                "tags": row.get("tags"),
                "reporter": row.get("reporter"),
                "urlhaus_link": row.get("urlhaus_link"),
                "url": url_value,
                "severity": "high",
            })

        return events

    def _extract_csv_lines(self, text: str) -> List[str]:
        lines = []

        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if stripped.startswith("#"):
                maybe_header = stripped.lstrip("#").strip()
                low = maybe_header.lower()

                # URLhaus header genelde "# id,dateadded,url,..." şeklindedir.
                if low.startswith("id,") or low.startswith("dateadded,"):
                    lines.append(maybe_header)

                # Diğer yorum satırlarını atla.
                continue

            lines.append(stripped)

        return lines

    def _normalize_row(self, row: Dict[str, Any]) -> Dict[str, str]:
        normalized = {}

        for key, value in row.items():
            if key is None:
                continue

            clean_key = str(key).strip().lstrip("#").strip().lower()
            clean_value = "" if value is None else str(value).strip()
            normalized[clean_key] = clean_value

        return normalized

    def _stable_hash(self, row: Dict[str, Any]) -> str:
        raw = "|".join(f"{k}={row.get(k, '')}" for k in sorted(row.keys()))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
