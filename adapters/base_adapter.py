import json
import urllib.request
from typing import Dict, Any, Optional


class BaseAdapter:
    def __init__(self, source: Dict[str, Any], timeout: int = 30):
        self.source = source
        self.timeout = timeout

    def get(self, key: str, default=None):
        return self.source.get(key, default)

    def fetch(self):
        raise NotImplementedError

    def fetch_text(self, url: str, headers: Optional[Dict[str, str]] = None) -> str:
        req_headers = {
            "User-Agent": "PII-Leak-Radar/1.0 defensive-osint",
            "Accept": "*/*",
        }
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(url, headers=req_headers, method="GET")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def fetch_json(self, url: str, headers: Optional[Dict[str, str]] = None):
        text = self.fetch_text(url, headers=headers)
        return json.loads(text)
