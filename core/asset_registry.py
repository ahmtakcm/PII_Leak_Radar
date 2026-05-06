from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from core.masking import mask_value
except ImportError:
    from masking import mask_value

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCAL_PATH = PROJECT_ROOT / "assets" / "assets.local.json"
DEFAULT_SAMPLE_PATH = PROJECT_ROOT / "assets" / "assets.sample.json"

FIELD_TYPE_MAP = {
    "emails": "email",
    "phones": "phone",
    "usernames": "username",
    "aliases": "alias",
    "domains": "domain",
    "subdomains": "domain",
    "keywords": "keyword",
    "profile_urls": "url",
    "urls": "url",
}

SENSITIVITY_WEIGHT = {
    "low": 20,
    "medium": 40,
    "high": 60,
    "critical": 80,
}

def normalize_text(value: Any) -> str:
    text = "" if value is None else str(value)
    text = text.strip().lower()
    text = text.replace("ı", "i").replace("ğ", "g").replace("ü", "u")
    text = text.replace("ş", "s").replace("ö", "o").replace("ç", "c")
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = re.sub(r"\s+", " ", text)
    return text.strip()

def compact_text(value: Any) -> str:
    text = normalize_text(value)
    return re.sub(r"[^a-z0-9@._+:/-]+", "", text)

def normalize_phone(value: Any) -> str:
    text = "" if value is None else str(value)
    digits = re.sub(r"\D+", "", text)
    if digits.startswith("90") and len(digits) == 12:
        return "+" + digits
    if digits.startswith("0") and len(digits) == 11:
        return "+9" + digits
    if len(digits) == 10:
        return "+90" + digits
    if text.strip().startswith("+") and digits:
        return "+" + digits
    return digits

def normalize_by_type(value: Any, value_type: str) -> str:
    kind = str(value_type or "").lower().strip()
    if kind == "phone":
        return normalize_phone(value)
    return compact_text(value)

def safe_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, tuple):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    return [text] if text else []

def load_json_file(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError("Asset file not found: " + str(path))
    with path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Asset file root must be a JSON object")
    return data

def pick_default_asset_file() -> Path:
    if DEFAULT_LOCAL_PATH.exists():
        try:
            data = load_json_file(DEFAULT_LOCAL_PATH)
            if data.get("assets"):
                return DEFAULT_LOCAL_PATH
        except Exception:
            pass
    return DEFAULT_SAMPLE_PATH

class AssetRegistry:
    def __init__(self, data: Dict[str, Any], source_path: Optional[Path] = None):
        self.data = data
        self.source_path = source_path
        self.schema_version = str(data.get("schema_version", ""))
        self.project = str(data.get("project", "PII Leak Radar"))
        self.mode = str(data.get("mode", "unknown"))
        self.default_context_keywords = safe_list(data.get("default_context_keywords"))
        self.assets = self._load_assets(data.get("assets", []))
        self.match_values = self._build_match_values()

    def _load_assets(self, raw_assets: Any) -> List[Dict[str, Any]]:
        if not isinstance(raw_assets, list):
            raise ValueError("assets must be a list")
        assets = []
        for index, item in enumerate(raw_assets):
            if not isinstance(item, dict):
                continue
            asset = dict(item)
            asset.setdefault("asset_id", "asset_" + str(index + 1).zfill(3))
            asset.setdefault("asset_kind", "custom")
            asset.setdefault("display_name", asset.get("asset_id"))
            asset.setdefault("sensitivity", "medium")
            asset.setdefault("enabled", True)
            if asset.get("enabled") is False:
                continue
            assets.append(asset)
        return assets

    def _build_match_values(self) -> List[Dict[str, Any]]:
        values = []
        for asset in self.assets:
            asset_id = str(asset.get("asset_id", ""))
            asset_kind = str(asset.get("asset_kind", "custom"))
            display_name = str(asset.get("display_name", asset_id))
            sensitivity = str(asset.get("sensitivity", "medium")).lower().strip()
            base_weight = SENSITIVITY_WEIGHT.get(sensitivity, 40)

            for field_name, value_type in FIELD_TYPE_MAP.items():
                for raw_value in safe_list(asset.get(field_name)):
                    normalized = normalize_by_type(raw_value, value_type)
                    if not normalized:
                        continue
                    values.append({
                        "asset_id": asset_id,
                        "asset_kind": asset_kind,
                        "display_name": display_name,
                        "sensitivity": sensitivity,
                        "base_weight": base_weight,
                        "field_name": field_name,
                        "value_type": value_type,
                        "raw_value": raw_value,
                        "normalized_value": normalized,
                        "masked_value": mask_value(raw_value, value_type),
                    })

            if display_name.strip():
                values.append({
                    "asset_id": asset_id,
                    "asset_kind": asset_kind,
                    "display_name": display_name,
                    "sensitivity": sensitivity,
                    "base_weight": base_weight,
                    "field_name": "display_name",
                    "value_type": "name",
                    "raw_value": display_name,
                    "normalized_value": normalize_by_type(display_name, "keyword"),
                    "masked_value": mask_value(display_name, "alias"),
                })
        return values

    def summary(self) -> Dict[str, Any]:
        by_type = {}
        for value in self.match_values:
            value_type = value.get("value_type", "unknown")
            by_type[value_type] = by_type.get(value_type, 0) + 1
        return {
            "project": self.project,
            "mode": self.mode,
            "schema_version": self.schema_version,
            "source_path": str(self.source_path) if self.source_path else None,
            "asset_count": len(self.assets),
            "match_value_count": len(self.match_values),
            "by_type": by_type,
        }

    def iter_match_values(self) -> Iterable[Dict[str, Any]]:
        return iter(self.match_values)

def load_asset_registry(path: Optional[str] = None) -> AssetRegistry:
    selected_path = Path(path).resolve() if path else pick_default_asset_file()
    data = load_json_file(selected_path)
    return AssetRegistry(data, selected_path)

def print_registry_report(registry: AssetRegistry) -> None:
    s = registry.summary()
    print("ASSET_REGISTRY_OK")
    print("source=" + str(s.get("source_path")))
    print("mode=" + str(s.get("mode")))
    print("asset_count=" + str(s.get("asset_count")))
    print("match_value_count=" + str(s.get("match_value_count")))
    print("by_type=" + str(s.get("by_type")))
    print("")
    print("Sample masked match values:")
    for item in registry.match_values[:12]:
        print("- " + item.get("asset_id", "") + " | " + item.get("value_type", "") + " | " + item.get("masked_value", "") + " | norm=" + item.get("normalized_value", ""))

if __name__ == "__main__":
    registry = load_asset_registry()
    print_registry_report(registry)
