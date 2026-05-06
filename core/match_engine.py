from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

try:
    from core.asset_registry import AssetRegistry, load_asset_registry, normalize_by_type, compact_text
    from core.masking import mask_value, build_masked_snippet
except ImportError:
    from asset_registry import AssetRegistry, load_asset_registry, normalize_by_type, compact_text
    from masking import mask_value, build_masked_snippet

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]{1,80}@[A-Za-z0-9.\-]{1,120}\.[A-Za-z]{2,20}\b")
PHONE_RE = re.compile(r"(?<!\d)(\+?\d[\d\s().\-]{7,22}\d)(?!\d)")
URL_RE = re.compile(r"\bhttps?://[^\s<>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,20}\b", re.IGNORECASE)

RISK_CONTEXT_KEYWORDS = [
    "leak", "dump", "combo", "database", "breach", "sizinti", "sızıntı",
    "telegram", "discord", "market", "satilik", "satılık", "satis", "satış",
    "panel", "log", "stealer", "credential", "password", "bot", "davet", "invite"
]

MATCH_TYPE_WEIGHT = {
    "exact": 20,
    "regex": 18,
    "normalized": 12,
    "context": 8,
}

VALUE_TYPE_WEIGHT = {
    "email": 14,
    "phone": 16,
    "username": 8,
    "domain": 8,
    "url": 8,
    "keyword": 6,
    "alias": 5,
    "name": 5,
}

def _safe_text(value: Any) -> str:
    return "" if value is None else str(value)

def _find_context_keywords(text: str, extra_keywords: Optional[List[str]] = None) -> List[str]:
    compact = compact_text(text)
    found = []
    keywords = list(RISK_CONTEXT_KEYWORDS)
    if extra_keywords:
        keywords.extend(extra_keywords)

    for keyword in keywords:
        nk = compact_text(keyword)
        if nk and nk in compact and keyword not in found:
            found.append(keyword)
    return found

def _score_match(asset_value: Dict[str, Any], match_type: str, context_keywords: List[str]) -> int:
    base = int(asset_value.get("base_weight", 40))
    value_type = str(asset_value.get("value_type", "unknown"))
    score = base
    score += MATCH_TYPE_WEIGHT.get(match_type, 5)
    score += VALUE_TYPE_WEIGHT.get(value_type, 4)

    if context_keywords:
        score += min(20, len(context_keywords) * 5)

    if value_type in {"email", "phone"} and match_type in {"exact", "regex"}:
        score += 8

    return max(0, min(100, score))

def _make_match(asset_value: Dict[str, Any], match_type: str, source_id: str, source_type: str, text: str, start: int, end: int, context_keywords: List[str]) -> Dict[str, Any]:
    value_type = str(asset_value.get("value_type", "unknown"))
    raw_value = str(asset_value.get("raw_value", ""))
    return {
        "asset_id": asset_value.get("asset_id"),
        "asset_kind": asset_value.get("asset_kind"),
        "display_name": asset_value.get("display_name"),
        "field_name": asset_value.get("field_name"),
        "value_type": value_type,
        "match_type": match_type,
        "risk_score": _score_match(asset_value, match_type, context_keywords),
        "matched_value_masked": mask_value(raw_value, value_type),
        "context_keywords": context_keywords,
        "snippet_masked": build_masked_snippet(text, start, end),
        "source_id": source_id,
        "source_type": source_type,
    }

def _dedupe(matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    best = {}
    for item in matches:
        key = (
            item.get("asset_id"),
            item.get("field_name"),
            item.get("value_type"),
            item.get("matched_value_masked"),
            item.get("source_id"),
        )
        old = best.get(key)
        if old is None or int(item.get("risk_score", 0)) > int(old.get("risk_score", 0)):
            best[key] = item
    return sorted(best.values(), key=lambda x: int(x.get("risk_score", 0)), reverse=True)

def _regex_candidates(text: str) -> List[Dict[str, Any]]:
    candidates = []
    for kind, regex in [("email", EMAIL_RE), ("phone", PHONE_RE), ("url", URL_RE), ("domain", DOMAIN_RE)]:
        for m in regex.finditer(text):
            candidates.append({
                "value_type": kind,
                "value": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "normalized": normalize_by_type(m.group(0), kind),
            })
    return candidates

def find_matches(text: str, registry: Optional[AssetRegistry] = None, source_id: str = "dry_run", source_type: str = "text") -> List[Dict[str, Any]]:
    text = _safe_text(text)
    registry = registry or load_asset_registry()
    context_keywords = _find_context_keywords(text, registry.default_context_keywords)
    matches = []
    compact_body = compact_text(text)

    regex_index = {}
    for c in _regex_candidates(text):
        regex_index.setdefault((c["value_type"], c["normalized"]), []).append(c)

    for asset_value in registry.iter_match_values():
        raw = str(asset_value.get("raw_value", ""))
        normalized = str(asset_value.get("normalized_value", ""))
        value_type = str(asset_value.get("value_type", ""))

        if not raw or not normalized:
            continue

        if len(normalized) < 3 and value_type not in {"phone"}:
            continue

        exact_pattern = re.compile(re.escape(raw), re.IGNORECASE)
        exact_hit = False
        for m in exact_pattern.finditer(text):
            exact_hit = True
            matches.append(_make_match(asset_value, "exact", source_id, source_type, text, m.start(), m.end(), context_keywords))

        if value_type in {"email", "phone", "domain", "url"}:
            for c in regex_index.get((value_type, normalized), []):
                matches.append(_make_match(asset_value, "regex", source_id, source_type, text, c["start"], c["end"], context_keywords))

        if not exact_hit and normalized in compact_body:
            matches.append(_make_match(asset_value, "normalized", source_id, source_type, text, 0, min(len(text), 160), context_keywords))

    return _dedupe(matches)

def summarize_matches(matches: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_asset = {}
    max_score = 0
    for item in matches:
        aid = str(item.get("asset_id"))
        by_asset[aid] = by_asset.get(aid, 0) + 1
        max_score = max(max_score, int(item.get("risk_score", 0)))
    return {
        "match_count": len(matches),
        "asset_count": len(by_asset),
        "max_risk_score": max_score,
        "by_asset": by_asset,
    }

def scan_text(text: str, source_id: str = "dry_run", source_type: str = "text", asset_file: Optional[str] = None) -> Dict[str, Any]:
    registry = load_asset_registry(asset_file) if asset_file else load_asset_registry()
    matches = find_matches(text, registry=registry, source_id=source_id, source_type=source_type)
    return {
        "status": "ok",
        "source_id": source_id,
        "source_type": source_type,
        "summary": summarize_matches(matches),
        "matches": matches,
    }

if __name__ == "__main__":
    sample_text = "Telegram leak dump içinde sample.person@example.com ve +905551112233 geçti. Ayrıca login.example.net panel log ifadesi var."
    result = scan_text(sample_text, source_id="match_engine_self_test", source_type="dry_run")
    print("MATCH_ENGINE_OK")
    print(json.dumps(result, ensure_ascii=False, indent=2))
