
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PII Leak Radar - Sprint 3 / Step 45B
Paste / Manual Review Parser Runner

Offline, dry-run, alerts-disabled, sanitized runner.
Reads files under paste_manual_review_inbox and produces:
- reports/paste_manual_review_results.json
- reports/paste_manual_review_report.html
"""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import html
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_ROOT = Path(__file__).resolve().parent
INBOX_DIR = PROJECT_ROOT / "paste_manual_review_inbox"
REPORTS_DIR = PROJECT_ROOT / "reports"
SCOPE_PATH = PROJECT_ROOT / "config" / "scope.yml"

RESULT_JSON = REPORTS_DIR / "paste_manual_review_results.json"
RESULT_HTML = REPORTS_DIR / "paste_manual_review_report.html"

ALLOWED_EXTENSIONS = {".txt", ".log", ".json", ".html", ".htm", ".csv"}
MAX_FILE_BYTES = 2_000_000
MAX_FILES = 250
MAX_SNIPPETS_PER_FILE = 30
SNIPPET_RADIUS = 90

DRY_RUN = True
ALERTS_ENABLED = False
MASK_SENSITIVE = True
RAW_SENSITIVE_OUTPUT = False


RISK_TERMS: Dict[str, List[str]] = {
    "leak_dump": [
        "leak", "leaked", "sızıntı", "sizinti", "dump", "database dump", "db dump",
        "breach", "data breach", "veri sızıntısı", "veri sizintisi", "ifşa", "ifsa",
        "combo", "combo list", "paste", "pastebin", "log dump",
    ],
    "credential": [
        "credential", "credentials", "password", "passwd", "pwd", "şifre", "sifre",
        "parola", "login", "username", "user:pass", "mail:pass", "token", "api key",
        "apikey", "secret", "session", "cookie", "access token", "refresh token",
    ],
    "illegal_market": [
        "market", "illegal market", "black market", "darkweb", "dark web",
        "satılık", "satilik", "satılıyor", "satiliyor", "panel", "bot panel",
        "sorgu paneli", "gsm sorgu", "tc sorgu", "kimlik sorgu", "mavi panel",
    ],
    "invite_group": [
        "invite", "invitation", "davet", "telegram", "discord", "whatsapp",
        "kanal", "grup", "group", "join", "katıl", "katil", "t.me/", "discord.gg",
    ],
    "pii_identity": [
        "tc kimlik", "tckn", "kimlik no", "ad soyad", "adres", "telefon", "gsm",
        "iban", "kredi kartı", "kredi karti", "e-posta", "email", "mail",
    ],
}

RISK_WEIGHTS = {
    "leak_dump": 25,
    "credential": 35,
    "illegal_market": 25,
    "invite_group": 15,
    "pii_identity": 20,
}

PII_PATTERNS: Dict[str, re.Pattern[str]] = {
    "email": re.compile(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b"),
    "phone_tr": re.compile(r"(?<!\d)(?:\+?90[\s\-]?)?(?:0[\s\-]?)?5\d{2}[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}(?!\d)"),
    "tckn_like": re.compile(r"(?<!\d)[1-9]\d{10}(?!\d)"),
    "iban_tr": re.compile(r"(?i)\bTR\d{2}[\s\-]?(?:\d{4}[\s\-]?){5}\d{2}\b"),
    "credit_card_like": re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "url": re.compile(r"(?i)\bhttps?://[^\s<>'\"()]+"),
    "token_assignment": re.compile(
        r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd|cookie|authorization)\b\s*[:=]\s*['\"]?[^'\"\s,;<>]{6,}"
    ),
}

PASTE_SOURCE_PATTERNS: Dict[str, re.Pattern[str]] = {
    "pastebin": re.compile(r"(?i)\bhttps?://(?:www\.)?pastebin\.com/(?:raw/)?[A-Za-z0-9]+"),
    "github_gist": re.compile(r"(?i)\bhttps?://gist\.github\.com/[A-Za-z0-9_.-]+/[A-Fa-f0-9]+"),
    "rentry": re.compile(r"(?i)\bhttps?://(?:www\.)?rentry\.co/[A-Za-z0-9_.-]+"),
    "ghostbin": re.compile(r"(?i)\bhttps?://(?:www\.)?ghostbin\.(?:org|co)/[^\s<>'\"()]+"),
    "controlc": re.compile(r"(?i)\bhttps?://(?:www\.)?controlc\.com/[A-Za-z0-9]+"),
}

HTML_TAG_RE = re.compile(r"<[^>]+>")
WHITESPACE_RE = re.compile(r"\s+")


def now_iso() -> str:
    return dt.datetime.now().replace(microsecond=0).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_read_bytes(path: Path) -> Tuple[bytes, Optional[str]]:
    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            with path.open("rb") as f:
                return f.read(MAX_FILE_BYTES), f"truncated: file_size={size}, max_bytes={MAX_FILE_BYTES}"
        return path.read_bytes(), None
    except Exception as exc:
        return b"", f"read_error: {type(exc).__name__}: {exc}"


def decode_bytes(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "cp1254", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def flatten_json(value: Any, prefix: str = "", out: Optional[List[str]] = None) -> List[str]:
    if out is None:
        out = []

    if isinstance(value, dict):
        for key, item in value.items():
            safe_key = str(key)[:80]
            flatten_json(item, f"{prefix}.{safe_key}" if prefix else safe_key, out)
    elif isinstance(value, list):
        for idx, item in enumerate(value[:1000]):
            flatten_json(item, f"{prefix}[{idx}]", out)
    else:
        if value is not None:
            out.append(f"{prefix}: {value}" if prefix else str(value))

    return out


def normalize_text_by_extension(path: Path, text: str) -> str:
    ext = path.suffix.lower()

    if ext in {".html", ".htm"}:
        stripped = HTML_TAG_RE.sub(" ", text)
        return html.unescape(stripped)

    if ext == ".json":
        try:
            parsed = json.loads(text)
            return "\n".join(flatten_json(parsed))
        except Exception:
            return text

    if ext == ".csv":
        try:
            rows: List[str] = []
            reader = csv.reader(text.splitlines())
            for i, row in enumerate(reader):
                if i >= 2000:
                    rows.append("[csv_truncated_rows]")
                    break
                rows.append(" | ".join(row))
            return "\n".join(rows)
        except Exception:
            return text

    return text


def compact_text(text: str) -> str:
    return WHITESPACE_RE.sub(" ", text).strip()


def mask_middle(value: str, keep_start: int = 2, keep_end: int = 2, mask: str = "***") -> str:
    value = str(value)
    if len(value) <= keep_start + keep_end:
        return mask
    return value[:keep_start] + mask + value[-keep_end:]


def mask_email(match: re.Match[str]) -> str:
    value = match.group(0)
    local, domain = value.split("@", 1)
    masked_local = mask_middle(local, 1, 1)
    domain_parts = domain.split(".")
    if domain_parts:
        domain_parts[0] = mask_middle(domain_parts[0], 1, 1)
    return f"{masked_local}@{'.'.join(domain_parts)}"


def mask_phone(match: re.Match[str]) -> str:
    digits = re.sub(r"\D+", "", match.group(0))
    if len(digits) <= 4:
        return "***PHONE***"
    return f"***PHONE:{digits[-4:]}***"


def mask_tckn(match: re.Match[str]) -> str:
    value = match.group(0)
    return f"***TCKN:{value[-2:]}***"


def mask_iban(match: re.Match[str]) -> str:
    value = re.sub(r"\s+|-", "", match.group(0))
    return f"***IBAN:{value[-4:]}***"


def mask_card(match: re.Match[str]) -> str:
    raw = match.group(0)
    digits = re.sub(r"\D+", "", raw)
    if len(digits) < 13 or len(digits) > 19:
        return raw
    return f"***CARD:{digits[-4:]}***"


def mask_ipv4(match: re.Match[str]) -> str:
    parts = match.group(0).split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.***.***"
    return "***IP***"


def mask_url(match: re.Match[str]) -> str:
    value = match.group(0)
    # Preserve rough host context, strip path/query that may contain tokens.
    m = re.match(r"(?i)(https?://)([^/\s?#]+)", value)
    if not m:
        return "***URL***"
    host = m.group(2)
    return f"{m.group(1)}{host}/***"


def sanitize_text(text: str) -> str:
    if not MASK_SENSITIVE:
        return text

    sanitized = text
    sanitized = PII_PATTERNS["token_assignment"].sub(lambda m: f"{m.group(1)}=***SECRET***", sanitized)
    sanitized = PII_PATTERNS["email"].sub(mask_email, sanitized)
    sanitized = PII_PATTERNS["iban_tr"].sub(mask_iban, sanitized)
    sanitized = PII_PATTERNS["phone_tr"].sub(mask_phone, sanitized)
    sanitized = PII_PATTERNS["tckn_like"].sub(mask_tckn, sanitized)
    sanitized = PII_PATTERNS["credit_card_like"].sub(mask_card, sanitized)
    sanitized = PII_PATTERNS["ipv4"].sub(mask_ipv4, sanitized)
    sanitized = PII_PATTERNS["url"].sub(mask_url, sanitized)
    return sanitized


def detect_pii_indicators(text: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for name, pattern in PII_PATTERNS.items():
        if name == "token_assignment":
            # Count secrets as credential indicator too.
            pass
        matches = pattern.findall(text)
        if matches:
            counts[name] = len(matches)
    return counts


def extract_paste_references(text: str) -> List[Dict[str, Any]]:
    refs: List[Dict[str, Any]] = []
    seen = set()

    for source_name, pattern in PASTE_SOURCE_PATTERNS.items():
        for match in pattern.finditer(text):
            url = match.group(0).rstrip(".,;)")
            key = url.lower()
            if key in seen:
                continue
            seen.add(key)
            refs.append({
                "source": source_name,
                "url_masked": sanitize_text(url),
                "url_hash": sha256_text(key)[:16],
            })

    refs.sort(key=lambda x: (str(x.get("source")), str(x.get("url_hash"))))
    return refs[:100]


def load_scope_raw(scope_path: Path) -> Any:
    if not scope_path.exists():
        return {}

    text = scope_path.read_text(encoding="utf-8", errors="replace")

    try:
        import yaml  # type: ignore
        return yaml.safe_load(text) or {}
    except Exception:
        # Minimal fallback: collect useful scalar strings from YAML-ish text.
        terms: List[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # Remove inline comments conservatively.
            if " #" in stripped:
                stripped = stripped.split(" #", 1)[0].strip()
            if ":" in stripped:
                _, rhs = stripped.split(":", 1)
                stripped = rhs.strip()
            if stripped.startswith("-"):
                stripped = stripped[1:].strip()
            stripped = stripped.strip("'\"")
            if stripped and stripped not in {"[]", "{}", "|", ">"}:
                terms.append(stripped)
        return {"fallback_terms": terms}


def collect_scope_terms(obj: Any) -> List[Dict[str, str]]:
    terms: List[Dict[str, str]] = []

    def add_term(value: Any, source_key: str = "scope") -> None:
        if value is None:
            return
        text = str(value).strip()
        if not text:
            return
        # Avoid noisy yaml fragments and overly broad one/two-char tokens.
        if len(text) < 3:
            return
        if text.lower() in {"true", "false", "none", "null", "yes", "no"}:
            return
        if len(text) > 180:
            return
        terms.append({"term": text, "source_key": source_key})

    def walk(value: Any, key: str = "scope") -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                lk = str(k).lower()
                if lk in {
                    "name", "label", "value", "domain", "email", "phone", "keyword",
                    "term", "pattern", "asset", "identifier", "organization", "brand",
                }:
                    add_term(v, str(k))
                else:
                    walk(v, str(k))
        elif isinstance(value, list):
            for item in value:
                walk(item, key)
        else:
            add_term(value, key)

    walk(obj)

    dedup: Dict[str, Dict[str, str]] = {}
    for item in terms:
        key = item["term"].casefold()
        dedup.setdefault(key, item)
    return list(dedup.values())


def mask_asset_label(value: str) -> str:
    value = str(value)
    if "@" in value and PII_PATTERNS["email"].fullmatch(value):
        return PII_PATTERNS["email"].sub(mask_email, value)
    if re.fullmatch(r"(?i)https?://.+", value):
        return PII_PATTERNS["url"].sub(mask_url, value)
    if PII_PATTERNS["phone_tr"].fullmatch(value):
        return PII_PATTERNS["phone_tr"].sub(mask_phone, value)
    if PII_PATTERNS["tckn_like"].fullmatch(value):
        return PII_PATTERNS["tckn_like"].sub(mask_tckn, value)
    if len(value) > 60:
        return value[:18] + "***" + value[-8:]
    return value


def find_asset_matches(text: str, scope_terms: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    lowered = text.casefold()
    matches: List[Dict[str, Any]] = []

    for item in scope_terms:
        term = item["term"]
        term_norm = term.casefold().strip()
        if len(term_norm) < 3:
            continue

        # Avoid matching generic noisy terms.
        if term_norm in {
            "http", "https", "www", "com", "net", "org", "mail", "test", "demo",
            "true", "false", "active", "enabled", "disabled",
        }:
            continue

        idx = lowered.find(term_norm)
        if idx >= 0:
            matches.append({
                "asset_label": sanitize_text(mask_asset_label(term)),
                "asset_hash": sha256_text(term_norm)[:16],
                "source_key": item.get("source_key", "scope"),
                "match_count": lowered.count(term_norm),
            })

    matches.sort(key=lambda x: (-int(x["match_count"]), str(x["asset_label"])))
    return matches[:50]


def find_keyword_hits(text: str) -> List[Dict[str, Any]]:
    lowered = text.casefold()
    hits: List[Dict[str, Any]] = []

    for category, terms in RISK_TERMS.items():
        category_hits: List[Dict[str, Any]] = []
        for term in terms:
            term_norm = term.casefold()
            start = 0
            found_count = 0

            while True:
                idx = lowered.find(term_norm, start)
                if idx < 0:
                    break

                found_count += 1
                if len(category_hits) < MAX_SNIPPETS_PER_FILE:
                    s = max(0, idx - SNIPPET_RADIUS)
                    e = min(len(text), idx + len(term) + SNIPPET_RADIUS)
                    snippet = compact_text(text[s:e])
                    category_hits.append({
                        "term": term,
                        "snippet": sanitize_text(snippet),
                        "snippet_hash": sha256_text(snippet)[:16],
                    })

                start = idx + max(1, len(term_norm))

            if found_count and not any(x["term"] == term for x in category_hits):
                category_hits.append({
                    "term": term,
                    "snippet": "",
                    "snippet_hash": "",
                })

        if category_hits:
            hits.append({
                "category": category,
                "weight": RISK_WEIGHTS.get(category, 10),
                "hits": category_hits[:MAX_SNIPPETS_PER_FILE],
                "hit_count": sum(1 for _ in category_hits),
            })

    return hits


def score_file(
    keyword_hits: List[Dict[str, Any]],
    asset_matches: List[Dict[str, Any]],
    pii_counts: Dict[str, int],
    paste_refs: List[Dict[str, Any]],
) -> Tuple[int, str, List[str]]:
    score = 0
    reasons: List[str] = []

    categories = {hit["category"] for hit in keyword_hits}
    for cat in sorted(categories):
        score += RISK_WEIGHTS.get(cat, 10)
        reasons.append(f"risk_context:{cat}")

    if asset_matches:
        score += min(35, 15 + len(asset_matches) * 5)
        reasons.append(f"asset_match:{len(asset_matches)}")

    if paste_refs:
        score += min(15, 5 + len(paste_refs) * 2)
        reasons.append(f"paste_reference:{len(paste_refs)}")

    pii_total = sum(pii_counts.values())
    if pii_total:
        score += min(25, 10 + pii_total)
        reasons.append(f"pii_indicator:{pii_total}")

    # Strong combinations.
    if "credential" in categories and asset_matches:
        score += 15
        reasons.append("combo:credential+asset")
    if "leak_dump" in categories and asset_matches:
        score += 10
        reasons.append("combo:leak+asset")
    if paste_refs and asset_matches:
        score += 10
        reasons.append("combo:paste+asset")
    if "illegal_market" in categories and ("credential" in categories or "pii_identity" in categories):
        score += 10
        reasons.append("combo:illegal_market+sensitive_context")

    score = max(0, min(100, score))

    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 35:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "none"

    return score, level, reasons


def scan_file(path: Path, scope_terms: List[Dict[str, str]]) -> Dict[str, Any]:
    data, read_note = safe_read_bytes(path)
    raw_hash = sha256_bytes(data) if data else ""

    text = decode_bytes(data)
    normalized = normalize_text_by_extension(path, text)
    normalized = compact_text(normalized)

    keyword_hits = find_keyword_hits(normalized)
    pii_counts = detect_pii_indicators(normalized)
    asset_matches = find_asset_matches(normalized, scope_terms)
    paste_refs = extract_paste_references(normalized)
    risk_score, risk_level, reasons = score_file(keyword_hits, asset_matches, pii_counts, paste_refs)

    result: Dict[str, Any] = {
        "file": str(path.relative_to(PROJECT_ROOT)),
        "extension": path.suffix.lower(),
        "size_bytes_read": len(data),
        "sha256": raw_hash,
        "read_note": read_note,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_reasons": reasons,
        "keyword_contexts": keyword_hits,
        "pii_indicators": pii_counts,
        "asset_matches": asset_matches,
        "paste_references": paste_refs,
        "paste_source_count": len({ref.get("source") for ref in paste_refs}),
    }

    if RAW_SENSITIVE_OUTPUT:
        result["raw_text_preview"] = normalized[:2000]
    else:
        result["sanitized_preview"] = sanitize_text(normalized[:1000])

    return result


def discover_inbox_files() -> List[Path]:
    if not INBOX_DIR.exists():
        INBOX_DIR.mkdir(parents=True, exist_ok=True)

    files = [
        p for p in INBOX_DIR.rglob("*")
        if p.is_file() and p.suffix.lower() in ALLOWED_EXTENSIONS
    ]
    files.sort(key=lambda p: str(p).lower())
    return files[:MAX_FILES]


def summarize(files: List[Dict[str, Any]]) -> Dict[str, Any]:
    risk_summary: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    context_summary: Dict[str, int] = {}
    pii_summary: Dict[str, int] = {}
    paste_summary: Dict[str, int] = {}
    total_asset_matches = 0
    total_paste_refs = 0

    for item in files:
        risk_summary[item.get("risk_level", "none")] = risk_summary.get(item.get("risk_level", "none"), 0) + 1
        total_asset_matches += len(item.get("asset_matches", []))
        total_paste_refs += len(item.get("paste_references", []))

        for ctx in item.get("keyword_contexts", []):
            cat = ctx.get("category", "unknown")
            context_summary[cat] = context_summary.get(cat, 0) + 1

        for pii_name, count in item.get("pii_indicators", {}).items():
            pii_summary[pii_name] = pii_summary.get(pii_name, 0) + int(count)

        for ref in item.get("paste_references", []):
            source = str(ref.get("source", "unknown"))
            paste_summary[source] = paste_summary.get(source, 0) + 1

    return {
        "risk_summary": risk_summary,
        "context_summary": context_summary,
        "pii_summary": pii_summary,
        "paste_summary": paste_summary,
        "paste_reference_count": total_paste_refs,
        "asset_match_count": total_asset_matches,
    }


def build_report(scope_terms: List[Dict[str, str]], files: List[Dict[str, Any]]) -> Dict[str, Any]:
    summary = summarize(files)
    status = "ok"
    warnings: List[str] = []

    if not SCOPE_PATH.exists():
        warnings.append("config/scope.yml bulunamadı; asset match sadece boş scope ile çalıştı.")
    if len(discover_inbox_files()) >= MAX_FILES:
        warnings.append(f"Dosya limiti uygulandı: MAX_FILES={MAX_FILES}")

    return {
        "status": status,
        "runner": "run_paste_manual_review.py",
        "step": "45B",
        "checked_at": now_iso(),
        "mode": "dry-run" if DRY_RUN else "live",
        "alerts_enabled": ALERTS_ENABLED,
        "mask_sensitive": MASK_SENSITIVE,
        "raw_sensitive_output": RAW_SENSITIVE_OUTPUT,
        "legal_notice": (
            "Bu runner yalnızca offline/manual review ve savunma amaçlı risk sinyali üretir. "
            "Yetkisiz erişim, credential kullanımı, bypass, exploit veya kapalı kaynaklara erişim yapmaz."
        ),
        "paths": {
            "project_root": str(PROJECT_ROOT),
            "inbox": str(INBOX_DIR),
            "scope": str(SCOPE_PATH),
            "json": str(RESULT_JSON),
            "html": str(RESULT_HTML),
        },
        "scope_term_count": len(scope_terms),
        "files_scanned": len(files),
        "finding_count": sum(1 for f in files if f.get("risk_level") != "none"),
        "warning_count": len(warnings),
        "warnings": warnings,
        **summary,
        "files": files,
    }


def html_badge(level: str) -> str:
    cls = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "none": "none",
    }.get(level, "none")
    return f'<span class="badge {cls}">{html.escape(level)}</span>'


def render_html(report: Dict[str, Any]) -> str:
    files = report.get("files", [])
    rows: List[str] = []

    for item in files:
        contexts = ", ".join(
            html.escape(ctx.get("category", ""))
            for ctx in item.get("keyword_contexts", [])
        ) or "-"

        assets = item.get("asset_matches", [])
        asset_html = "<br>".join(
            f'{html.escape(str(a.get("asset_label", "")))} '
            f'<small>#{html.escape(str(a.get("asset_hash", "")))}</small>'
            for a in assets[:10]
        ) or "-"

        pii = item.get("pii_indicators", {})
        pii_html = "<br>".join(
            f"{html.escape(str(k))}: {html.escape(str(v))}"
            for k, v in pii.items()
        ) or "-"

        paste_refs = item.get("paste_references", [])
        paste_html = "<br>".join(
            f'{html.escape(str(ref.get("source", "")))} '
            f'<small>#{html.escape(str(ref.get("url_hash", "")))}</small>'
            for ref in paste_refs[:10]
        ) or "-"

        snippets: List[str] = []
        for ctx in item.get("keyword_contexts", []):
            for hit in ctx.get("hits", [])[:3]:
                snip = hit.get("snippet") or hit.get("term") or ""
                if snip:
                    snippets.append(
                        f'<div class="snippet"><b>{html.escape(ctx.get("category", ""))}</b>: '
                        f'{html.escape(str(snip))}</div>'
                    )
        snippets_html = "\n".join(snippets[:8]) or '<span class="muted">-</span>'

        rows.append(f"""
        <tr>
          <td>
            <b>{html.escape(item.get("file", ""))}</b><br>
            <small>sha256: {html.escape(item.get("sha256", "")[:16])}...</small>
          </td>
          <td>{html_badge(item.get("risk_level", "none"))}<br><b>{html.escape(str(item.get("risk_score", 0)))}</b>/100</td>
          <td>{contexts}</td>
          <td>{paste_html}</td>
          <td>{asset_html}</td>
          <td>{pii_html}</td>
          <td>{snippets_html}</td>
        </tr>
        """)

    risk_summary = report.get("risk_summary", {})
    context_summary = report.get("context_summary", {})
    pii_summary = report.get("pii_summary", {})
    paste_summary = report.get("paste_summary", {})

    def dict_cards(data: Dict[str, Any]) -> str:
        if not data:
            return '<span class="muted">-</span>'
        return "".join(
            f'<span class="pill">{html.escape(str(k))}: <b>{html.escape(str(v))}</b></span>'
            for k, v in data.items()
        )

    return f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>PII Leak Radar - Paste Manual Review Report</title>
<style>
:root {{
  --bg: #0f172a;
  --card: #111827;
  --text: #e5e7eb;
  --muted: #9ca3af;
  --border: #374151;
}}
body {{
  margin: 0;
  padding: 24px;
  background: var(--bg);
  color: var(--text);
  font-family: Arial, Helvetica, sans-serif;
}}
h1, h2 {{ margin: 0 0 12px; }}
.card {{
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 16px;
  margin-bottom: 16px;
}}
.grid {{
  display: grid;
  grid-template-columns: repeat(4, minmax(160px, 1fr));
  gap: 12px;
}}
.kpi {{
  background: #020617;
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 12px;
}}
.kpi b {{
  display: block;
  font-size: 24px;
  margin-top: 6px;
}}
table {{
  width: 100%;
  border-collapse: collapse;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 14px;
  overflow: hidden;
}}
th, td {{
  vertical-align: top;
  border-bottom: 1px solid var(--border);
  padding: 10px;
  font-size: 13px;
}}
th {{
  text-align: left;
  background: #020617;
  color: #f9fafb;
}}
small, .muted {{ color: var(--muted); }}
.badge {{
  display: inline-block;
  padding: 4px 8px;
  border-radius: 999px;
  font-weight: 700;
  font-size: 12px;
}}
.critical {{ background: #7f1d1d; color: #fecaca; }}
.high {{ background: #9a3412; color: #fed7aa; }}
.medium {{ background: #854d0e; color: #fef3c7; }}
.low {{ background: #164e63; color: #cffafe; }}
.none {{ background: #374151; color: #e5e7eb; }}
.pill {{
  display: inline-block;
  padding: 6px 9px;
  margin: 4px 4px 0 0;
  background: #020617;
  border: 1px solid var(--border);
  border-radius: 999px;
}}
.snippet {{
  max-width: 520px;
  margin-bottom: 6px;
  color: #d1d5db;
}}
.footer {{
  margin-top: 16px;
  color: var(--muted);
  font-size: 12px;
}}
</style>
</head>
<body>
  <div class="card">
    <h1>PII Leak Radar - Paste Manual Review Report</h1>
    <div class="muted">
      checked_at={html.escape(str(report.get("checked_at", "")))} |
      mode={html.escape(str(report.get("mode", "")))} |
      alerts_enabled={html.escape(str(report.get("alerts_enabled", "")))} |
      mask_sensitive={html.escape(str(report.get("mask_sensitive", "")))} |
      raw_sensitive_output={html.escape(str(report.get("raw_sensitive_output", "")))}
    </div>
  </div>

  <div class="grid">
    <div class="kpi">Files scanned <b>{html.escape(str(report.get("files_scanned", 0)))}</b></div>
    <div class="kpi">Findings <b>{html.escape(str(report.get("finding_count", 0)))}</b></div>
    <div class="kpi">Asset matches <b>{html.escape(str(report.get("asset_match_count", 0)))}</b></div>
    <div class="kpi">Paste refs <b>{html.escape(str(report.get("paste_reference_count", 0)))}</b></div>
  </div>

  <div class="card">
    <h2>Summary</h2>
    <p><b>Risk:</b> {dict_cards(risk_summary)}</p>
    <p><b>Contexts:</b> {dict_cards(context_summary)}</p>
    <p><b>Paste sources:</b> {dict_cards(paste_summary)}</p>
    <p><b>PII indicators:</b> {dict_cards(pii_summary)}</p>
  </div>

  <table>
    <thead>
      <tr>
        <th>File</th>
        <th>Risk</th>
        <th>Contexts</th>
        <th>Paste Sources</th>
        <th>Asset Matches</th>
        <th>PII Indicators</th>
        <th>Sanitized Evidence Snippets</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows) if rows else '<tr><td colspan="7" class="muted">No files found.</td></tr>'}
    </tbody>
  </table>

  <div class="footer">
    {html.escape(str(report.get("legal_notice", "")))}<br>
    JSON: {html.escape(str(report.get("paths", {}).get("json", "")))}
  </div>
</body>
</html>
"""


def main() -> int:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    INBOX_DIR.mkdir(parents=True, exist_ok=True)

    scope_raw = load_scope_raw(SCOPE_PATH)
    scope_terms = collect_scope_terms(scope_raw)

    files: List[Dict[str, Any]] = []
    for path in discover_inbox_files():
        files.append(scan_file(path, scope_terms))

    report = build_report(scope_terms, files)

    RESULT_JSON.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    RESULT_HTML.write_text(render_html(report), encoding="utf-8")

    print("PASTE_MANUAL_REVIEW_RUNNER")
    print(f"status={report['status']}")
    print(f"mode={report['mode']}")
    print(f"alerts_enabled={report['alerts_enabled']}")
    print(f"mask_sensitive={report['mask_sensitive']}")
    print(f"raw_sensitive_output={report['raw_sensitive_output']}")
    print(f"scope_term_count={report['scope_term_count']}")
    print(f"files_scanned={report['files_scanned']}")
    print(f"finding_count={report['finding_count']}")
    print(f"asset_match_count={report['asset_match_count']}")
    print(f"warning_count={report['warning_count']}")
    print(f"json={RESULT_JSON}")
    print(f"html={RESULT_HTML}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
