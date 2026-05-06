from pathlib import Path
from typing import Dict, Any, List


KNOWN_ACTIVE_ADAPTERS = {
    "cisa_kev",
    "nvd",
    "urlhaus",
    "otx",
    "github_code_search",
}

PLACEHOLDER_ADAPTERS = {
    "vendor_advisory_placeholder",
    "manual_placeholder",
    "export_placeholder",
}


def load_scope(scope_path: Path) -> Dict[str, Any]:
    try:
        import yaml
    except ModuleNotFoundError as exc:
        raise SystemExit("PyYAML eksik. Kurulum: py -m pip install -r requirements.txt") from exc

    if not scope_path.exists():
        return {"scope": {}, "rules": {}}

    with scope_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {"scope": {}, "rules": {}}


def build_catalog(registry: Dict[str, Any], scope_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    sources = registry.get("sources", [])
    scope = scope_cfg.get("scope", {}) or {}
    rules = scope_cfg.get("rules", {}) or {}

    has_scope = bool(
        scope.get("organization_name")
        or scope.get("organization_domains")
        or scope.get("allowed_keywords")
        or scope.get("allowed_emails")
        or scope.get("allowed_phone_prefixes")
    )

    rows = []

    for source in sources:
        adapter = source.get("adapter", "")
        enabled = bool(source.get("enabled", False))
        requires_scope = bool(source.get("requires_scope", False))
        requires_manual_legal_review = bool(source.get("requires_manual_legal_review", False))

        status = "active" if enabled else "catalog_only"
        blocker = ""
        recommended_next_step = source.get("suggested_action", "")

        if adapter in PLACEHOLDER_ADAPTERS:
            status = "placeholder" if not enabled else "needs_adapter"

        if requires_scope and not has_scope:
            status = "scope_required"
            blocker = "config/scope.yml içinde kurum kapsamı boş."
            recommended_next_step = "Aktif edilmeden önce organization_name/domain/allowed keyword kapsamı tanımlanmalı."

        if requires_manual_legal_review or source.get("legal_level", "").startswith("high_risk"):
            status = "legal_review_required"
            blocker = "Yüksek riskli kaynak tipi; manuel yasal/operasyonel kontrol gerekli."
            recommended_next_step = "Aktif erişim yapılmadan yalnızca yasal/izinli rapor veya kullanıcı sağladığı delil üzerinden kayıt açılmalı."

        if enabled and adapter not in KNOWN_ACTIVE_ADAPTERS:
            status = "needs_adapter"
            blocker = f"Adapter henüz uygulanmadı: {adapter}"
            recommended_next_step = "Adapter yazılmadan ve güvenlik kontrolleri tamamlanmadan enabled=true yapılmamalı."

        if rules.get("require_scope_for_public_code_search") and source.get("category") == "public_code_search" and not has_scope:
            status = "scope_required"
            blocker = "Public code search için izinli kapsam gerekli."
            recommended_next_step = "Önce config/scope.yml içinde kurum domain/marka kapsamını gir."

        rows.append({
            "id": source.get("id", ""),
            "name": source.get("name", ""),
            "enabled": enabled,
            "status": status,
            "adapter": adapter,
            "category": source.get("category", ""),
            "legal_level": source.get("legal_level", ""),
            "review_priority": source.get("review_priority", ""),
            "risk_base": source.get("risk_base", ""),
            "requires_scope": requires_scope,
            "blocker": blocker,
            "recommended_next_step": recommended_next_step,
        })

    return rows

