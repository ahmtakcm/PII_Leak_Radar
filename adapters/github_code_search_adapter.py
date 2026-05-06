import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlencode

try:
    import yaml
except ModuleNotFoundError:
    yaml = None

from adapters.base_adapter import BaseAdapter


class GitHubCodeSearchAdapter(BaseAdapter):
    """
    Defensive public code search adapter.

    Güvenlik sınırı:
    - Sadece izinli scope varsa çalışır.
    - Token yoksa config notice döner.
    - Public code metadata kaydeder.
    - Dosya içeriği çekmez.
    - Bulunan secret/credential denenmez, kullanılmaz.
    """

    def fetch(self) -> List[Dict[str, Any]]:
        scope_cfg = self._load_scope()
        scope = scope_cfg.get("scope", {}) or {}

        if not self._has_scope(scope):
            return [self._notice(
                "github_scope_missing",
                "GitHub public code search için config/scope.yml içinde izinli kurum kapsamı tanımlı değil.",
                "low",
            )]

        env_key = self.get("env_api_key", "GITHUB_TOKEN")
        token = os.environ.get(env_key)

        if not token:
            return [self._notice(
                "github_token_missing",
                f"{env_key} ortam değişkeni tanımlı değil; GitHub public code search atlandı.",
                "low",
            )]

        queries = self._build_queries(scope)
        if not queries:
            return [self._notice(
                "github_query_empty",
                "GitHub search için kapsamdan güvenli query üretilemedi.",
                "low",
            )]

        total_limit = int(self.get("limit", 25) or 25)
        per_query_limit = int(self.get("per_query_limit", 5) or 5)
        base_url = self.get("base_url", "https://api.github.com/search/code")

        events = []
        seen = set()

        for query in queries:
            if len(events) >= total_limit:
                break

            per_page = max(1, min(per_query_limit, total_limit - len(events), 100))
            url = base_url + "?" + urlencode({
                "q": query,
                "per_page": per_page,
                "page": 1,
            })

            try:
                data = self.fetch_json(url, headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                })
            except Exception as exc:
                events.append(self._notice(
                    "github_api_error_" + self._safe_id(query),
                    f"GitHub code search API hatası: {type(exc).__name__}: {exc}",
                    "medium",
                    query=query,
                ))
                continue

            for item in data.get("items", []) or []:
                repo = item.get("repository", {}) or {}
                html_url = item.get("html_url", "")
                path = item.get("path", "")
                repo_full_name = repo.get("full_name", "")

                dedup_key = html_url or f"{repo_full_name}:{path}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                events.append({
                    "source_id": self.get("id"),
                    "source_name": self.get("name"),
                    "source_category": self.get("category"),
                    "risk_base": self.get("risk_base", 70),
                    "external_id": dedup_key,
                    "type": "github_public_code_hit",
                    "title": f"GitHub public code hit | {repo_full_name} | {path}",
                    "query": query,
                    "repository": repo_full_name,
                    "repository_url": repo.get("html_url", ""),
                    "file_path": path,
                    "file_name": item.get("name", ""),
                    "html_url": html_url,
                    "sha": item.get("sha", ""),
                    "legal_level": self.get("legal_level", "open_public_api_scope_required"),
                    "review_priority": self.get("review_priority", "scope_required"),
                    "severity": self._severity_from_query(query),
                    "recommended_action": (
                        "Public code üzerinde kurum kapsamıyla eşleşen potansiyel sızıntı göstergesi var. "
                        "Dosya içeriği yayılmadan doğrulama, repo sahibine bildirim, kaldırma/rotasyon süreci ve delil kaydı yapılmalı. "
                        "Bulunan token/secret/credential kesinlikle denenmemeli veya kullanılmamalı."
                    ),
                })

                if len(events) >= total_limit:
                    break

            # GitHub search endpoint rate limitlerine saygılı davranmak için küçük gecikme.
            time.sleep(1.2)

        return events

    def _load_scope(self) -> Dict[str, Any]:
        if yaml is None:
            return {"scope": {}, "rules": {}}

        root = Path(__file__).resolve().parent.parent
        scope_path = root / "config" / "scope.yml"

        if not scope_path.exists():
            return {"scope": {}, "rules": {}}

        with scope_path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {"scope": {}, "rules": {}}

    def _has_scope(self, scope: Dict[str, Any]) -> bool:
        return bool(
            scope.get("organization_name")
            or scope.get("organization_domains")
            or scope.get("allowed_keywords")
            or scope.get("allowed_emails")
        )

    def _build_queries(self, scope: Dict[str, Any]) -> List[str]:
        templates = self.get("query_templates", []) or []

        organization_name = str(scope.get("organization_name") or "").strip()
        domains = [str(x).strip() for x in (scope.get("organization_domains") or []) if str(x).strip()]
        keywords = [str(x).strip() for x in (scope.get("allowed_keywords") or []) if str(x).strip()]
        emails = [str(x).strip() for x in (scope.get("allowed_emails") or []) if str(x).strip()]

        queries = []

        for domain in domains:
            for tpl in templates:
                q = str(tpl).replace("{organization_domain}", domain).replace("{organization_name}", organization_name)
                if self._safe_query(q):
                    queries.append(q)

        if organization_name:
            for term in ("api_key", "token", "password", "secret"):
                q = f'"{organization_name}" "{term}"'
                if self._safe_query(q):
                    queries.append(q)

        for keyword in keywords:
            for term in ("api_key", "token", "password", "secret"):
                q = f'"{keyword}" "{term}"'
                if self._safe_query(q):
                    queries.append(q)

        for email in emails:
            q = f'"{email}"'
            if self._safe_query(q):
                queries.append(q)

        # Duplicate temizliği.
        seen = set()
        result = []
        for q in queries:
            key = q.lower()
            if key in seen:
                continue
            seen.add(key)
            result.append(q)

        return result[:20]

    def _safe_query(self, query: str) -> bool:
        q = str(query or "").strip()
        if len(q) < 4:
            return False

        # Çok geniş ve tehlikeli anlamsız aramaları engelle.
        banned_exact = {
            '"password"',
            '"token"',
            '"api_key"',
            '"secret"',
            "password",
            "token",
            "api_key",
            "secret",
        }

        return q.lower() not in banned_exact

    def _severity_from_query(self, query: str) -> str:
        low = query.lower()
        if any(x in low for x in ("password", "token", "api_key", "secret")):
            return "high"
        return "medium"

    def _notice(self, external_id: str, title: str, severity: str = "low", query: str = "") -> Dict[str, Any]:
        return {
            "source_id": self.get("id"),
            "source_name": self.get("name"),
            "source_category": self.get("category"),
            "risk_base": 10 if severity == "low" else 40,
            "external_id": external_id,
            "type": "config_notice",
            "title": title,
            "query": query,
            "legal_level": self.get("legal_level", "open_public_api_scope_required"),
            "review_priority": self.get("review_priority", "scope_required"),
            "severity": severity,
            "recommended_action": "config/scope.yml ve token ayarları kontrol edilmeli; kapsam olmadan public code search çalıştırılmamalı.",
        }

    def _safe_id(self, value: str) -> str:
        return "".join(ch if ch.isalnum() else "_" for ch in value.lower())[:80]
