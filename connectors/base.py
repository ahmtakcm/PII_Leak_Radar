from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Type


@dataclass
class ConnectorDecision:
    """Dry-run decision returned by a connector adapter.

    This object is intentionally metadata-only. It must not contain raw leaked
    records, credentials, tokens, cookies, invite links, or secrets.
    """

    source_id: str
    adapter_name: str
    can_run: bool
    run_mode: str = "dry-run-metadata-only"
    block_reasons: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    expected_outputs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SafeConnector:
    """Base class for all safe connector adapters.

    Sprint 3 policy:
    - network calls are disabled
    - credentials are not read or used
    - alerts are disabled
    - outputs are sanitized
    """

    source_id: str = "base"
    class_id: str = "base"
    adapter_name: str = "SafeConnector"
    requires_network: bool = False
    requires_auth: bool = False
    supports_local_files: bool = False
    supports_manual_review: bool = False
    legacy_adapter_class: Optional[Type[Any]] = None

    def __init__(self, source_record: Optional[Dict[str, Any]] = None, runtime_policy: Optional[Dict[str, Any]] = None):
        self.source_record = source_record or {}
        self.runtime_policy = runtime_policy or {}

    def describe(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "class_id": self.class_id,
            "adapter_name": self.adapter_name,
            "requires_network": self.requires_network,
            "requires_auth": self.requires_auth,
            "supports_local_files": self.supports_local_files,
            "supports_manual_review": self.supports_manual_review,
        }

    def dry_run(self) -> ConnectorDecision:
        block_reasons: List[str] = []
        notes: List[str] = []

        if self.requires_network and not self.runtime_policy.get("network_enabled", False):
            # This is not necessarily fatal for dry-run; it means no live fetch.
            notes.append("live network fetch disabled; adapter will only report metadata")

        if self.requires_auth and not self.runtime_policy.get("auth_enabled", False):
            block_reasons.append("auth_disabled")

        if self.requires_auth and not self.runtime_policy.get("credential_use_enabled", False):
            block_reasons.append("credential_use_disabled")

        can_run = not block_reasons
        return ConnectorDecision(
            source_id=self.source_record.get("source_id") or self.source_id,
            adapter_name=self.adapter_name,
            can_run=can_run,
            block_reasons=block_reasons,
            notes=notes,
            expected_outputs=[
                "sanitized connector readiness metadata",
                "no raw sensitive data",
                "no alert delivery",
            ],
        )

    def live_block_reasons(self) -> List[str]:
        reasons: List[str] = []

        if self.requires_network and not self.runtime_policy.get("network_enabled", False):
            reasons.append("network_disabled")

        if self.requires_auth and not self.runtime_policy.get("auth_enabled", False):
            reasons.append("auth_disabled")

        if self.requires_auth and not self.runtime_policy.get("credential_use_enabled", False):
            reasons.append("credential_use_disabled")

        if self.supports_manual_review and not self.runtime_policy.get("manual_review_execution_enabled", False):
            reasons.append("manual_review_only")

        return reasons

    def can_fetch_live(self) -> bool:
        return not self.live_block_reasons()

    def fetch_live(self) -> List[Dict[str, Any]]:
        if self.live_block_reasons():
            raise PermissionError("live fetch blocked by policy: " + ",".join(self.live_block_reasons()))
        if not self.legacy_adapter_class:
            raise NotImplementedError(f"{self.adapter_name} does not implement live fetch")
        adapter = self.legacy_adapter_class(self.source_record, timeout=int(self.runtime_policy.get("timeout", 30)))
        return adapter.fetch()
