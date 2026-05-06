import unittest
import json
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.asset_registry import load_asset_registry
from core.masking import mask_text, mask_value
from core.reporting import build_report, derive_status
from connectors.registry import ConnectorRegistry
from pii_radar import append_unique, update_scope_value, validate_scope_data
from run_evidence_package import create_package, safe_name
from run_asset_match_pipeline_report import extract_scan_payload
from run_paste_manual_review import extract_paste_references
from run_full_pipeline import build_steps, classify_step_status
from run_maintenance import purge_old_observations, purge_old_source_runs
from run_release_notes import git_log_range, parse_git_log, render_markdown


class ReportingTests(unittest.TestCase):
    def test_derive_status(self):
        self.assertEqual(derive_status([], []), "ok")
        self.assertEqual(derive_status([], ["warn"]), "warning")
        self.assertEqual(derive_status(["err"], []), "error")

    def test_build_report_defaults_to_sanitized_output(self):
        report = build_report("sample", summary={"count": 1})
        self.assertEqual(report["status"], "ok")
        self.assertFalse(report["raw_sensitive_output"])
        self.assertEqual(report["summary"]["count"], 1)


class PipelineTests(unittest.TestCase):
    def test_default_pipeline_excludes_live_registry_scan(self):
        ids = [step["id"] for step in build_steps()]
        self.assertIn("safe_connectors", ids)
        self.assertNotIn("source_registry", ids)

    def test_network_pipeline_includes_live_registry_scan(self):
        ids = [step["id"] for step in build_steps(with_network_feeds=True)]
        self.assertIn("source_registry", ids)

    def test_status_classifier_marks_stdout_errors_as_warning(self):
        status = classify_step_status(0, "[ERROR] cisa_kev: failed", "")
        self.assertEqual(status, "warning")

    def test_status_classifier_marks_nonzero_as_error(self):
        status = classify_step_status(1, "", "")
        self.assertEqual(status, "error")


class ConnectorPolicyTests(unittest.TestCase):
    def test_registry_build_accepts_legacy_registry_id(self):
        adapter = ConnectorRegistry.build(
            {"id": "cisa_kev", "adapter": "cisa_kev", "legal_level": "open_public_feed"},
            {"network_enabled": False},
        )
        self.assertIsNotNone(adapter)
        self.assertEqual(adapter.source_record["source_id"], "cisa_kev")
        self.assertIn("network_disabled", adapter.live_block_reasons())

    def test_paste_sources_are_manual_review_connectors(self):
        for source_id in [
            "pastebin_manual_review",
            "github_gist_manual_review",
            "rentry_manual_review",
            "ghostbin_manual_review",
            "controlc_manual_review",
        ]:
            adapter = ConnectorRegistry.build(
                {"source_id": source_id, "class_id": "paste_manual_review"},
                {"network_enabled": False, "auth_enabled": False, "credential_use_enabled": False},
            )
            self.assertIsNotNone(adapter)
            self.assertFalse(adapter.requires_network)
            self.assertTrue(adapter.supports_manual_review)

    def test_public_feed_connector_wraps_legacy_live_adapter(self):
        adapter = ConnectorRegistry.build(
            {"id": "urlhaus_recent", "adapter": "urlhaus", "legal_level": "open_public_feed"},
            {"network_enabled": True, "timeout": 1},
        )
        self.assertIsNotNone(adapter)
        self.assertTrue(adapter.can_fetch_live())
        self.assertIsNotNone(adapter.legacy_adapter_class)

    def test_auth_connector_blocks_live_fetch_without_credential_policy(self):
        adapter = ConnectorRegistry.build(
            {"id": "otx_subscribed", "adapter": "otx", "legal_level": "open_api_requires_key"},
            {"network_enabled": True, "auth_enabled": False, "credential_use_enabled": False},
        )
        self.assertIsNotNone(adapter)
        self.assertIn("auth_disabled", adapter.live_block_reasons())
        self.assertIn("credential_use_disabled", adapter.live_block_reasons())


class PasteParserTests(unittest.TestCase):
    def test_extract_paste_references_masks_and_dedups(self):
        refs = extract_paste_references(
            "See https://pastebin.com/AbCd1234 and https://pastebin.com/AbCd1234 plus "
            "https://gist.github.com/acme/abcdef1234567890"
        )
        self.assertEqual(len(refs), 2)
        self.assertEqual({ref["source"] for ref in refs}, {"pastebin", "github_gist"})
        self.assertTrue(all("url_hash" in ref for ref in refs))


class CliHelperTests(unittest.TestCase):
    def test_append_unique_is_case_insensitive(self):
        values = ["Example.com"]
        self.assertFalse(append_unique(values, "example.com"))
        self.assertTrue(append_unique(values, "other.example"))
        self.assertEqual(values, ["Example.com", "other.example"])

    def test_evidence_safe_name_removes_unsafe_chars(self):
        self.assertEqual(safe_name("CASE 2026/001"), "CASE_2026_001")
        self.assertEqual(safe_name(""), "case")

    def test_scope_update_domain_updates_org_and_code_scope(self):
        data = {}
        self.assertTrue(update_scope_value(data, "add-domain", "example.com"))
        self.assertFalse(update_scope_value(data, "add-domain", "EXAMPLE.com"))
        self.assertTrue(data["organization_scope"]["enabled"])
        self.assertTrue(data["public_code_search_scope"]["enabled"])
        self.assertEqual(data["organization_scope"]["domains"], ["example.com"])
        self.assertEqual(data["public_code_search_scope"]["allowed_domains"], ["example.com"])

    def test_scope_update_paste_source_forces_manual_review(self):
        data = {"paste_scope": {"automatic_crawling_enabled": True}}
        self.assertTrue(update_scope_value(data, "add-paste-source", "pastebin"))
        self.assertTrue(data["paste_scope"]["manual_review_enabled"])
        self.assertFalse(data["paste_scope"]["automatic_crawling_enabled"])

    def test_validate_scope_data_catches_unsafe_flags(self):
        data = {
            "global_rules": {
                "unauthorized_access_allowed": False,
                "credential_use_allowed": True,
                "bypass_allowed": False,
                "exploit_allowed": False,
                "illegal_market_transaction_allowed": False,
                "closed_group_intrusion_allowed": False,
                "raw_sensitive_output_allowed": False,
                "alerts_enabled": False,
            },
            "paste_scope": {"automatic_crawling_enabled": True},
        }
        errors = validate_scope_data(data)
        self.assertIn("credential_use_allowed", errors)
        self.assertIn("paste_scope.automatic_crawling_enabled", errors)

    def test_evidence_package_manifest_and_zip(self):
        root = Path.cwd() / "reports" / "_test_evidence_package"
        if root.exists():
            shutil.rmtree(root)
        reports = root / "reports"
        config = root / "config"
        out = root / "out"
        reports.mkdir(parents=True)
        config.mkdir(parents=True)
        (reports / "dashboard.html").write_text("<html>ok</html>", encoding="utf-8")
        (config / "scope.yml").write_text("mode: dry-run\n", encoding="utf-8")
        (root / "registry.yml").write_text("global: {}\n", encoding="utf-8")

        result = create_package(
            "CASE 2026/001",
            reports_root=reports,
            config_root=config,
            output_root=out,
            project_root=root,
        )
        self.assertTrue(result["manifest_path"].exists())
        self.assertTrue(result["zip_path"].exists())
        manifest = json.loads(result["manifest_path"].read_text(encoding="utf-8"))
        self.assertEqual(manifest["case_id"], "CASE_2026_001")
        self.assertFalse(manifest["raw_sensitive_output"])

    def test_release_notes_parse_and_render_git_log(self):
        line = "a" * 40 + "\x1fabc1234\x1f2026-05-06\x1fAdd release workflow"
        commits = parse_git_log(line)
        self.assertEqual(commits[0]["short_sha"], "abc1234")
        self.assertEqual(git_log_range("v1.0.0"), "v1.0.0..HEAD")
        rendered = render_markdown(commits, "v1.0.0")
        self.assertIn("`abc1234`", rendered)
        self.assertIn("Add release workflow", rendered)


class AssetMatchReportTests(unittest.TestCase):
    def test_extract_scan_payload_prefers_hits(self):
        payload = {"report_schema": {"data": {"legacy_hits": [{"a": 1}]}}, "hits": [{"b": 2}]}
        self.assertEqual(extract_scan_payload(payload), [{"b": 2}])

    def test_extract_scan_payload_reads_legacy_events(self):
        payload = {"report_schema": {"data": {"legacy_events": [{"event": "x"}]}}}
        self.assertEqual(extract_scan_payload(payload), [{"event": "x"}])


class MaskingAndAssetTests(unittest.TestCase):
    def test_masking_removes_raw_email_and_token(self):
        text = "sample.person@example.com token abcdefghijklmnopqrstuvwxyz123456"
        masked = mask_text(text)
        self.assertNotIn("sample.person@example.com", masked)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz123456", masked)
        self.assertIn("s****@example.com", masked)

    def test_mask_value_domain_and_url(self):
        self.assertEqual(mask_value("login.example.net", "domain"), "*.example.net")
        self.assertEqual(mask_value("https://login.example.net/path", "url"), "https://*.example.net/***")

    def test_sample_asset_registry_loads(self):
        registry = load_asset_registry("assets/assets.sample.json")
        summary = registry.summary()
        self.assertEqual(summary["asset_count"], 4)
        self.assertGreaterEqual(summary["match_value_count"], 20)


class RetentionTests(unittest.TestCase):
    def test_retention_cleanup_deletes_only_old_rows(self):
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE observations (id INTEGER PRIMARY KEY, last_seen TEXT)")
        conn.execute("CREATE TABLE source_runs (id INTEGER PRIMARY KEY, checked_at TEXT)")
        old = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        recent = datetime.now(timezone.utc).isoformat()
        conn.execute("INSERT INTO observations (last_seen) VALUES (?)", (old,))
        conn.execute("INSERT INTO observations (last_seen) VALUES (?)", (recent,))
        conn.execute("INSERT INTO source_runs (checked_at) VALUES (?)", (old,))
        conn.execute("INSERT INTO source_runs (checked_at) VALUES (?)", (recent,))

        self.assertEqual(purge_old_observations(conn, 1), 1)
        self.assertEqual(purge_old_source_runs(conn, 1), 1)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0], 1)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM source_runs").fetchone()[0], 1)
        conn.close()


if __name__ == "__main__":
    unittest.main()
