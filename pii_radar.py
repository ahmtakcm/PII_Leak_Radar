import argparse
import compileall
import py_compile
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SCOPE_PATH = ROOT / "config" / "scope.yml"


COMMANDS = {
    "health": [sys.executable, str(ROOT / "run_health_check.py")],
    "pipeline": [sys.executable, str(ROOT / "run_full_pipeline.py")],
    "policy": [sys.executable, str(ROOT / "run_source_registry_policy_validate.py")],
    "connectors": [sys.executable, str(ROOT / "run_safe_connectors_dry_run.py")],
    "assets": [sys.executable, str(ROOT / "run_asset_scope_validate.py")],
    "registry": [sys.executable, str(ROOT / "run_registry_dry_scan.py")],
    "maintenance": [sys.executable, str(ROOT / "run_maintenance.py")],
    "evidence": [sys.executable, str(ROOT / "run_evidence_package.py")],
}


VERIFY_COMMAND_STEPS = [
    [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
    [sys.executable, str(ROOT / "pii_radar.py"), "health"],
    [sys.executable, str(ROOT / "pii_radar.py"), "policy"],
    [sys.executable, str(ROOT / "pii_radar.py"), "connectors"],
    [sys.executable, str(ROOT / "pii_radar.py"), "pipeline"],
]

COMPILE_DIRS = [
    "adapters",
    "connectors",
    "core",
    "parsers",
    "tests",
    "tools",
]


def parse_args():
    parser = argparse.ArgumentParser(description="PII Leak Radar command line")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("health", help="Run project health check")
    sub.add_parser("verify", help="Run compile, tests, health, policy, connectors, and offline pipeline")

    pipeline = sub.add_parser("pipeline", help="Run full offline-safe pipeline")
    pipeline.add_argument("--with-network-feeds", action="store_true", help="Include live public feed scan")

    sub.add_parser("policy", help="Validate source registry policy")
    sub.add_parser("connectors", help="Run safe connector dry-run")
    sub.add_parser("assets", help="Validate active asset registry")

    registry = sub.add_parser("registry", help="Run source registry scan")
    registry.add_argument("--with-network", action="store_true", help="Enable live public feed fetches")

    maintenance = sub.add_parser("maintenance", help="Run maintenance and retention tasks")
    maintenance.add_argument("--purge-github-test", action="store_true")
    maintenance.add_argument("--purge-test-export", action="store_true")
    maintenance.add_argument("--keep-observations-days", type=int, default=None)
    maintenance.add_argument("--keep-source-runs-days", type=int, default=None)
    maintenance.add_argument("--vacuum", action="store_true")

    scope = sub.add_parser("scope", help="Manage config/scope.yml")
    scope_sub = scope.add_subparsers(dest="scope_command", required=True)
    scope_sub.add_parser("show", help="Print scope summary")
    scope_sub.add_parser("validate", help="Validate scope safety gates")
    add_domain = scope_sub.add_parser("add-domain", help="Add organization domain")
    add_domain.add_argument("value")
    add_keyword = scope_sub.add_parser("add-keyword", help="Add organization keyword")
    add_keyword.add_argument("value")
    add_name = scope_sub.add_parser("add-name", help="Add organization name")
    add_name.add_argument("value")
    add_paste = scope_sub.add_parser("add-paste-source", help="Add allowed paste source name")
    add_paste.add_argument("value")

    evidence = sub.add_parser("evidence", help="Create sanitized evidence package")
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)
    package = evidence_sub.add_parser("package", help="Package sanitized reports and config snapshots")
    package.add_argument("--case", required=True)

    return parser.parse_args()


def run_command(command):
    proc = subprocess.run(command, cwd=str(ROOT))
    return proc.returncode


def run_verify():
    print("PII_RADAR_VERIFY")
    print("[VERIFY:1] targeted_compile")
    if not compile_project():
        print("[VERIFY_FAIL] step=1 returncode=1")
        return 1

    for idx, command in enumerate(VERIFY_COMMAND_STEPS, start=2):
        print(f"[VERIFY:{idx}] {' '.join(command)}")
        code = run_command(command)
        if code != 0:
            print(f"[VERIFY_FAIL] step={idx} returncode={code}")
            return code
    print("[VERIFY_OK]")
    return 0


def compile_project():
    ok = True
    for rel in COMPILE_DIRS:
        path = ROOT / rel
        if path.exists():
            ok = compileall.compile_dir(str(path), quiet=1, maxlevels=10) and ok

    for path in ROOT.glob("*.py"):
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as exc:
            ok = False
            print(str(exc))

    return ok


def load_scope(scope_path=SCOPE_PATH):
    try:
        import yaml  # type: ignore
    except ModuleNotFoundError:
        raise SystemExit("PyYAML is required for scope management. Run: py -m pip install -r requirements.txt")

    scope_path = Path(scope_path)
    if not scope_path.exists():
        raise SystemExit(f"Scope file not found: {scope_path}")
    data = yaml.safe_load(scope_path.read_text(encoding="utf-8-sig")) or {}
    return data, yaml


def save_scope(data, yaml, scope_path=SCOPE_PATH):
    Path(scope_path).write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def ensure_path(data, *keys):
    cur = data
    for key in keys:
        if key not in cur or cur[key] is None:
            cur[key] = {}
        cur = cur[key]
    return cur


def append_unique(values, value):
    text = str(value).strip()
    if not text:
        return False
    existing = {str(v).casefold() for v in values}
    if text.casefold() in existing:
        return False
    values.append(text)
    return True


def validate_scope_data(data):
    rules = data.get("global_rules", {}) or {}
    errors = []
    for key in [
        "unauthorized_access_allowed",
        "credential_use_allowed",
        "bypass_allowed",
        "exploit_allowed",
        "illegal_market_transaction_allowed",
        "closed_group_intrusion_allowed",
        "raw_sensitive_output_allowed",
        "alerts_enabled",
    ]:
        if rules.get(key) is not False:
            errors.append(key)
    paste = data.get("paste_scope", {}) or {}
    if paste.get("automatic_crawling_enabled") is not False:
        errors.append("paste_scope.automatic_crawling_enabled")
    return errors


def update_scope_value(data, scope_command, value):
    org = ensure_path(data, "organization_scope")
    code = ensure_path(data, "public_code_search_scope")
    paste = ensure_path(data, "paste_scope")

    if scope_command == "add-domain":
        org.setdefault("domains", [])
        code.setdefault("allowed_domains", [])
        changed = append_unique(org["domains"], value)
        append_unique(code["allowed_domains"], value)
        org["enabled"] = True
        code["enabled"] = True
        return changed

    if scope_command == "add-keyword":
        org.setdefault("keywords", [])
        code.setdefault("allowed_keywords", [])
        changed = append_unique(org["keywords"], value)
        append_unique(code["allowed_keywords"], value)
        org["enabled"] = True
        code["enabled"] = True
        return changed

    if scope_command == "add-name":
        org.setdefault("names", [])
        changed = append_unique(org["names"], value)
        org["enabled"] = True
        return changed

    if scope_command == "add-paste-source":
        paste.setdefault("allowed_sources", [])
        changed = append_unique(paste["allowed_sources"], value)
        paste["manual_review_enabled"] = True
        paste["automatic_crawling_enabled"] = False
        return changed

    raise ValueError(f"Unsupported scope command: {scope_command}")


def run_scope(args):
    data, yaml = load_scope()

    if args.scope_command == "show":
        org = data.get("organization_scope", {}) or {}
        code = data.get("public_code_search_scope", {}) or {}
        paste = data.get("paste_scope", {}) or {}
        print("SCOPE_SUMMARY")
        print(f"organization_enabled={org.get('enabled')}")
        print(f"organization_names={len(org.get('names') or [])}")
        print(f"organization_domains={len(org.get('domains') or [])}")
        print(f"organization_keywords={len(org.get('keywords') or [])}")
        print(f"public_code_search_enabled={code.get('enabled')}")
        print(f"public_code_allowed_domains={len(code.get('allowed_domains') or [])}")
        print(f"public_code_allowed_keywords={len(code.get('allowed_keywords') or [])}")
        print(f"paste_manual_review_enabled={paste.get('manual_review_enabled')}")
        print(f"paste_allowed_sources={len(paste.get('allowed_sources') or [])}")
        return 0

    if args.scope_command == "validate":
        errors = validate_scope_data(data)
        print("SCOPE_VALIDATE")
        print(f"status={'fail' if errors else 'ok'}")
        print(f"error_count={len(errors)}")
        for err in errors:
            print(f"error={err}")
        return 1 if errors else 0

    if args.scope_command in {"add-domain", "add-keyword", "add-name", "add-paste-source"}:
        changed = update_scope_value(data, args.scope_command, args.value)
        save_scope(data, yaml)
        label = args.scope_command.replace("add-", "").replace("-", "_")
        print(f"scope_{label}_added={changed}")
        return 0

    raise SystemExit(f"Unsupported scope command: {args.scope_command}")


def main():
    args = parse_args()

    if args.command == "verify":
        return run_verify()
    if args.command == "scope":
        return run_scope(args)

    command = list(COMMANDS[args.command])

    if args.command == "pipeline" and args.with_network_feeds:
        command.append("--with-network-feeds")
    elif args.command == "registry" and args.with_network:
        command.append("--with-network")
    elif args.command == "maintenance":
        if args.purge_github_test:
            command.append("--purge-github-test")
        if args.purge_test_export:
            command.append("--purge-test-export")
        if args.keep_observations_days is not None:
            command.extend(["--keep-observations-days", str(args.keep_observations_days)])
        if args.keep_source_runs_days is not None:
            command.extend(["--keep-source-runs-days", str(args.keep_source_runs_days)])
        if args.vacuum:
            command.append("--vacuum")
    elif args.command == "evidence":
        if args.evidence_command == "package":
            command.extend(["--case", args.case])

    return run_command(command)


if __name__ == "__main__":
    raise SystemExit(main())
