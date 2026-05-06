import hashlib
import html
import json
import re
import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
DB_PATH = ROOT / "data" / "pii_radar.db"

REAL_SECRET_PATTERNS = {
    "github_classic_pat": re.compile(r"ghp_[A-Za-z0-9_]{20,}"),
    "github_fine_grained_pat": re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
}

GENERIC_SECRET_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|authorization)\b\s*[:=]\s*['\"]?[^'\"\s,;]+"
)

TEXT_EXTENSIONS = {
    ".py", ".ps1", ".txt", ".md", ".yml", ".yaml", ".json", ".csv", ".html", ".htm", ".log"
}

EXCLUDE_DIRS = {
    ".git", "__pycache__", ".venv", "venv", "node_modules"
}

REQUIRED_FILES = [
    "registry.yml",
    "requirements.txt",
    "run_registry_dry_scan.py",
    "run_export_parse.py",
    "run_manual_import.py",
    "run_source_catalog_review.py",
    "run_dashboard_refresh.py",
    "run_full_pipeline.py",
    "run_full_scan.ps1",
    "core/dedup_store.py",
    "core/dashboard.py",
    "core/sanitizer.py",
    "adapters/cisa_kev_adapter.py",
    "adapters/nvd_adapter.py",
    "adapters/urlhaus_adapter.py",
    "adapters/otx_adapter.py",
    "adapters/github_code_search_adapter.py",
]

EXPECTED_REPORTS = [
    "reports/dashboard.html",
    "reports/source_catalog.html",
    "reports/export_parse_report.html",
    "reports/manual_import_report.html",
    "reports/full_pipeline_report.html",
]

BENIGN_ENV_NAMES = {
    "GITHUB_TOKEN",
    "OTX_API_KEY",
    "BOT_TOKEN",
    "CHAT_ID",
    "BRIDGE_SECRET",
}

BENIGN_GENERIC_CONTEXTS = [
    "env_api_key",
    "os.environ.get",
    "self.get(\"env_api_key\"",
    "self.get('env_api_key'",
    "\"env_api_key\"",
    "'env_api_key'",
    "query_templates",
    "\"api_key\"",
    "'api_key'",
    "\"token\"",
    "'token'",
    "\"password\"",
    "'password'",
    "\"secret\"",
    "'secret'",
    "credential",
    "recommended_action",
    "legal_notice",
    "never_use_credentials",
    "source_registry_dry_run.json",
]


def main():
    REPORTS.mkdir(parents=True, exist_ok=True)

    result = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "project": str(ROOT),
        "status": "ok",
        "checks": [],
        "summary": {},
        "file_inventory": [],
        "secret_findings": [],
        "ignored_secret_findings": [],
        "db": {},
    }

    check_required_files(result)
    build_file_inventory(result)
    scan_for_secrets(result)
    inspect_db(result)
    check_reports(result)
    summarize(result)

    if any(c["status"] == "error" for c in result["checks"]):
        result["status"] = "error"
    elif any(c["status"] == "warning" for c in result["checks"]) or result["secret_findings"]:
        result["status"] = "warning"
    else:
        result["status"] = "ok"

    json_path = REPORTS / "health_check.json"
    html_path = REPORTS / "health_check.html"

    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    write_html(result, html_path)

    inventory_path = REPORTS / "file_inventory.json"
    inventory_path.write_text(json.dumps(result["file_inventory"], ensure_ascii=False, indent=2), encoding="utf-8")

    print("=== PII Leak Radar | Health Check ===")
    print(f"Durum: {result['status']}")
    print(f"Dosya sayısı: {result['summary'].get('file_count')}")
    print(f"Toplam boyut: {result['summary'].get('total_size_bytes')} bytes")
    print(f"Secret finding: {len(result['secret_findings'])}")
    print(f"Ignored finding: {len(result['ignored_secret_findings'])}")
    print(f"DB observations: {result['db'].get('observations')}")
    print(f"DB source_runs: {result['db'].get('source_runs')}")
    print(f"HTML: {html_path}")
    print(f"JSON: {json_path}")

    if result["secret_findings"]:
        print("")
        print("[UYARI] Proje dosyalarında gerçek token/secret benzeri iz bulundu. Paketlemeden önce health_check.html raporunu incele.")
        print("Not: Bulgularda değer gösterilmez; sadece dosya/satır/pattern gösterilir.")


def add_check(result, name, status, detail):
    result["checks"].append({
        "name": name,
        "status": status,
        "detail": detail,
    })


def check_required_files(result):
    missing = []

    for rel in REQUIRED_FILES:
        if not (ROOT / rel).exists():
            missing.append(rel)

    if missing:
        add_check(result, "required_files", "error", f"Eksik dosyalar: {', '.join(missing)}")
    else:
        add_check(result, "required_files", "ok", "Zorunlu dosyalar mevcut.")


def build_file_inventory(result):
    files = []

    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue

        rel = path.relative_to(ROOT).as_posix()
        parts = set(path.parts)

        if parts & EXCLUDE_DIRS:
            continue

        try:
            size = path.stat().st_size
            sha256 = file_sha256(path) if size <= 5_000_000 else ""
            files.append({
                "path": rel,
                "suffix": path.suffix.lower(),
                "size_bytes": size,
                "sha256": sha256,
                "modified": datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds"),
            })
        except Exception as exc:
            files.append({
                "path": rel,
                "error": f"{type(exc).__name__}: {exc}",
            })

    result["file_inventory"] = sorted(files, key=lambda x: x.get("path", ""))


def scan_for_secrets(result):
    findings = []
    ignored = []

    for item in result["file_inventory"]:
        rel = item.get("path", "")
        path = ROOT / rel

        if path.suffix.lower() not in TEXT_EXTENSIONS:
            continue

        if rel.startswith("reports/health_check") or rel.startswith("reports/file_inventory"):
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        for idx, line in enumerate(text.splitlines(), start=1):
            # Gerçek token patternleri asla ignore edilmez.
            for name, pattern in REAL_SECRET_PATTERNS.items():
                if pattern.search(line):
                    findings.append({
                        "path": rel,
                        "line": idx,
                        "pattern": name,
                        "note": "Değer rapora yazılmadı; dosyayı manuel kontrol et.",
                    })

            # Generic pattern sadece gerçek assignment gibi görünüyorsa uyarı üretir.
            if GENERIC_SECRET_PATTERN.search(line):
                if is_benign_generic_secret_line(rel, line):
                    ignored.append({
                        "path": rel,
                        "line": idx,
                        "pattern": "generic_api_key_assignment",
                        "reason": "Env var adı / query template / açıklama metni olarak değerlendirildi.",
                    })
                else:
                    findings.append({
                        "path": rel,
                        "line": idx,
                        "pattern": "generic_api_key_assignment",
                        "note": "Değer rapora yazılmadı; dosyayı manuel kontrol et.",
                    })

    result["secret_findings"] = findings
    result["ignored_secret_findings"] = ignored

    if findings:
        add_check(result, "secret_scan", "warning", f"{len(findings)} gerçek token/secret benzeri iz bulundu.")
    else:
        add_check(
            result,
            "secret_scan",
            "ok",
            f"Gerçek token/secret pattern bulunmadı. Ignore edilen false-positive: {len(ignored)}",
        )


def is_benign_generic_secret_line(rel, line):
    low = line.lower()
    stripped = line.strip()

    # Raporlarda GitHub query içinde api_key/token/password kelimesi geçebilir; gerçek secret değil.
    if rel.startswith("reports/") and any(x in low for x in ("\"api_key\"", "\"token\"", "\"password\"", "\"secret\"")):
        return True

    # Kod içinde env var adı veya config key’i.
    if any(name in line for name in BENIGN_ENV_NAMES):
        return True

    if any(ctx.lower() in low for ctx in BENIGN_GENERIC_CONTEXTS):
        return True

    # Sadece örnek/şablon placeholder.
    if any(x in stripped for x in ("BURAYA_", "ORNEK_", "example", "demo", "***MASKED***")):
        return True

    # Yaml/env key adı ama değer sadece büyük harfli env var ismi.
    if re.search(r'(?i)env_api_key\s*:\s*["\']?[A-Z0-9_]+["\']?', stripped):
        return True

    return False


def inspect_db(result):
    if not DB_PATH.exists():
        result["db"] = {"exists": False}
        add_check(result, "database", "warning", "SQLite DB bulunamadı.")
        return

    db_info = {"exists": True}

    try:
        conn = sqlite3.connect(str(DB_PATH))
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM observations")
        db_info["observations"] = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM source_runs")
        db_info["source_runs"] = cur.fetchone()[0]

        cur.execute("SELECT source_id, COUNT(*) FROM observations GROUP BY source_id ORDER BY source_id")
        db_info["observations_by_source"] = dict(cur.fetchall())

        cur.execute("SELECT risk_label, COUNT(*) FROM observations GROUP BY risk_label ORDER BY risk_label")
        db_info["observations_by_risk"] = dict(cur.fetchall())

        conn.close()

        add_check(result, "database", "ok", "SQLite DB okunabildi.")

    except Exception as exc:
        db_info["error"] = f"{type(exc).__name__}: {exc}"
        add_check(result, "database", "error", db_info["error"])

    result["db"] = db_info


def check_reports(result):
    missing = []

    for rel in EXPECTED_REPORTS:
        if not (ROOT / rel).exists():
            missing.append(rel)

    if missing:
        add_check(result, "reports", "warning", f"Eksik raporlar: {', '.join(missing)}")
    else:
        add_check(result, "reports", "ok", "Beklenen HTML raporlar mevcut.")


def summarize(result):
    file_count = len(result["file_inventory"])
    total_size = sum(int(x.get("size_bytes", 0) or 0) for x in result["file_inventory"])
    suffix_counts = Counter(x.get("suffix", "") for x in result["file_inventory"])

    result["summary"] = {
        "file_count": file_count,
        "total_size_bytes": total_size,
        "suffix_counts": dict(suffix_counts),
    }


def file_sha256(path):
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 512), b""):
            h.update(chunk)

    return h.hexdigest()


def write_html(result, path):
    check_rows = []
    for c in result["checks"]:
        check_rows.append(
            "<tr>"
            f"<td>{html.escape(str(c.get('name', '')))}</td>"
            f"<td><span class='status {html.escape(str(c.get('status', '')))}'>{html.escape(str(c.get('status', '')))}</span></td>"
            f"<td>{html.escape(str(c.get('detail', '')))}</td>"
            "</tr>"
        )

    secret_rows = []
    for f in result["secret_findings"]:
        secret_rows.append(
            "<tr>"
            f"<td>{html.escape(str(f.get('path', '')))}</td>"
            f"<td>{html.escape(str(f.get('line', '')))}</td>"
            f"<td>{html.escape(str(f.get('pattern', '')))}</td>"
            f"<td>{html.escape(str(f.get('note', '')))}</td>"
            "</tr>"
        )

    ignored_rows = []
    for f in result["ignored_secret_findings"]:
        ignored_rows.append(
            "<tr>"
            f"<td>{html.escape(str(f.get('path', '')))}</td>"
            f"<td>{html.escape(str(f.get('line', '')))}</td>"
            f"<td>{html.escape(str(f.get('pattern', '')))}</td>"
            f"<td>{html.escape(str(f.get('reason', '')))}</td>"
            "</tr>"
        )

    db_source_rows = []
    for source, count in (result["db"].get("observations_by_source") or {}).items():
        db_source_rows.append(f"<li><b>{html.escape(str(source))}</b>: {html.escape(str(count))}</li>")

    inventory_rows = []
    for item in result["file_inventory"]:
        inventory_rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('path', '')))}</td>"
            f"<td>{html.escape(str(item.get('suffix', '')))}</td>"
            f"<td>{html.escape(str(item.get('size_bytes', '')))}</td>"
            f"<td>{html.escape(str(item.get('modified', '')))}</td>"
            "</tr>"
        )

    content = f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>PII Leak Radar - Health Check</title>
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 24px;
    background: #111827;
    color: #e5e7eb;
}}
.card {{
    background: #1f2937;
    border: 1px solid #374151;
    border-radius: 14px;
    padding: 18px;
    margin-bottom: 18px;
}}
.table-wrap {{
    overflow-x: auto;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    background: #0f172a;
}}
th, td {{
    border-bottom: 1px solid #374151;
    padding: 8px;
    text-align: left;
    vertical-align: top;
    font-size: 13px;
}}
th {{
    background: #111827;
    color: #93c5fd;
}}
.status {{
    display: inline-block;
    padding: 4px 8px;
    border-radius: 999px;
    background: #374151;
    font-weight: 700;
}}
.status.ok {{ background: #064e3b; color: #bbf7d0; }}
.status.warning {{ background: #78350f; color: #fde68a; }}
.status.error {{ background: #7f1d1d; color: #fecaca; }}
.note {{
    color: #fbbf24;
}}
</style>
</head>
<body>
<div class="card">
<h1>PII Leak Radar - Health Check</h1>
<p><b>Durum:</b> <span class="status {html.escape(str(result.get('status', '')))}">{html.escape(str(result.get('status', '')))}</span></p>
<p><b>Üretim zamanı:</b> {html.escape(str(result.get('generated_at', '')))}</p>
<p><b>Dosya sayısı:</b> {html.escape(str(result['summary'].get('file_count', '')))}</p>
<p><b>Toplam boyut:</b> {html.escape(str(result['summary'].get('total_size_bytes', '')))} bytes</p>
<p class="note">Yasal not: Health check yalnızca proje dosyalarını, raporları ve DB özetini kontrol eder. Yetkisiz erişim veya aktif kaynak işlemi yapmaz.</p>
</div>

<div class="card">
<h2>Kontroller</h2>
<table>
<thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
<tbody>{''.join(check_rows)}</tbody>
</table>
</div>

<div class="card">
<h2>Secret Scan Bulguları</h2>
<table>
<thead><tr><th>Path</th><th>Line</th><th>Pattern</th><th>Note</th></tr></thead>
<tbody>{''.join(secret_rows) if secret_rows else '<tr><td colspan="4">Gerçek token/secret bulgusu yok.</td></tr>'}</tbody>
</table>
</div>

<div class="card">
<h2>Ignore Edilen False-Positive Bulgular</h2>
<table>
<thead><tr><th>Path</th><th>Line</th><th>Pattern</th><th>Reason</th></tr></thead>
<tbody>{''.join(ignored_rows) if ignored_rows else '<tr><td colspan="4">Ignore edilen bulgu yok.</td></tr>'}</tbody>
</table>
</div>

<div class="card">
<h2>SQLite DB Özeti</h2>
<p><b>Observations:</b> {html.escape(str(result['db'].get('observations', '')))}</p>
<p><b>Source Runs:</b> {html.escape(str(result['db'].get('source_runs', '')))}</p>
<ul>{''.join(db_source_rows)}</ul>
</div>

<div class="card">
<h2>Dosya Envanteri</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Path</th><th>Suffix</th><th>Size</th><th>Modified</th></tr></thead>
<tbody>{''.join(inventory_rows)}</tbody>
</table>
</div>
</div>
</body>
</html>
"""
    path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
