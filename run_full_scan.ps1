param(
    [switch]$OpenReports,
    [switch]$WithNetworkFeeds
)

$ErrorActionPreference = "Stop"

$Project = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Project

Write-Host "=== PII Leak Radar | Full Scan ===" -ForegroundColor Cyan

if ($WithNetworkFeeds) {
    py .\run_full_pipeline.py --with-network-feeds
} else {
    py .\run_full_pipeline.py
}

if ($OpenReports) {
    Start-Process ".\reports\full_pipeline_report.html"
    Start-Process ".\reports\dashboard.html"
    Start-Process ".\reports\source_catalog.html"
}

# === Sprint 2 Asset Scope & Match Engine Health Check START ===
Write-Host ""
Write-Host "Sprint 2 Asset Scope & Match Engine health check çalışıyor..." -ForegroundColor Cyan

$sprint2Health = Join-Path $PSScriptRoot "run_sprint2_health_check.py"

if (Test-Path $sprint2Health) {
  python $sprint2Health
  if ($LASTEXITCODE -ne 0) {
    Write-Host "Sprint 2 health check başarısız. Ana scan akışı durdurulmadı, ancak kontrol edilmeli." -ForegroundColor Yellow
  } else {
    Write-Host "Sprint 2 health check başarılı." -ForegroundColor Green
  }
} else {
  Write-Host "run_sprint2_health_check.py bulunamadı. Sprint 2 kontrolü atlandı." -ForegroundColor Yellow
}
# === Sprint 2 Asset Scope & Match Engine Health Check END ===

# === Sprint 2.1 Pipeline Asset Match START ===
Write-Host ""
Write-Host "Sprint 2.1 Pipeline Asset Match raporları oluşturuluyor..." -ForegroundColor Cyan

$assetMatchRunner = Join-Path $PSScriptRoot "run_asset_match_pipeline_report.py"
$assetMatchCombiner = Join-Path $PSScriptRoot "run_asset_match_combine_reports.py"

if (Test-Path $assetMatchRunner) {
  python $assetMatchRunner --report (Join-Path $PSScriptRoot "reports\export_parse_results.json") --label "export_parse" --out (Join-Path $PSScriptRoot "reports\asset_match_export_parse.json") --html (Join-Path $PSScriptRoot "reports\asset_match_export_parse.html")
  python $assetMatchRunner --report (Join-Path $PSScriptRoot "reports\manual_import_results.json") --label "manual_import" --out (Join-Path $PSScriptRoot "reports\asset_match_manual_import.json") --html (Join-Path $PSScriptRoot "reports\asset_match_manual_import.html")
  python $assetMatchRunner --report (Join-Path $PSScriptRoot "reports\source_registry_dry_run.json") --label "source_registry" --out (Join-Path $PSScriptRoot "reports\asset_match_source_registry.json") --html (Join-Path $PSScriptRoot "reports\asset_match_source_registry.html")
} else {
  Write-Host "run_asset_match_pipeline_report.py bulunamadı. Asset match raporları atlandı." -ForegroundColor Yellow
}

if (Test-Path $assetMatchCombiner) {
  python $assetMatchCombiner
} else {
  Write-Host "run_asset_match_combine_reports.py bulunamadı. Birleşik asset match raporu atlandı." -ForegroundColor Yellow
}

Write-Host "Sprint 2.1 Pipeline Asset Match bloğu tamamlandı." -ForegroundColor Green
# === Sprint 2.1 Pipeline Asset Match END ===

# === Sprint 2.2 Dashboard Asset Match Card START ===
Write-Host ""
Write-Host "Sprint 2.2 Dashboard Asset Match kartı güncelleniyor..." -ForegroundColor Cyan

$dashboardAssetCard = Join-Path $PSScriptRoot "run_dashboard_asset_match_card.py"

if (Test-Path $dashboardAssetCard) {
  python $dashboardAssetCard
  if ($LASTEXITCODE -ne 0) {
    Write-Host "Dashboard Asset Match kartı güncellenemedi. Ana pipeline durdurulmadı." -ForegroundColor Yellow
  } else {
    Write-Host "Dashboard Asset Match kartı güncellendi." -ForegroundColor Green
  }
} else {
  Write-Host "run_dashboard_asset_match_card.py bulunamadı. Dashboard kartı atlandı." -ForegroundColor Yellow
}
# === Sprint 2.2 Dashboard Asset Match Card END ===
