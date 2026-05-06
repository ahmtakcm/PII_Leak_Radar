param(
    [switch]$IncludeData,
    [switch]$IncludeReports
)

$ErrorActionPreference = "Stop"

$Project = Split-Path -Parent $MyInvocation.MyCommand.Path
$Desktop = [Environment]::GetFolderPath("Desktop")
$PackageRoot = Join-Path $Desktop "PII_Leak_Radar_Packages"
$Stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$TempRoot = Join-Path $env:TEMP "PII_Leak_Radar_package_$Stamp"
$DestZip = Join-Path $PackageRoot "PII_Leak_Radar_CLEAN_SPRINT1_$Stamp.zip"

New-Item -ItemType Directory -Force -Path $PackageRoot | Out-Null
New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null

Write-Host "=== PII Leak Radar | Clean Package ===" -ForegroundColor Cyan

Set-Location $Project
py .\run_health_check.py

$Health = Get-Content ".\reports\health_check.json" -Raw | ConvertFrom-Json

if ($Health.secret_findings.Count -gt 0) {
    Write-Host "[DURDU] Secret/token benzeri bulgu var. Paket oluşturulmadı." -ForegroundColor Red
    Write-Host "Rapor: $Project\reports\health_check.html"
    exit 2
}

$ExcludeDirs = @(
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    "manual_sources_inbox",
    "exports_inbox"
)

if (-not $IncludeData) {
    $ExcludeDirs += "data"
    $ExcludeDirs += "logs"
}

if (-not $IncludeReports) {
    $ExcludeDirs += "reports"
}

$ExcludeFiles = @(
    "*.pyc",
    "*.pyo",
    "*.log",
    ".env",
    ".env.*",
    "token.txt",
    "secrets.txt"
)

Write-Host "[1] Temiz kopya hazırlanıyor..."

Get-ChildItem $Project -Force | ForEach-Object {
    $Name = $_.Name

    if ($ExcludeDirs -contains $Name) {
        Write-Host "[SKIP DIR] $Name"
        return
    }

    $Target = Join-Path $TempRoot $Name

    if ($_.PSIsContainer) {
        Copy-Item $_.FullName $Target -Recurse -Force
    } else {
        Copy-Item $_.FullName $Target -Force
    }
}

Write-Host "[2] Exclude dosyalar temizleniyor..."

foreach ($Pattern in $ExcludeFiles) {
    Get-ChildItem $TempRoot -Recurse -Force -File -Filter $Pattern -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}

Get-ChildItem $TempRoot -Recurse -Force -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "[3] Paket manifesti yazılıyor..."

$Manifest = @{
    name = "PII_Leak_Radar_CLEAN_SPRINT1"
    generated_at = (Get-Date).ToString("s")
    include_data = [bool]$IncludeData
    include_reports = [bool]$IncludeReports
    legal_note = "Savunma/OSINT/adli bilişim amaçlı temiz proje paketi. Token/secret, inbox exportları, manuel delil dosyaları varsayılan olarak dahil edilmez."
}

$Manifest | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 (Join-Path $TempRoot "PACKAGE_MANIFEST.json")

Write-Host "[4] ZIP oluşturuluyor..."

if (Test-Path $DestZip) {
    Remove-Item $DestZip -Force
}

Compress-Archive -Path "$TempRoot\*" -DestinationPath $DestZip -Force

Remove-Item $TempRoot -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "[OK] Paket oluşturuldu:" -ForegroundColor Green
Write-Host $DestZip
