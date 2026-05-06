$base = Split-Path -Parent $PSScriptRoot

Set-Location $base

Write-Host "=== PII Leak Radar Tam Tarama ===" -ForegroundColor Cyan

Write-Host "`n[1/3] Kaynak kaydı kontrol ediliyor..." -ForegroundColor Yellow
python .\tools\source_manager.py init

Write-Host "`n[2/3] PII/risk analizi çalışıyor..." -ForegroundColor Yellow
python .\tools\analyze_pii_leak.py

Write-Host "`n[3/3] Genel test araması çalışıyor..." -ForegroundColor Yellow
python .\tools\search_content.py --q "sorgu" --out-prefix "quick_search"

Write-Host "`nTamamlandı." -ForegroundColor Green
Write-Host "Raporlar: $base\reports"
Write-Host "Çıktılar: $base\output"
