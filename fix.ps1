# Debug script to check what's happening with the security assessment

Write-Host "=== DEBUG: Security Assessment Loading ===" -ForegroundColor Cyan

# Check if global variables exist
Write-Host "`nChecking Global Variables:" -ForegroundColor Yellow
Write-Host "- Global:Config exists: $($null -ne $Global:Config)" -ForegroundColor White
Write-Host "- Global:OutputPath: $Global:OutputPath" -ForegroundColor White
Write-Host "- Global:LogFile: $Global:LogFile" -ForegroundColor White

# Check if output directory exists
if ($Global:OutputPath) {
    Write-Host "- Output directory exists: $(Test-Path $Global:OutputPath)" -ForegroundColor White
} else {
    Write-Host "- Output directory not set!" -ForegroundColor Red
}

# Try to manually load the core script
Write-Host "`nManually loading core script..." -ForegroundColor Yellow
$CoreScript = "C:\Scripts\00-AD-Assessment-Core.ps1"
if (Test-Path $CoreScript) {
    Write-Host "Core script found at: $CoreScript" -ForegroundColor Green
    
    # Load it with explicit output path
    . $CoreScript -OutputPath "C:\AD_Assessment"
    
    Write-Host "`nAfter loading core script:" -ForegroundColor Yellow
    Write-Host "- Global:OutputPath: $Global:OutputPath" -ForegroundColor White
    Write-Host "- Output directory exists: $(Test-Path $Global:OutputPath)" -ForegroundColor White
} else {
    Write-Host "Core script NOT found!" -ForegroundColor Red
}

Write-Host "`n=== END DEBUG ===" -ForegroundColor Cyan
