# Quick script to check for parser-worker processes
Write-Host "Checking for parser-worker processes..." -ForegroundColor Cyan
Write-Host ""

$workers = Get-WmiObject Win32_Process | Where-Object {
    $_.Name -eq "node.exe" -and 
    ($_.CommandLine -like "*dist/index.js*" -or $_.CommandLine -like "*parser-worker*")
}

if ($workers) {
    Write-Host "Found $($workers.Count) potential worker process(es):" -ForegroundColor Yellow
    $workers | ForEach-Object {
        Write-Host "  PID: $($_.ProcessId) | Started: $($_.ConvertToDateTime($_.CreationDate))" -ForegroundColor Yellow
        Write-Host "  Command: $($_.CommandLine)" -ForegroundColor Gray
        Write-Host ""
    }
} else {
    Write-Host "No parser-worker processes found." -ForegroundColor Green
}

Write-Host "All Node.js processes:" -ForegroundColor Cyan
Get-Process node -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, StartTime | Format-Table -AutoSize
