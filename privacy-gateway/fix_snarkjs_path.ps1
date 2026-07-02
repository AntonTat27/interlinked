# =============================================================================
# fix_snarkjs_path.ps1
# Run this once to diagnose and fix snarkjs not found on Windows.
# =============================================================================

Write-Host ""
Write-Host "--- Diagnosing snarkjs install ---"
Write-Host ""

# Where npm puts global binaries
$raw = & npm config get prefix 2>&1
$npmGlobalPrefix = ($raw | Where-Object { $_ -notmatch '^npm (warn|error|notice)' } | Select-Object -First 1).Trim()
$npmGlobalBin    = Join-Path $npmGlobalPrefix ""

Write-Host "npm global prefix : $npmGlobalPrefix"
Write-Host ""

# Check if snarkjs.cmd exists there
$snarkjsCmd = Join-Path $npmGlobalPrefix "snarkjs.cmd"
if (Test-Path $snarkjsCmd) {
    Write-Host "OK  snarkjs.cmd found at: $snarkjsCmd"
} else {
    Write-Host "NOT FOUND at expected location: $snarkjsCmd"
    Write-Host ""
    Write-Host "Trying to locate it..."
    $found = Get-ChildItem -Path $npmGlobalPrefix -Filter "snarkjs.cmd" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
        Write-Host "OK  found at: $($found.FullName)"
        $npmGlobalPrefix = $found.DirectoryName
    } else {
        Write-Host "snarkjs.cmd not found anywhere under npm prefix."
        Write-Host "Run:  npm install -g snarkjs"
        Write-Host "Then re-run this script."
        exit 1
    }
}

Write-Host ""
Write-Host "--- Checking PATH ---"
$currentPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
if ($currentPath -like "*$npmGlobalPrefix*") {
    Write-Host "OK  npm global bin is already in your PATH."
    Write-Host "    You may need to restart your terminal for it to take effect."
} else {
    Write-Host "NOT IN PATH -- adding $npmGlobalPrefix to user PATH..."
    $newPath = $currentPath + ";" + $npmGlobalPrefix
    [System.Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
    Write-Host "OK  PATH updated."
    Write-Host ""
    Write-Host "IMPORTANT: Close and reopen PowerShell for the change to take effect."
    Write-Host "           Then run prove.ps1 again."
}

Write-Host ""
Write-Host "--- Verifying snarkjs is callable in this session ---"
# Temporarily add to current session PATH as well
$env:PATH = $env:PATH + ";" + $npmGlobalPrefix
try {
    $version = & snarkjs --version 2>&1
    Write-Host "OK  snarkjs version: $version"
} catch {
    Write-Host "Still not callable. Try running: npm install -g snarkjs"
}
