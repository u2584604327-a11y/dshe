# P102 standalone phone log collection — non-destructive, no uninstall, no installs.
# Use in Windows PowerShell 5.1+ with an already authorized Android USB debugger.
param([string]$AdbPath = "")
$ErrorActionPreference = "Stop"
$package = "com.dsh.p102.trustedtoolprobe"
if ([string]::IsNullOrWhiteSpace($AdbPath)) {
    $defaultAdb = Join-Path $env:USERPROFILE "Downloads\P102-ADB\platform-tools\adb.exe"
    if (Test-Path -LiteralPath $defaultAdb) {
        $AdbPath = $defaultAdb
    } else {
        $cmd = Get-Command adb -ErrorAction SilentlyContinue
        if ($null -ne $cmd) { $AdbPath = $cmd.Source }
    }
}
if ([string]::IsNullOrWhiteSpace($AdbPath) -or -not (Test-Path -LiteralPath $AdbPath)) {
    throw "ADB not found. Provide -AdbPath 'C:\path\to\adb.exe'"
}
$devices = @(& $AdbPath devices)
if ($LASTEXITCODE -ne 0 -or -not (@($devices | Where-Object { $_ -match '\sdevice\s*$' }).Count -eq 1)) {
    throw "Exactly one authorized USB device is required. Check adb devices."
}
$installed = @(& $AdbPath shell pm list packages $package)
if ($LASTEXITCODE -ne 0 -or -not ($installed -contains "package:$package")) {
    throw "The P102 lab package is not installed. No packages were modified."
}
Write-Host "P102_PHONE_PACKAGE_INSTALLED=YES"
# Nothing is launched automatically: the user explicitly opens and approves
# the standalone P102 lab on their phone, preserving native consent semantics.
Write-Host "Open the P102 standalone app manually on the phone."
Write-Host "Tap its native approval button ONCE within 10 seconds of opening."
Read-Host "After tapping on the phone, press Enter to read the filtered P102 logs"
Write-Host "Reading only P102_TOOL_BINDER log tags; no full logcat export."
$logLines = @(& $AdbPath logcat -b all -d -v threadtime -s 'P102_TOOL_BINDER:V' '*:S')
if ($LASTEXITCODE -ne 0) { throw "Logcat read failed; device files were not changed." }
$filtered = @($logLines | Where-Object { $_ -match 'P102_' } | Select-Object -Last 90)
if ($filtered.Count -eq 0) { Write-Host "P102_TAG_LOGS=NOT_VISIBLE" }
$filtered | ForEach-Object { Write-Host $_ }
$markers = @(
  'P102_NATIVE_UI_APPROVAL_DISPATCH=YES',
  'P102_TRUSTED_EXECUTION_COUNT=1',
  'P102_HOST_TERMINAL_SEND=PASS_NOT_RECEIPT',
  'P102_HOST_WORKER_TERMINAL_RECEIPT=PASS_OBSERVATION_ONLY',
  'P102_HOST_REPLAY_REQUEST_REJECTED=PASS'
)
foreach ($marker in $markers) {
    if (@($filtered | Where-Object { $_ -match [regex]::Escape($marker) }).Count -gt 0) {
        Write-Host "OBSERVED $marker"
    } else {
        Write-Host "NOT_OBSERVED $marker"
    }
}
Write-Host "P102_DIAGNOSTIC_ONLY=YES; P102_PHONE_FULL_E2E=NOT_AUTOMATICALLY_CERTIFIED"
Write-Host "No uninstall, install, file removal, device data clear, or log buffer clear was performed."
