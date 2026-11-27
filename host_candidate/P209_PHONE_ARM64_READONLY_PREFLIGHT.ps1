# P209 phone ABI / environment READ-ONLY preflight (Windows PowerShell 5.1+).
# Does NOT install, update, uninstall, launch, stop or modify ANY phone app.
# Does NOT run adb root, run-as, logcat, dumpsys, backup, shell file reads,
# or collect private paths, account data, serial numbers, messages or tokens.
# Result is environment precheck ONLY, not original EngineManager/P47 proof.
# Public signed v138 source in this repo's Release dsh-baseline-v135dsh-baseline-v135.
# Canonical offline APK SHA256: 3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5.
# This script does not download APK bytes or require original com.dsh.android installed.
$ErrorActionPreference = "Stop"
function Say([string]$s) { Write-Output $s }
function Fail([string]$code) {
  Say ("P209_PHONE_PREFLIGHT=BLOCKED_" + $code)
  exit 2
}
$adb = Get-Command adb -ErrorAction SilentlyContinue
if ($null -eq $adb) { Fail "ADB_NOT_ON_PATH" }
$rawDevices = @(& adb devices 2>$null)
if ($LASTEXITCODE -ne 0) { Fail "ADB_DEVICES_FAILED" }
$ready = @($rawDevices | Where-Object { $_ -match '^([^\s]+)\s+device(?:\s|$)' })
Say ("P209_PHONE_ADB_READY_DEVICE_COUNT=" + $ready.Count)
if ($ready.Count -ne 1) { Fail "REQUIRES_EXACTLY_ONE_AUTHORIZED_DEVICE" }
$serial = ([regex]::Match([string]$ready[0], '^([^\s]+)\s+device(?:\s|$)')).Groups[1].Value
if ([string]::IsNullOrEmpty($serial)) { Fail "ADB_DEVICE_PARSE" }
function ReadDevice([string[]]$argsList) {
  # Never echo the ADB serial or the raw command response to the user.
  $out = @(& adb -s $serial shell @argsList 2>$null)
  if ($LASTEXITCODE -ne 0) { return "" }
  return (($out -join "`n").Trim())
}
$api = ReadDevice @("getprop", "ro.build.version.sdk")
$kernel = ReadDevice @("uname", "-m")
$abi = ReadDevice @("getprop", "ro.product.cpu.abi")
$abiList = ReadDevice @("getprop", "ro.product.cpu.abilist")
$qemu = ReadDevice @("getprop", "ro.kernel.qemu")
$selinux = ReadDevice @("getenforce")
$originalPkg = ReadDevice @("pm", "path", "com.dsh.android")
$sidecarPkg = ReadDevice @("pm", "path", "com.dsh.p51.isolatedprobe")
$originalPid = ReadDevice @("pidof", "com.dsh.android")
$apiValid = $api -match '^[0-9]{2,3}$' -and [int]$api -ge 34
$kernelValid = ($kernel -eq "aarch64")
$abiValid = ($abi -eq "arm64-v8a") -and (($abiList -split ",") -contains "arm64-v8a")
$qemuValid = ($qemu -ne "1")
$selinuxValid = ($selinux -eq "Enforcing")
Say ("P209_PHONE_API=" + $(if($apiValid){$api}else{"NOT_VERIFIED"}))
Say ("P209_PHONE_KERNEL_AARCH64=" + $(if($kernelValid){"PASS"}else{"NOT_PROVEN"}))
Say ("P209_PHONE_PRIMARY_ABI_ARM64=" + $(if($abiValid){"PASS"}else{"NOT_PROVEN"}))
Say ("P209_PHONE_EMULATOR_FLAG=" + $(if($qemu -eq "1"){"EMULATOR_REJECTED"}else{"NOT_ADVERTISED"}))
Say ("P209_PHONE_SELINUX_ENFORCING=" + $(if($selinuxValid){"PASS"}else{"NOT_PROVEN"}))
Say ("P209_ORIGINAL_DSH_INSTALLED=" + $(if($originalPkg -match '^package:'){"YES"}else{"NOT_VERIFIED"}))
Say ("P209_P51_SEPARATE_PACKAGE_INSTALLED=" + $(if($sidecarPkg -match '^package:'){"YES"}else{"NOT_VERIFIED"}))
Say ("P209_ORIGINAL_DSH_PROCESS_VISIBLE=" + $(if($originalPid -match '^\d+(\s+\d+)*$'){"YES"}else{"NOT_OBSERVED"}))
Say "P209_USER_APP_INSTALL_OR_DATA_MUTATION=NONE"
Say "P209_ORIGINAL_APP_UID_ISOLATION=NOT_ATTESTED"
Say "P209_ORIGINAL_ENGINEMANAGER_P40_P47=NOT_ATTESTED"
Say "P209_REAL_NODE_HTTP_READY=NOT_ATTESTED"
if (-not $apiValid) { Fail "ANDROID_API" }
if (-not $kernelValid -or -not $abiValid) { Fail "NOT_PROVEN_ARM64_ANDROID" }
if (-not $qemuValid) { Fail "EMULATOR_NOT_PHYSICAL_PHONE" }
if (-not $selinuxValid) { Fail "SELINUX_NOT_ENFORCING" }
Say "P209_ORIGINAL_APK_SOURCE=PUBLIC_RELEASE_PINNED_NOT_DOWNLOADED"
Say "P209_ORIGINAL_APK_SIGNATURE_MATCH_INSTALLED=NOT_ATTESTED"
Say "P209_ORIGINAL_INSTALLED_NOT_REQUIRED_FOR_ABI_TEST=YES"
Say "P209_PHONE_PREFLIGHT=PASS_ENVIRONMENT_ONLY"
