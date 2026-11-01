# P137 manual permission boundary for the existing P136 Android guest check

The exact Google SDK system-image license acknowledgment is **not** granted by
a PR synchronization, an ordinary chat message, or a passing diagnostic CI.

The current P136 CI observes license prompts and responds **n** by default.
It does not use sdkmanager --licenses or broadly accept every SDK license.

**Registration blocker (verified at this PR HEAD):** The P136 workflow file
exists on PR #80's branch but is NOT present in the repository's default
main branch. GitHub's manual workflow_dispatch UI requires a workflow
registered on the default branch. Therefore there is currently NO
actionable Actions -> Run workflow step for P136. Do NOT merge the PR,
alter main or add another workflow just to evade that safety boundary.

After a separately authorized future workflow registration on the default
branch, an authorized repository operator who reviews the actual Google
SDK license can select PR #80's branch and type this exact
case-sensitive input in acknowledge_sdk_license:

I_ACCEPT_GOOGLE_ANDROID_SDK_LICENSE_FOR_ARM64_IMAGE

This only sends **one** "y" to the installer for
system-images;android-35;google_apis;arm64-v8a in a disposable GitHub runner.
If that process prompts for other licenses, the response is not repeated.
All other event types and unrecognized inputs send "n". No acceptance is
performed by creating or merging this code.

The best possible positive P136 result is that a true Android guest reports
uname -m = aarch64 and the primary ABI = arm64-v8a. It does not constitute
original Node execution, original Android app isolated UID, or EngineManager
production lifecycle acceptance. P109 remains DENY_ALL, v139 BLOCKED.

Real-ARM64 Android emulator TCG on x86_64 without acceleration is unsupported
and may time out even if the image installs successfully. Stop after this
bounded attempt if it fails; switch to an explicitly authorized real ARM64
Android test environment rather than trying further permission/ABI bypasses.
