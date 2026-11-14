# macOS ARM64 runner: read-only Android guest prerequisite gate

**Question:** Can the standard GitHub-hosted Apple Silicon `macos-15` image overcome P160's proven Linux AArch64 runner blockage (`NO_KVM_CHAR_DEVICE`, no preinstalled SDK/arm64 guest image) without touching the user's phone?

The current GitHub runner-images manifest publicly identifies `macos-15` as **ARM64**, with Android SDK platform-tools and emulator installed. It does NOT certify any preinstalled Android ARM64 system image, and GitHub's macOS virtualization may not expose nested HVF to the runner. This job measures those missing facts instead of guessing.

The job uses **only** the standard `macos-15` runner (never paid `-xlarge`), inspect-only Python, an 8-second bounded `emulator -accel-check` (no emulator guest boot), and read-only presence checks for API35/API36 `arm64-v8a` system images. It calls no `sdkmanager`, `avdmanager`, `install`, `yes`, `emulator -avd`, `adb`, `gh release download`, or APK/Node tool. No SDK license acceptance, software download, binaries, signing key or user device data is involved.

A workflow SUCCESS means **the guard executed**; explicit `MAC_ANDROID_35_ARM64_GUEST_PREREQUISITES` and `MAC_ANDROID_36_ARM64_GUEST_PREREQUISITES` labels decide whether a native guest is even feasible. These labels require host AArch64 + preinstalled SDK binaries + positively usable HVF + an actual preinstalled matching Android system.img. Unknown/unavailable is BLOCKED. A positive prerequisite result would authorize only designing a separate, reviewed guest test, **never** production Node admission. A blocked result means no real Android ARM64 guest can be claimed from this preinstalled environment without a separately reviewed image/license/runner route.

Original signed-v138 EngineManager, authentic Android isolated UID, Node ELF dependencies and token HTTP Ready remain entirely UNTESTED. P47/P142 no host fallback, P109 DENY_ALL, GS OFF, sole Draft PR #80, and formal signed-v139 BLOCKED remain unchanged.
