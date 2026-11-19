# P160 native ARM64 hosted runner: OS capability preflight

GitHub Actions offers `ubuntu-24.04-arm` for public repositories. Unlike
P136's Ubuntu x86_64 TCG or P132/P158's Google APIs x86_64 Native Bridge
emulator, this is a **real Linux aarch64 host kernel**. It is not an
Android emulator/kernel and cannot itself start a signed-v138 Android Bionic
Node ELF with `/system/bin/linker64`.

This guard inspects (without installing anything) the real host architecture,
the unprivileged KVM API version plus one **empty** VM file descriptor,
and the presence of preinstalled Android SDK, emulator ELF and Android35
Google APIs arm64-v8a image. It does not create a guest vCPU, boot Android,
run an original APK, accept any SDK license, download software, access a
phone, emulate a user or execute Node.

A `KVM_VM_CREATE_PASS_NO_GUEST` on native ARM64 Linux proves hardware
virtualization is accessible to the hosted runner, NOT that a usable Android
image exists. If missing, stop. If present and a licensed image was already
available, next steps may design a separate bounded Android guest test;
never invent P137 license approval and never use the native Linux kernel
as proof of the Android guest or isolated Worker security boundary.

Required future gates still include a real Android guest aarch64 uname and
arm64-v8a ABI, original signed-v138 exact Node SHA inside a trusted Android
isolated process, original EngineManager Process lifecycle and HTTP Ready.
Sensitive tools remain DENY_ALL. v139 is not releasable on P160 evidence.
