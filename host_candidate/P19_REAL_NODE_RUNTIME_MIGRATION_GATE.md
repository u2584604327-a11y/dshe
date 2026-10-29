# DSH P19 — actual production Node runtime migration gates

Date: 2026-10-29. Source-only and read-only. Not a v139 APK.

## Verified packaging observations (original signed v138; exact SHA checked)

- The assets/node-runtime.bin entry is a ZIP, not directly executable:
  SHA-256 ba16f7f4d0cc0b0272700effe06dc0d3682206afe1b54af75ca530a3e5c0d3bf.
- The nested bin/node is ARM64 ELF:
  SHA-256 a0d21a1589312919114b24a5cc520c30ab7f26f9985b3f0c643c153172ebd1e6.
- ELF interpreter: /system/bin/linker64.
- DT_RUNPATH contains a Termux path: /data/data/com.termux/files/usr/lib.
- Required shared libraries are not all present under resolvable sonames in the
  standalone runtime ZIP. Some LINKS.txt aliases point to absent ZIP members.
  This is a static archive dependency closure deficit; on-device system library
  availability and the current native host resolution sequence remain unknown.
- assets/engine.bin is separate compressed data.
- P15 original v138 manifest: zero isolatedProcess services.
- P18 separate Binder/UI/capability probe passed Android35:
  https://github.com/u2584604327-a11y/dshe/actions/runs/40839307072
  No original DSH Node launch was performed in that probe.

## Mandatory P19 migration boundaries

1. Read and verify exact original runtime, dependencies and native load path.
2. Build an immutable Android-compatible runtime distribution with complete
   verified library dependency closure, not writable host-private binaries.
3. Test the actual verified Node executable inside a disposable Android35
   isolated UID with no inherited app permissions. Prove process UID, host file
   denial, child-process denial and direct outbound egress denial.
4. Restrict all workload interactions through a per-worker-instance Binder
   capability broker: authenticated UID, explicit trusted native UI approval,
   scope, one-shot, expiry, replay denial, stop/death revocation.
5. No generic arbitrary file path / URL / header / FileDescriptor proxy.
   Ordinary user-selected image/file sends need separate explicit scopes.
6. Migrate original DSH host integration only after successful standalone
   real Node execution and full native callgraph / library coverage.
7. Regress real DSH dialogs, chat persistence, streaming, attachments,
   browser, logs, and prior P1–P18 security boundaries.
8. Never silently replace installed user v138, publish unsigned test APK, or
   upload fixed signing keys to GitHub Actions.

Official Android docs: isolatedProcess runs without app permissions
(https://developer.android.com/guide/topics/manifest/service-element).
Android 10+ targets cannot execute arbitrary code from writable app home
(https://developer.android.com/about/versions/10/behavior-changes-10).

## Release gate

P19_REAL_NODE_ZIP_ELF_METADATA=CI_PENDING
P19_RUNPATH_TERMUX_HARD_BINDING=DETECTED_STATIC
P19_NODE_ZIP_LIBRARY_CLOSURE=NOT_ESTABLISHED
P19_ISOLATED_UID_ORIGINAL_NODE_STARTUP=NOT_TESTED
P19_DSH_NODE_NATIVE_HOST_INTEGRATED=NO
P19_ORIGINAL_CERT_V139=NO
P19_USER_PHONE_CHANGED=NO
P19_RELEASE=BLOCKED

Browser device profiles and independent device detection website cannot prove
Linux UID isolation, SELinux enforcement or genuine iOS hardware identity.
