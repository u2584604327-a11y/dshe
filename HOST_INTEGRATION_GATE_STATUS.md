# DSH v139 P2+P6 real baseline preflight — 2026-10-29

## Primary verified run

GitHub Actions run: https://github.com/u2584604327-a11y/dshe/actions/runs/40812133057

Status: **SUCCESS**. This run reads existing signed v138 APK and P6 Release sources, but **never generates a modified APK or installs anything**.

### Verified input identity

- Repo: `u2584604327-a11y/dshe` (private).
- v138 input: `DSH-vc138-P0-OFFLINE-TEST-fixed-signature.apk`, SHA256 `3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5`.
- P6 input: `DSH_V139_P6_NODE_CREDENTIAL_LOG_REDACTION_AND_ASSET_STAGING.zip`, SHA256 `3af586c2c83d1aea67d119357672559eb09371c77ef4e06900bb697c06d11fd5`.
- Original v135 and v138 package identity, v2 signature and fixed certificate were previously verified in https://github.com/u2584604327-a11y/dshe/actions/runs/40810972896

### Native bounded DEX static verification

Current private files:
- `host_candidate/patch_deny.py`
- `host_candidate/patch_browser.py`
- `host_candidate/patch_privacy.py`
- `host_candidate/verify_p2_scope.py`

The workflow **replays** four diagnostic-deny methods, two browser getter/open methods and one WebView configuration method from the exact v138 `classes.dex`, entirely in memory.

- Combined target DEX SHA256: `9a7cd89f4a5c86394770febf703a9345a44d8c12c39abec9d494635587d8f221` — PASS.
- 7 targeted original method bodies — scope PASS.
- 52,004 other code method bodies unchanged — PASS.
- Only expected DEX header integrity fields and target instruction ranges changed — PASS.
- Reconstructed instructions, preserved code headers/handlers, DEX SHA-1 and Adler32 — PASS.
- No new DEX references — static scope PASS.
- **New signed DSH APK built: NO**.

This is **not** a run of these bytes under Android ART or a true connection of P5's new Java classes into the existing Android host. Four original upload-entry denials do **not** cover generic native uploads or arbitrary Node diagnostic-sending paths.

### P6 asset preimage compatibility

Current private verifier: `host_candidate/verify_p6_asset_preimages.py`.

The workflow compares these three v138 ZIP entries with the P6 overlay manifest, both by exact SHA256 and byte length:

- `assets/browser-tool.zip` — PASS.
- `assets/browser-pane.zip` — PASS.
- `assets/dsh-fetch-guard.mjs` — PASS.

All three replacement assets match their pinned P6 hashes; nested browser ZIP CRC checks PASS. This proves **static asset replacement compatibility**, not that a running DSH host loads the replacements or fixes the visible UI.

### CI artifact storage

One preceding CI run had `P2/P6` checks PASS but the final artifact upload failed because the GitHub Actions **artifact storage quota was exhausted**. The final successful workflow writes textual hashes and gating status to the job summary instead, with **no artifact upload**, and requires no additional user files.

## Remaining release blockers

| Gate | Status |
| --- | --- |
| Exact baseline inputs | PASS |
| v138 P2 bounded DEX candidate static replay | PASS |
| P6 three-resource overlay preimages | PASS |
| P5 single-use safe sender hooked into real native transport | NOT_IMPLEMENTED |
| Native and Node diagnostic sending fully closed against bypass | NOT_VERIFIED |
| Native user review dialog hooked to existing log UI | NOT_IMPLEMENTED |
| Device settings button attached to original browser title bar | NOT_IMPLEMENTED |
| viewport/DPR/UA real application and readback | NOT_VERIFIED |
| Separate browser profile, cookies and storage verified | NOT_IMPLEMENTED |
| Runtime JS asset migration into full original host | NOT_VERIFIED |
| VersionCode >138 APK build | NO |
| Original-certificate v139 signing | NO |
| Android ART, data-preserving offline install and real phone | NOT_VERIFIED |

**Do not sign, publish or install a new APK based on the static replay alone.** Keep original signing material out of GitHub and the existing phone v138 unchanged. The next required engineering work is *actual native/Node send-path integration* and *Android host UI integration*, which cannot be accomplished by merely appending the existing standalone Java classes to DEX.
