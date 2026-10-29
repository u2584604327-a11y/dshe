# Upload input bundles: two private Releases

Both workflows are **manual or auto-start on Release publication**. Nothing is signed or installed.

## Release A — Original v135 APK (147,351,542 bytes)
1. Open `Releases → Draft a new release` in this private repository.
2. Create tag `dsh-baseline-v135`.
3. Attach exactly `DSH0.4.1-v135-browser-native-device-v1.3.5-fixed-signature.apk`.
4. Expected SHA-256: `394adfbe85b81ce46c285b1c531ffa307432d777e17af04fe5418272c5cc2e99`.
5. Publish the release. The `APK baseline identity audit` workflow will start automatically.

This APK belongs to version 135, not v139. Do not download it over installed v138.

## Release B — P6 source bundle (770,325 bytes)
1. Create a *draft* Release with tag `dsh-source-v139-p6`.
2. Attach exactly `DSH_V139_P6_NODE_CREDENTIAL_LOG_REDACTION_AND_ASSET_STAGING.zip`.
3. Expected SHA-256: `3af586c2c83d1aea67d119357672559eb09371c77ef4e06900bb697c06d11fd5`.
4. Publish. The `DSH v139 P6 source and D8 evidence audit` workflow will start.

## Optional v138 identity baseline
Only if you have the previously signed v138 APK locally:
- Tag: `dsh-p0-v138`
- Filename: `DSH-vc138-P0-OFFLINE-TEST-fixed-signature.apk`
- Expected SHA256: `3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5` (from earlier report, not independently verified in this workspace)

## Things not to upload
Do **not** attach original fixed signing private key, JKS/P12/keystore, passwords, API keys, full logs, or any diagnostic archives.

## Correct interpretation
- `APK baseline identity audit = PASS` means **original** APK hash, v2 signer, package, version verified.
- `P6 source audit = PASS` means **offline** Java/Node tests and D8 conversion succeeded.
- Neither means the v139 host was integrated, runtime upload protection is complete, or a signed v139 APK was created.
- Until a complete Android host/DEX and runtime validation are available, `APK_BUILT=NO`, `ART=NOT_VERIFIED`, `USER_DATA_PRESERVATION=NOT_VERIFIED`.
