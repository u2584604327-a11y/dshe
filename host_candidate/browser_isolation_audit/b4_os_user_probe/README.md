# B4 actual Android35 OS-managed user storage (disposable test only)

An Android35 x86_64 fresh QEMU creates a temporary managed-profile-type
Android user. The same no-permission/no-INTERNET independent package is
installed for parent and work users, each must have a different OS-supplied
Linux UID while sharing the same appId remainder. Both seed fixed synthetic
SharedPreferences and private file data and verify only their own persisted
values after force-stop/relaunch. Each must be unable to open the other
user's already-written private file via its absolute test-only path.

Does not install on phone, run original DSH, use accounts, enable device
admin, use TestDPC, cross-profile Intent/URI sharing, root, or network.
This is not enterprise DPC profile-owner policy proof; not a real phone
work-profile UI, not original BrowserBridge integration, not AVF/pVM.
Fail closed on missing emulation, user creation, UID or storage markers.
Only this test user/package are cleaned up at runner exit.

B4 strict-errno amendment: both parent and work-user verification must
record the actual app-process Os.open() EACCES/EPERM marker. ENOENT and
other errno values are inconclusive and fail closed. The runner demands
exactly two permission-denied markers inside one unique real log boundary.
This cannot be replaced by FileNotFoundException alone.

## B4 explicit cross-user ContentProvider URI probe (disposable synthetic only)

The APK has a deliberately exported fixture-only `SyntheticRoleProvider`, containing
**only** a constant role (`PARENT` or `WORK`) for the current Android OS user;
it never accesses files, cookies, accounts, or real browser data. No URI grants,
`singleUser` mode, network or app permissions are requested. The source tests
both users with explicit `content://<selfUserId>@com.dsh.b4probe.synthetic/role`
positive `ContentResolver.query()` calls, checking exactly one matching
synthetic role. The corresponding `otherUserId@authority` query must throw
a real `SecurityException`. A null cursor, unresolved provider, inaccessible
same-user fixture, path typo, failed user unlock, or other exception does **not**
count as an Android cross-user security pass. Both directions must be present
exactly once after the fresh emulator Logcat boundary.

The Android35 emulator proves only this explicit cross-user URI route under
the disposable package and its no-permission settings, NOT arbitrary
`Intent`/Binder transfers, enterprise device/profile-owner policy, a real
phone's work-profile settings, production DSH integration or AVF/pVM.
No real provider is exposed in the original DSH or production build.
