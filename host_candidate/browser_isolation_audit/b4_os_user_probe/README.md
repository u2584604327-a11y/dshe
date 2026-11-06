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
