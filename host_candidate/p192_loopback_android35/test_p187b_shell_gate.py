#!/usr/bin/env python3
"""Run P187B harness against fake ADB only; never touch real/emulated devices."""
import os, pathlib, subprocess, tempfile, textwrap
ROOT = pathlib.Path(__file__).resolve().parent
HARNESS = ROOT / "run_android35_emulator_only.sh"
MOCK = r'''#!/usr/bin/env python3
import os, pathlib, sys
args=sys.argv[1:]
scenario=os.environ.get('P187B_SCENARIO','pass')
store=pathlib.Path(os.environ['P187B_MOCK_MARKER_FILE'])
if args[:2]!=['-s','emulator-5554']:
    print('WRONG_SERIAL',file=sys.stderr);sys.exit(2)
if args[2:6]==['shell','getprop','ro.kernel.qemu']:
    print('0' if scenario=='wrong-qemu' else '1')
elif args[2:6]==['shell','pm','path','com.dsh.android']:
    if scenario!='missing-app':print('package:/data/app/com.dsh.android/base.apk')
elif args[2:7]==['shell','log','-p','i','-t']:
    if args[7]!='P187_RUN_BOUNDARY':sys.exit(2)
    store.write_text(args[8])
elif args[2:5]==['shell','am','start']:
    print('Error: Activity not started' if scenario=='am-error' else 'Starting: Intent ...')
elif args[2:5]==['logcat','-d','-v']:
    marker=store.read_text()
    old='I/P43_HOST_BINDER( 123): P187_HOST_UID_SELF_LOOPBACK=PASS\n'
    old+='I/P43_HOST_BINDER( 123): P187_ISOLATED_BIND_127001=PASS\n'
    old+='I/P43_HOST_BINDER( 123): P187_HOST_TO_ISOLATED_CONNECT_127001=PASS\n'
    old+='I/P43_HOST_BINDER( 123): P187_ISOLATED_ACCEPT_NONCE=PASS\n'
    if scenario=='stale-only':print(old,end='');sys.exit(0)
    print(old,end='')
    if scenario!='no-marker':print('I/P187_RUN_BOUNDARY( 456): '+marker)
    if scenario=='no-results':sys.exit(0)
    suffix=old
    if scenario=='duplicate':suffix+=('I/P43_HOST_BINDER( 123): '
                                       'P187_ISOLATED_BIND_127001=PASS\n')
    if scenario=='bind-denied':suffix=suffix.replace('P187_ISOLATED_BIND_127001=PASS',
                                                     'P187_ISOLATED_BIND_127001=BIND_EACCES')
    if scenario=='unexpected-error':suffix+=('I/P43_HOST_BINDER( 123): '
                                              'P187_REQUEST_BINDER_SEND=FAILED\n')
    print(suffix,end='')
else:
    print('UNKNOWN_ADB_CALL '+repr(args),file=sys.stderr)
    sys.exit(2)
'''
CASES=[
    ('pass',True),('stale-only',False),('no-marker',False),
    ('no-results',False),('duplicate',False),('bind-denied',False),
    ('unexpected-error',False),('wrong-qemu',False),
    ('missing-app',False),('am-error',False),
]
only = os.environ.get("P187B_ONLY")
if only:
    requested = set(only.split(","))
    CASES = [item for item in CASES if item[0] in requested]
with tempfile.TemporaryDirectory(prefix='p187b_fake_adb_') as td:
    d=pathlib.Path(td)
    adb=d/'adb';adb.write_text(MOCK);adb.chmod(0o755)
    marker_file=d/'marker'
    for scenario,should_pass in CASES:
        env={**os.environ,'PATH':str(d)+os.pathsep+os.environ['PATH'],
             'P187B_SCENARIO':scenario,'P187B_MOCK_MARKER_FILE':str(marker_file),
             'P187B_OBSERVE_SECONDS':'0'}
        marker_file.write_text('')
        res=subprocess.run(['bash',str(HARNESS),'emulator-5554'],
                           env=env,stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,text=True,timeout=30)
        passed=res.returncode==0
        if passed!=should_pass:
            raise AssertionError(f'{scenario}: rc={res.returncode} output={res.stdout!r} err={res.stderr!r}')
        if passed and 'P187B_ANDROID35_LOOPBACK_VERIFIED_IN_THIS_EMULATOR_RUN=PASS' not in res.stdout:
            raise AssertionError(f'{scenario}: missing proof')
        print(f'P187B_FAKE_ADB_{scenario.upper().replace("-","_")}=PASS')
print(f'P187B_FAKE_ADB_GATE=PASS scenarios={len(CASES)}')
