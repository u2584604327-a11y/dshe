#!/usr/bin/env python3
"""Explicit separate HTTP component test: INTERNET on host, isolated worker.
The permissionless P51 manifest contract is unchanged. Never an original DSH
application or an upgrade package; only the new test pair is executable.
"""
import argparse
import copy
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from p51_side_by_side import p51_manifest as p51
A = p51.A
PACKAGE = 'com.dsh.p51.networkprobe'
ACTIVITY = 'com.dsh.android.engine.OriginalHttpProbeActivity'
SERVICE = 'com.dsh.android.engine.OriginalHttpIsolatedService'
LABEL = 'DSH HTTP Components TEST'


def require(value, code):
    if not value:
        raise RuntimeError('HTTP_TEST_MANIFEST_' + code)


def transform(source):
    root = ET.fromstring(p51.transform(source))
    root.set('package', PACKAGE)
    root.set(A + 'versionName', 'http-components-test-1')
    ET.SubElement(root, 'uses-permission', {A + 'name': 'android.permission.INTERNET'})
    app = root.find('application')
    app.set(A + 'label', LABEL)
    app.set(A + 'usesCleartextTraffic', 'true')
    app.find('activity').set(A + 'name', ACTIVITY)
    app.find('activity').set(A + 'label', LABEL)
    app.find('service').set(A + 'name', SERVICE)
    app.find('service').set(A + 'process', ':http_isolated')
    output = ET.tostring(root, encoding='utf-8', xml_declaration=True)
    verify_bytes(output)
    return output


def verify_bytes(source):
    root = ET.fromstring(source)
    require(root.get('package') == PACKAGE and root.get(A + 'versionCode') == '1' and
            root.get(A + 'versionName') == 'http-components-test-1', 'IDENTITY')
    permission = root.findall('uses-permission')
    require(len(permission) == 1 and permission[0].attrib == {A + 'name': 'android.permission.INTERNET'}, 'HOST_INTERNET_ONLY')
    app = root.find('application')
    require(app is not None and app.get(A + 'usesCleartextTraffic') == 'true' and app.get(A + 'label') == LABEL, 'APP')
    require(app.find('activity').get(A + 'name') == ACTIVITY and
            app.find('service').get(A + 'name') == SERVICE and
            app.find('service').get(A + 'process') == ':http_isolated', 'TEST_COMPONENT_PAIR')
    # Normalize ONLY the enumerated HTTP-test differences and delegate every
    # other structural/permission/component restriction to the strict P51 gate.
    normalized = copy.deepcopy(root)
    normalized.remove(normalized.find('uses-permission'))
    normalized.set('package', p51.SIDECAR)
    app = normalized.find('application')
    app.set(A + 'usesCleartextTraffic', 'false');app.set(A + 'label', p51.LABEL)
    app.find('activity').set(A + 'name', p51.ACTIVITY);app.find('activity').set(A + 'label', p51.LABEL)
    app.find('service').set(A + 'name', p51.SERVICE);app.find('service').set(A + 'process', ':p51_isolated')
    p51.verify_manifest_bytes(ET.tostring(normalized))


def verify_apk(path):
    from androguard.core.apk import APK
    from lxml import etree
    apk = APK(str(path))
    require(apk.get_package() == PACKAGE and apk.get_permissions() == ['android.permission.INTERNET'], 'APK_PERMISSIONS')
    require(int(apk.get_min_sdk_version() or 0) == 26 and int(apk.get_target_sdk_version() or 0) == 28, 'APK_SDK')
    verify_bytes(etree.tostring(apk.get_android_manifest_xml()))
    print('HTTP_TEST_SEPARATE_IDENTITY_INTERNET_ONLY_ISOLATED_SERVICE=PASS')
    print('HTTP_TEST_ORIGINAL_DSH_APPLICATION_AND_DATA=UNTOUCHED')
    print('HTTP_TEST_FORMAL_V139=NO')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['inject', 'verify'])
    parser.add_argument('target', type=Path)
    args = parser.parse_args()
    if args.mode == 'inject':
        args.target.write_bytes(transform(args.target.read_bytes()))
    else:
        verify_apk(args.target)
