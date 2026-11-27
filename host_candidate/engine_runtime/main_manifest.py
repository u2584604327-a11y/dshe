#!/usr/bin/env python3
"""Explicit full-original-main TEST ONLY identity over the strict network test."""
import argparse
import copy
import xml.etree.ElementTree as ET
from pathlib import Path
if __package__:
    from . import http_manifest as previous
else:
    import http_manifest as previous
A=previous.A
PACKAGE=previous.PACKAGE
ACTIVITY='com.dsh.android.engine.OriginalMainProbeActivity'
SERVICE='com.dsh.android.engine.OriginalMainIsolatedService'
LABEL='DSH Original Main TEST'
VERSION='original-main-storage-test-3'


def require(value,code):
    if not value:raise RuntimeError('MAIN_TEST_MANIFEST_'+code)


def transform(source):
    root=ET.fromstring(previous.transform(source));root.set(A+'versionName',VERSION)
    app=root.find('application');app.set(A+'label',LABEL)
    app.find('activity').set(A+'name',ACTIVITY);app.find('activity').set(A+'label',LABEL)
    app.find('service').set(A+'name',SERVICE);app.find('service').set(A+'process',':main_isolated')
    data=ET.tostring(root,encoding='utf-8',xml_declaration=True);verify_bytes(data);return data


def verify_bytes(data):
    root=ET.fromstring(data);app=root.find('application')
    require(root.get('package')==PACKAGE and root.get(A+'versionName')==VERSION,'IDENTITY')
    require(app is not None and app.get(A+'label')==LABEL,'APP')
    require(app.find('activity').get(A+'name')==ACTIVITY and app.find('activity').get(A+'label')==LABEL and
            app.find('service').get(A+'name')==SERVICE and app.find('service').get(A+'process')==':main_isolated','COMPONENTS')
    normal=copy.deepcopy(root);normal.set(A+'versionName','http-native-prerequisite-test-2')
    app=normal.find('application');app.set(A+'label',previous.LABEL)
    app.find('activity').set(A+'name',previous.ACTIVITY);app.find('activity').set(A+'label',previous.LABEL)
    app.find('service').set(A+'name',previous.SERVICE);app.find('service').set(A+'process',':http_isolated')
    previous.verify_bytes(ET.tostring(normal))


def verify_apk(path):
    from androguard.core.apk import APK
    from lxml import etree
    apk=APK(str(path))
    require(apk.get_package()==PACKAGE and apk.get_permissions()==['android.permission.INTERNET'],'APK_PERMISSIONS')
    require(int(apk.get_min_sdk_version() or 0)==26 and int(apk.get_target_sdk_version() or 0)==28,'APK_SDK')
    verify_bytes(etree.tostring(apk.get_android_manifest_xml()))
    print('MAIN_TEST_SEPARATE_IDENTITY_HOST_INTERNET_ONLY_AND_ISOLATED_SERVICE=PASS')
    print('MAIN_TEST_ORIGINAL_ENGINE_MANAGER_AND_FORMAL_V139=NOT_WIRED')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=['inject','verify']);parser.add_argument('target',type=Path)
    args=parser.parse_args()
    if args.mode=='inject':args.target.write_bytes(transform(args.target.read_bytes()))
    else:verify_apk(args.target)
