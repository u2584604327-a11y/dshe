#!/usr/bin/env python3
"""Reject permission/identity/component drift in the explicit network test."""
import copy
import xml.etree.ElementTree as ET
import http_manifest as manifest
p51=manifest.p51
A=p51.A
source=ET.Element('manifest',{'package':p51.ORIGINAL})
app=ET.SubElement(source,'application',{A+'name':'com.dsh.android.OriginalApplication'})
ET.SubElement(source,'uses-permission',{A+'name':'android.permission.READ_EXTERNAL_STORAGE'})
ET.SubElement(app,'provider',{A+'name':'com.dsh.android.PrivateProvider'})
ET.SubElement(app,'service',{A+'name':p51.SERVICE,A+'isolatedProcess':'true',A+'exported':'false',A+'process':':p43_isolated'})
ET.SubElement(app,'activity',{A+'name':p51.ACTIVITY,A+'exported':'true'})
valid=ET.fromstring(manifest.transform(ET.tostring(source)))
manifest.verify_bytes(ET.tostring(valid))
for kind in ('permission','identity','export','isolation','original-component','shared-uid'):
    root=copy.deepcopy(valid)
    if kind=='permission':ET.SubElement(root,'uses-permission',{A+'name':'android.permission.READ_EXTERNAL_STORAGE'})
    if kind=='identity':root.set('package',p51.ORIGINAL)
    if kind=='export':root.find('application/service').set(A+'exported','true')
    if kind=='isolation':root.find('application/service').set(A+'isolatedProcess','false')
    if kind=='original-component':ET.SubElement(root.find('application'),'activity',{A+'name':'com.dsh.android.MainActivity'})
    if kind=='shared-uid':root.set(A+'sharedUserId','original')
    try:manifest.verify_bytes(ET.tostring(root))
    except RuntimeError:pass
    else:raise AssertionError('ACCEPTED_'+kind)
try:p51.verify_manifest_bytes(ET.tostring(valid))
except RuntimeError:pass
else:raise AssertionError('PERMISSIONLESS_P51_GATE_WEAKENED')
print('HTTP_TEST_MANIFEST_INTERNET_ONLY_AND_IDENTITY_NEGATIVES=PASS')
print('ORIGINAL_PERMISSIONLESS_P51_MANIFEST_GATE=UNCHANGED_DENY_NETWORK_VARIANT')

import main_manifest as main
main_valid=ET.fromstring(main.transform(ET.tostring(source)))
main.verify_bytes(ET.tostring(main_valid))
for kind in ('permission','identity','export','isolation','original-component','shared-uid'):
    root=copy.deepcopy(main_valid)
    if kind=='permission':ET.SubElement(root,'uses-permission',{A+'name':'android.permission.READ_EXTERNAL_STORAGE'})
    if kind=='identity':root.set('package',p51.ORIGINAL)
    if kind=='export':root.find('application/service').set(A+'exported','true')
    if kind=='isolation':root.find('application/service').set(A+'isolatedProcess','false')
    if kind=='original-component':ET.SubElement(root.find('application'),'activity',{A+'name':'com.dsh.android.MainActivity'})
    if kind=='shared-uid':root.set(A+'sharedUserId','original')
    try:main.verify_bytes(ET.tostring(root))
    except RuntimeError:pass
    else:raise AssertionError('MAIN_ACCEPTED_'+kind)
for validator in (manifest.verify_bytes,p51.verify_manifest_bytes):
    try:validator(ET.tostring(main_valid))
    except RuntimeError:pass
    else:raise AssertionError('PREVIOUS_MANIFEST_GATE_ACCEPTED_MAIN_VARIANT')
print('MAIN_TEST_MANIFEST_FIXED_PAIR_PREVIOUS_GATES_AND_SECURITY_NEGATIVES=PASS')
