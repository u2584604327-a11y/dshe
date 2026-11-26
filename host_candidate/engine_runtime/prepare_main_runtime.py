#!/usr/bin/env python3
"""Install only the pinned main bootstrap and original native supplement."""
import argparse
import hashlib
from pathlib import Path
from build_original_main_bootstrap import build
from prepare_native_http import embed
MAIN_SHA='81b162b3cd84d3623daa84a1049c0201ca8c4814198dbb570bf58e3dbe41178c'
MAIN_LENGTH=85349


def prepare(apk,decoded):
    script=build(apk)
    if len(script)!=MAIN_LENGTH or hashlib.sha256(script).hexdigest()!=MAIN_SHA:raise ValueError('MAIN_TEST_BOOTSTRAP_PIN')
    target=decoded/'assets/engine-original-main.mjs'
    if not target.parent.is_dir() or target.exists() or target.is_symlink():raise ValueError('MAIN_TEST_ASSET_COLLISION')
    with target.open('xb') as output:output.write(script)
    print('MAIN_TEST_PINNED_ORIGINAL_MAIN_RESOURCE_AND_FIXED_NATIVE_BOOTSTRAP=PASS_STATIC')
    print('MAIN_TEST_ANDROID_ARM64_MAIN_RUNTIME=NOT_TESTED')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=['prepare','embed']);parser.add_argument('apk',type=Path);parser.add_argument('target',type=Path)
    args=parser.parse_args();(prepare if args.mode=='prepare' else embed)(args.apk,args.target)
