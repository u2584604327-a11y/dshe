#!/usr/bin/env python3
"""Real original HTTP/auth/frontend over a host listener and Process pipes.
Host validation only. Never installs an APK or claims Android/full DSH READY.
"""
import argparse
import hashlib
from pathlib import Path
import os
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent
APK_SHA = '3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5'
TREE_SHA = 'b2c7e52890351c4d1a3200c67ccb9be6154389a20da0b0b590d16676ce47b1e1'


def require(value, code):
    if not value:
        raise RuntimeError(code)


def reference(apk, destination, wire):
    with apk.open('rb') as source:
        require(hashlib.file_digest(source, 'sha256').hexdigest() == APK_SHA, 'ORIGINAL_APK_SHA')
    tree = hashlib.sha256(b'P54_IMMUTABLE_ENGINE_TREE_V1\0')
    names = set()
    total = addons = 0
    wire.write(b'DSHMOD02')
    with zipfile.ZipFile(apk) as archive:
        with tarfile.open(fileobj=archive.open('assets/engine.bin'), mode='r|gz') as tar:
            for member in tar:
                name = member.name.rstrip('/')
                require(name and not any(x in ('', '.', '..') for x in name.split('/')) and
                        '\\' not in name and not any(ord(x) < 32 or ord(x) == 127 for x in name) and
                        name not in names and member.type in (b'0', b'\0', b'5') and
                        0 <= member.size <= 128 * 1024 * 1024, 'ORIGINAL_MEMBER_TYPE_PATH_BOUND')
                names.add(name)
                require(len(names) <= 30411, 'ORIGINAL_MEMBER_COUNT')
                directory = member.isdir()
                require(not directory or member.size == 0, 'ORIGINAL_DIRECTORY_SIZE')
                encoded = name.encode('utf-8')
                metadata=struct.pack('>I',len(encoded))+encoded+bytes([directory])+struct.pack('>Q',member.size)
                tree.update(metadata)
                wire.write(metadata)
                digest = hashlib.sha256()
                target = destination / name
                require(target.resolve().is_relative_to(destination.resolve()), 'ORIGINAL_EXTRACTION_PATH')
                if directory:
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(member) as source, target.open('xb') as out:
                        copied = 0
                        while block := source.read(65536):
                            copied += len(block)
                            require(copied <= member.size, 'ORIGINAL_FILE_OVERRUN')
                            digest.update(block)
                            out.write(block)
                            wire.write(block)
                        require(copied == member.size, 'ORIGINAL_FILE_LENGTH')
                    total += member.size
                    addons += name.endswith('.node')
                tree.update(digest.digest())
    require(len(names) == 30411 and total == 262498938 and addons == 9 and
            tree.hexdigest() == TREE_SHA, 'ORIGINAL_COMPLETE_CLOSURE_SHA')
    wire.write(bytes(4));wire.flush()
    print('HTTP_TEST_ORIGINAL_COMPLETE_RESOURCE_CLOSURE=PASS members=30411 bytes=262498938')


def verify_snapshot_lock_reproduction(work):
    source=ROOT/'src/com/dsh/android/engine/DurableSessionSnapshot.java'
    old=source.read_text()
    additions=[
        '  // A second descriptor close can release this VM\'s POSIX locks on an inode.\n'
        '  // Reserve the directory identity BEFORE opening another lock descriptor.\n'
        '  private static final Set<Object> OPEN_ROOTS=new HashSet<>();\n'
        '  private final Object rootKey;\n',
        '    Object key;\n'
        '    try{key=directory.getFileAttributeView(BasicFileAttributeView.class).readAttributes().fileKey();}\n'
        '    catch(IOException failure){directory.close();throw failure;}\n'
        '    if(key==null){directory.close();throw new IOException("STORE_FILE_KEY_UNAVAILABLE");}\n'
        '    synchronized(OPEN_ROOTS){if(!OPEN_ROOTS.add(key)){directory.close();throw new IOException("STORE_OWNER_BUSY");}}\n'
        '    rootKey=key;\n',
    ]
    for added in additions:
        require(old.count(added)==1,'STORE_LEGACY_SOURCE_ANCHOR');old=old.replace(added,'')
    cleanup=('    }catch(IOException|RuntimeException failure){\n'
             '      try{if(acquired!=null)acquired.release();}finally{try{if(channel!=null)channel.close();}finally{try{directory.close();}finally{synchronized(OPEN_ROOTS){OPEN_ROOTS.remove(rootKey);}}}}\n'
             '      throw failure;\n    }')
    require(old.count(cleanup)==1,'STORE_LEGACY_CLEANUP_ANCHOR')
    old=old.replace(cleanup,'    }catch(IOException|RuntimeException failure){if(acquired!=null)acquired.release();if(channel!=null)channel.close();directory.close();throw failure;}')
    old=old.replace('try{lock.release();}finally{try{lockChannel.close();}finally{try{directory.close();}finally{synchronized(OPEN_ROOTS){OPEN_ROOTS.remove(rootKey);}}}}',
                    'try{lock.release();}finally{try{lockChannel.close();}finally{directory.close();}}')
    blob=old.encode();require(hashlib.sha1(b'blob '+str(len(blob)).encode()+b'\0'+blob).hexdigest()==
        '7bcfffd5ff7b66d1a7f8e5d41ffa002c09807a96','STORE_ORIGINAL_FAILURE_BLOB')
    folder=work/'legacy-store';folder.mkdir();(folder/'DurableSessionSnapshot.java').write_bytes(blob)
    subprocess.run(['javac','--release','8','-d',str(folder),str(folder/'DurableSessionSnapshot.java'),
                    str(ROOT/'src/com/dsh/android/engine/SessionSnapshotCodec.java'),
                    str(ROOT/'test/com/dsh/android/engine/DurableSessionSnapshotTest.java')],check=True)
    control=subprocess.run(['java','-cp',str(folder),'com.dsh.android.engine.DurableSessionSnapshotTest'],
                           capture_output=True,text=True,timeout=20)
    require(control.returncode!=0 and 'same_vm_duplicate_did_not_release_kernel_lock' in control.stderr,'STORE_LEGACY_KERNEL_LOCK_LOSS_NOT_REPRODUCED')
    print('OWNER_SNAPSHOT_OLD_DUPLICATE_CLOSE_RELEASES_KERNEL_LOCK=REPRODUCED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--node', type=Path, required=True)
    parser.add_argument('--android-jar', type=Path, required=True,
                        help='existing Android35 SDK stubs to compile the actual P68 stdin pump')
    args = parser.parse_args()
    require(args.android_jar.is_file(),'EXISTING_ANDROID_JAR_REQUIRED')
    node = str(args.node.resolve())
    require(subprocess.check_output([node, '--version'], text=True).strip() == 'v26.4.0', 'EXACT_NODE_VERSION')
    # This child has no network permission. The control must fail at a real
    # native bind, before the IPC adapter can legitimately serve HTTP.
    denied = subprocess.run([node, '--permission', '--eval',
                             "require('node:net').createServer().listen(0,'127.0.0.1')"],
                            capture_output=True, timeout=10)
    require(denied.returncode != 0 and b'ERR_ACCESS_DENIED' in denied.stderr, 'NATIVE_NODE_LISTEN_NOT_DENIED')
    print('HTTP_TEST_NATIVE_NODE_TCP_BIND=DENY_PERMISSION')
    with tempfile.TemporaryDirectory(prefix='dsh-original-http-') as folder:
        work = Path(folder)
        original = work / 'original'
        original.mkdir()
        module_stream=work/'original.modules'
        with module_stream.open('wb') as stream:reference(args.apk.resolve(),original,stream)
        from test_original_native_bundle import verify_runtime_adapter
        verify_runtime_adapter(args.apk.resolve(), args.node.resolve(), module_stream)
        classes = work / 'classes'
        home = work / 'fresh-home'
        home.mkdir(mode=0o700)
        sources = list((ROOT / 'src').rglob('*.java')) + list((ROOT / 'test').rglob('*.java'))
        host_root=ROOT.parent
        roots=[str(p) for pattern in ('*/src','*/android') for p in host_root.glob(pattern) if p.is_dir()]
        stdin_test=host_root/'p68_android_binder/test/com/dsh/android/p68/P68StdinLifecycleTest.java'
        sources.append(stdin_test)
        subprocess.run(['javac','--release','8','-cp',str(args.android_jar.resolve()),'-sourcepath',os.pathsep.join(roots),
                        '-d',str(classes),*map(str,sources)],check=True)
        classpath=str(classes)+os.pathsep+str(args.android_jar.resolve())
        # Independent old-order counterfactual: keep the current implementation
        # and remove only the EOF producer release. This is not a historical
        # byte-identical source claim. Real OS exit stays required in both.
        fixed=(ROOT/'src/com/dsh/android/engine/HttpProcessTransport.java').read_text()
        eof=('      // EOF releases this exact producer before waiting for the authenticated\n'
             '      // supervisor\'s EXIT. Otherwise its pipe drain can wait on this writer.\n'
             '      try{output.close();}catch(IOException ignored){}\n')
        require(fixed.count(eof)==1,'EOF_DRAIN_REPRODUCTION_ANCHOR')
        counter=work/'old-eof-order';counter.mkdir();source=counter/'HttpProcessTransport.java';source.write_text(fixed.replace(eof,''))
        subprocess.run(['javac','--release','8','-cp',classpath,'-d',str(counter),str(source)],check=True)
        refusal=subprocess.run(['java','-cp',str(counter)+os.pathsep+classpath,'com.dsh.android.engine.HttpProtocolNegativeTest',
                                node,str(ROOT/'test/malformed_peer.mjs'),'EXIT_DRAIN_ONLY'],capture_output=True,text=True,timeout=12)
        require(refusal.returncode!=0 and 'clean_unframed_exit_not_false_supervisor_failure_PREMATURE_EOF' in refusal.stderr,
                'EOF_DRAIN_OLD_ORDER_NOT_REPRODUCED')
        print('HTTP_EOF_WAIT_BEFORE_STDIN_CLOSE_FALSE_DENY=REPRODUCED_COUNTERFACTUAL')
        verify_snapshot_lock_reproduction(work)
        subprocess.run(['java','-cp',classpath,'com.dsh.android.engine.DurableSessionSnapshotTest'],check=True,timeout=25)
        # Main-profile-only extension; approved HTTP/native bootstraps below
        # remain byte-identical. These are real host pipes and durable files,
        # synthetic snapshots, never Android/original-main acceptance.
        from build_profile_transport import build as profile_transport
        extended=work/'profile-transport.mjs';extended.write_bytes(profile_transport())
        subprocess.run(['java','-cp',classpath,'com.dsh.android.engine.ProfileSnapshotWireTest',node,
                        str(extended),str(ROOT/'test/owned_snapshot_peer.mjs'),
                        str(ROOT/'test/snapshot_attack_peer.mjs')],check=True,timeout=45)
        # Recompile the byte-identified pre-fix source as an independent legacy
        # control. No original/baseline source or production gate is changed.
        actual=host_root/'p68_android_binder/android/com/dsh/android/p68/P68AndroidBinderIntake.java'
        fixed=actual.read_text()
        addition=('          // Process stdin can be buffered. A live interactive child must see\n'
                  '          // a short preface/frame before the producer sends more data or EOF.\n'
                  '          try{childInput.write(bytes,0,count);childInput.flush();}')
        require(fixed.count(addition)==1,'STDIN_FLUSH_REPRODUCTION_ANCHOR')
        old=fixed.replace(addition,'          try{childInput.write(bytes,0,count);}')
        blob=old.encode();require(hashlib.sha1(b'blob '+str(len(blob)).encode()+b'\0'+blob).hexdigest()==
            '65f69172ee029cb0566a8bf523e4d19d11382ced','LEGACY_STDIN_SOURCE_BLOB')
        legacy_source=work/'legacy-source/com/dsh/android/p68/P68AndroidBinderIntake.java'
        legacy_source.parent.mkdir(parents=True);legacy_source.write_bytes(blob)
        legacy_classes=work/'legacy-classes'
        subprocess.run(['javac','--release','8','-cp',str(args.android_jar.resolve()),'-sourcepath',os.pathsep.join(roots),
                        '-d',str(legacy_classes),str(legacy_source),str(stdin_test)],check=True)
        subprocess.run(['java','-cp',str(legacy_classes)+os.pathsep+str(args.android_jar.resolve()),
                        'com.dsh.android.p68.P68StdinLifecycleTest','--legacy-buffered'],check=True,timeout=15)
        subprocess.run(['java','-cp',classpath,'com.dsh.android.p68.P68StdinLifecycleTest'],check=True,timeout=30)
        ordinary = subprocess.run(['java', '-cp', classpath, 'com.dsh.android.engine.HttpProcessTransportTest', node,
                        str(ROOT / 'test/original_http_services.mjs'), str(original),
                        str(ROOT / 'http_transport.mjs'), str(home)], check=True, timeout=90, capture_output=True, text=True)
        print(ordinary.stdout, end='')
        matches=re.findall(r'^ORIGINAL_RENDERED_FRONTEND_SHA256=([a-f0-9]{64})$',ordinary.stdout,re.M)
        require(len(matches)==1,'INDEPENDENT_ORIGINAL_FRONTEND_SHA')
        require(not Path('/dsh-runtime').exists() and not Path('/dsh-home').exists(),'VIRTUAL_NAMESPACE_HAS_NATIVE_FILES')
        from build_http_bootstrap import build, _compose, CORE
        legacy=work/'legacy-unproxied-directory.mjs'
        legacy.write_bytes(_compose(False))
        require(hashlib.sha256(legacy.read_bytes()).hexdigest()==
                '14d9e696e0705e5ce8ed2ca25054a9926bf1028bbb151cf4905e730c6be13315','LEGACY_BOOTSTRAP_REPRODUCTION_SHA')
        directory=CORE.read_text().split('async function run() {\n')[0]
        directory+=(ROOT/'readonly_directory.mjs').read_text().replace('export function installVirtualDirectories','function installVirtualDirectories')
        directory+="\nimport assert from 'node:assert/strict';\n"+(ROOT/'test/readonly_directory.test.mjs').read_text()
        subprocess.run([node,'--permission','--input-type=module','--eval',directory],cwd='/',env={},check=True,timeout=15)
        bootstrap=work/'sealed-original-http.mjs'
        bootstrap.write_bytes(build())
        command=['java','-cp',classpath,'com.dsh.android.engine.ClosedResourceHttpTest',node,str(bootstrap)]
        subprocess.run(command[:5]+[str(legacy),str(module_stream),matches[0],'LEGACY_UNPROXIED_DIRECTORY'],check=True,timeout=90)
        subprocess.run(command+[str(module_stream),matches[0]],check=True,timeout=90)
        negative=work/'negative.modules'
        for kind,code in [('LEGACY','E_DSH_MODULE_STREAM_VERSION'),('HASH','E_DSH_MODULE_TREE_SEAL'),('CONTINUATION','E_DSH_IPC_HELLO')]:
            shutil.copyfile(module_stream,negative)
            with negative.open('r+b') as changed:
                if kind=='LEGACY':changed.write(b'DSHMOD01')
                elif kind=='CONTINUATION':changed.seek(0,os.SEEK_END);changed.write(bytes(88))
                else:
                    changed.seek(-5,os.SEEK_END);value=changed.read(1);changed.seek(-1,os.SEEK_CUR);changed.write(bytes([value[0]^1]))
            subprocess.run(command+[str(negative),matches[0],code],check=True,timeout=60)

        subprocess.run(['java', '-cp', classpath, 'com.dsh.android.engine.HttpProtocolNegativeTest', node,
                        str(ROOT / 'test/malformed_peer.mjs'), str(ROOT / 'test/malformed_host.mjs'),
                        str(ROOT / 'http_transport.mjs')], check=True, timeout=60)
    print('HTTP_TRANSPORT_ANDROID_BINDER_ARM64_MAIN_PROFILE=NOT_TESTED')
    print('DSH_PRODUCTION_ENGINE_HTTP_READY=NOT_ATTESTED')


if __name__ == '__main__':
    main()
