#!/usr/bin/env python3
"""Actual original default-config comparison; host Node only, never ARM64 proof."""
import argparse
import copy
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile

APK_SHA = '3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5'
CONFIG_SHA = '87eec7a72bd7a19225983090ee7f595f4a0c645259598b64f8d072879fa159b5'
ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = Path(__file__).with_name('original_modules.mjs').resolve()


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def verify_asset_allowlist(original, candidate, work):
    sys.path.insert(0, str(ROOT / 'host_candidate'))
    from loguru import logger
    logger.remove()
    import p49_original_node_stage as stage
    stage.verify(original, candidate, True)

    def denied(apk, explicit, reason):
        try:
            stage.verify(original, apk, explicit)
        except RuntimeError as error:
            require(str(error) == 'P49_BLOCKED_' + reason, 'WRONG_ASSET_REJECTION')
        else:
            raise RuntimeError('UNAUTHORIZED_MODULE_ASSET_ACCEPTED')

    denied(candidate, False, 'UNAUTHORIZED_EXTRA_ASSET_OR_LIB')
    negative = work / 'negative.apk'
    shutil.copyfile(candidate, negative)
    with zipfile.ZipFile(negative, 'a') as archive:
        archive.writestr('assets/unapproved-script.js', b'bad')
    denied(negative, True, 'UNAUTHORIZED_EXTRA_ASSET_OR_LIB')
    with zipfile.ZipFile(candidate) as source, zipfile.ZipFile(negative, 'w') as destination:
        for entry in source.infolist():
            payload = source.read(entry.filename)
            if entry.filename == 'assets/p50-original-modules.mjs':
                payload = bytes([payload[0] ^ 1]) + payload[1:]
            cloned = copy.copy(entry)
            cloned.compress_type = zipfile.ZIP_STORED
            destination.writestr(cloned, payload)
    denied(negative, True, 'MODULE_BOOTSTRAP_SHA_OR_LENGTH')
    negative.unlink()
    print('P49_DEFAULT_ALLOWLIST_REMAINS_STRICT=PASS')
    print('P49_EXPLICIT_MODULE_BOOTSTRAP_AND_EXTRA_ASSET_NEGATIVES=PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', required=True, type=Path)
    parser.add_argument('--host-node', required=True, type=Path)
    parser.add_argument('--module-apk', type=Path, help='also verify the built TEST-ONLY asset allowlist')
    parser.add_argument('--android-jar', type=Path, help='also test the actual stdin forwarding implementation on JVM')
    parser.add_argument('--baseline-bootstrap', type=Path, help='reproduce the exact 2c88fcc nonblocking-input failure')
    args = parser.parse_args()
    node = str(args.host_node.resolve())
    require(subprocess.check_output([node, '--version'], text=True).strip() == 'v26.4.0',
            'EXACT_NODE_26_4_0_REQUIRED')
    with args.apk.open('rb') as source:
        require(hashlib.file_digest(source, 'sha256').hexdigest() == APK_SHA, 'ORIGINAL_APK_SHA')
    with tempfile.TemporaryDirectory(prefix='dsh-original-modules-') as directory:
        work = Path(directory)
        if args.module_apk:
            verify_asset_allowlist(args.apk.resolve(), args.module_apk.resolve(), work)
        source = work / 'ModuleStreamMain.java'
        source.write_text('''import com.dsh.android.p50.P50ModuleStream;
import java.io.*;import java.util.zip.*;
public final class ModuleStreamMain {
 public static void main(String[] a)throws Exception{
  try(ZipFile z=new ZipFile(a[0]);OutputStream out=new BufferedOutputStream(new FileOutputStream(a[1]))){
   P50ModuleStream.writeOriginal(z.getInputStream(z.getEntry("assets/engine.bin")),out);
  }
 }
}''')
        roots = [str(p) for pattern in ('*/src', '*/android')
                 for p in (ROOT / 'host_candidate').glob(pattern) if p.is_dir()]
        sources = [str(source), str(ROOT / 'host_candidate/p77_engine_tar_audit/test/com/dsh/android/p77/P77TarAuditTest.java')]
        classpath = str(work)
        if args.android_jar:
            require(args.android_jar.is_file(), 'ANDROID_SDK_JAR_REQUIRED')
            sources.append(str(ROOT / 'host_candidate/p68_android_binder/test/com/dsh/android/p68/P68StdinLifecycleTest.java'))
            classpath += os.pathsep + str(args.android_jar.resolve())
        subprocess.run(['javac', '--release', '8', '-cp', classpath,
                        '-sourcepath', os.pathsep.join(roots), '-d', str(work), *sources], check=True)
        if args.android_jar:
            subprocess.run(['java', '-cp', classpath, 'com.dsh.android.p68.P68StdinLifecycleTest'],
                           check=True, timeout=30)
        subprocess.run(['java', '-cp', str(work), 'com.dsh.android.p77.P77TarAuditTest'], check=True)
        wire = work / 'original.modules'
        subprocess.run(['java', '-cp', str(work), 'ModuleStreamMain',
                        str(args.apk.resolve()), str(wire)], check=True)
        environment = {'PATH': os.environ.get('PATH', ''), 'HOME': '/dsh-home', 'DSH_HOME': '/dsh-home'}
        def execute(payload, nonblocking=False, bootstrap=BOOTSTRAP, expect_early_rejection=False):
            command = [node, '--permission', '--allow-worker', '--allow-fs-read=' + str(bootstrap), str(bootstrap)]
            failures = []
            with (work / 'stdout').open('wb') as stdout, (work / 'stderr').open('wb') as stderr:
                read_fd = write_fd = None
                if nonblocking:
                    read_fd, write_fd = os.pipe()
                    os.set_blocking(read_fd, False)
                try:
                    process = subprocess.Popen(command, stdin=read_fd if nonblocking else subprocess.PIPE,
                                               stdout=stdout, stderr=stderr, env=environment, cwd=work)
                except BaseException:
                    if write_fd is not None:
                        os.close(write_fd)
                    raise
                finally:
                    if read_fd is not None:
                        os.close(read_fd)
                feeder = os.fdopen(write_fd, 'wb') if nonblocking else process.stdin

                def send():
                    try:
                        if expect_early_rejection:
                            # Keep the writer open with zero bytes until the exact
                            # old reader rejects. EOF cannot produce this result.
                            for _ in range(400):
                                if process.poll() is not None:
                                    return
                                time.sleep(0.025)
                            raise RuntimeError('BASELINE_DID_NOT_REJECT_EMPTY_NONBLOCKING_FD')
                        if nonblocking:
                            time.sleep(0.25)  # real empty nonblocking fd during Node startup
                        with payload.open('rb') as data:
                            sent = 0
                            while block := data.read(65536):
                                feeder.write(block)
                                sent += len(block)
                                if nonblocking and sent % (4 * 1024 * 1024) == 0:
                                    feeder.flush()
                                    time.sleep(0.01)  # force repeated gaps, not just initial EAGAIN
                    except BrokenPipeError:
                        pass  # A bounded rejection need not consume the supplied stream.
                    except Exception as error:
                        failures.append(type(error).__name__)
                    finally:
                        try:
                            feeder.close()
                        except BrokenPipeError:
                            pass
                writer = threading.Thread(target=send, daemon=True)
                writer.start()
                try:
                    status = process.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise RuntimeError('ORIGINAL_MODULE_EXECUTION_TIMEOUT') from None
                writer.join(5)
                require(not writer.is_alive() and not failures, 'MODULE_WRITER_FAILURE')
            return status, (work / 'stdout').read_bytes(), (work / 'stderr').read_bytes()

        if args.baseline_bootstrap:
            baseline = args.baseline_bootstrap.resolve()
            require(hashlib.sha256(baseline.read_bytes()).hexdigest() ==
                    '9c48fee08e0038f3f6d1140ee93b808c20b7ecd4f74c990c250af2b3b747e4fd',
                    'BEFORE_FIX_BOOTSTRAP_SHA')
            status, output, diagnostics = execute(wire, nonblocking=True, bootstrap=baseline, expect_early_rejection=True)
            require(status == 125 and output == b'' and b'DSH_ORIGINAL_CONFIG_ERROR=EAGAIN' in diagnostics,
                    'BEFORE_FIX_FAILURE_NOT_REPRODUCED')
            print('ORIGINAL_MODULE_NONBLOCKING_BEFORE_FIX=REPRODUCED_EAGAIN_EXIT125')

        status, output, diagnostics = execute(wire)
        require(status == 0 and b'DSH_ORIGINAL_CONFIG_MODULES=69\n' in diagnostics,
                'ORIGINAL_RUNCLI_NOT_COMPLETED')
        require(len(output) == 44560 and hashlib.sha256(output).hexdigest() == CONFIG_SHA,
                'ORIGINAL_DEFAULT_CONFIG_CHANGED')

        # Independent Node filesystem/resolver reference: no custom hooks or synthetic JS.
        reference = work / 'reference'
        reference.mkdir()
        with zipfile.ZipFile(args.apk) as apk:
            with tarfile.open(fileobj=apk.open('assets/engine.bin'), mode='r|gz') as archive:
                for member in archive:
                    target = reference / member.name
                    require(target.resolve().is_relative_to(reference) and
                            (member.isdir() or member.isfile()), 'UNSAFE_REFERENCE_TAR')
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with archive.extractfile(member) as source_file, target.open('wb') as destination:
                            shutil.copyfileobj(source_file, destination)
        home = work / 'reference-home'
        home.mkdir()
        reference_environment = dict(environment, HOME=str(home), DSH_HOME=str(home))
        result = subprocess.run([node, '--permission', '--allow-fs-read=' + str(reference),
                                 '--allow-fs-read=' + str(home), '--allow-fs-write=' + str(home),
                                 str(reference / 'node_modules/@deepseek-ai/dsh/lib/bin.js'),
                                 '--dump-default-config', '--profile', 'web'],
                                env=reference_environment, cwd=work, capture_output=True, timeout=60)
        require(result.returncode == 0, 'INDEPENDENT_ORIGINAL_REFERENCE_FAILED')
        normalized = result.stdout.replace(str(home).encode(), b'/dsh-home').replace(
            str(reference).encode(), b'/dsh-runtime')
        require(normalized == output, 'HOOKS_DIFFER_FROM_ORIGINAL_NODE_RESOLVER')
        status, delayed, diagnostics = execute(wire, nonblocking=True)
        require(status == 0 and delayed == output and b'DSH_ORIGINAL_CONFIG_MODULES=69\n' in diagnostics,
                'NONBLOCKING_STDIN_LOST_ORIGINAL_MODULES')
        print('ORIGINAL_MODULE_NONBLOCKING_STDIN_AND_DELAYED_CHUNKS=PASS modules=69')
        print('ORIGINAL_MODULE_STREAM_DEFAULT_CONFIG=PASS modules=69 bytes=44560')
        print('ORIGINAL_CONFIG_NATIVE_NODE_RESOLVER_COMPARISON=PASS sha256=' + CONFIG_SHA)

        negative = work / 'negative.modules'
        for label, contents in (
            ('TRUNCATED', b'DSHMOD01' + struct.pack('>I', 100)),
            ('TRAVERSAL', b'DSHMOD01' + struct.pack('>I', 7) + b'../evil'),
            ('VERSION', b'DSHMOD00'),
            ('OVERSIZED', b'DSHMOD01' + struct.pack('>I', 1) + b'a' + b'\0' + struct.pack('>Q', 128 * 1024 * 1024 + 1)),
        ):
            negative.write_bytes(contents)
            status, output, diagnostics = execute(negative)
            require(status == 125 and output == b'' and b'DSH_ORIGINAL_CONFIG_ERROR=' in diagnostics,
                    'MALICIOUS_STREAM_ACCEPTED_' + label)
            print('ORIGINAL_MODULE_STREAM_' + label + '=DENY')
        shutil.copyfile(wire, negative)
        with negative.open('ab') as destination:
            destination.write(b'X')
        status, output, diagnostics = execute(negative)
        require(status == 125 and output == b'' and b'E_DSH_MODULE_TREE_SEAL' in diagnostics,
                'TRAILING_STREAM_ACCEPTED')
        with negative.open('r+b') as destination:
            destination.truncate(wire.stat().st_size)
            destination.seek(0, os.SEEK_END)
            destination.seek(destination.tell() - 5)  # last original payload byte, before terminator
            value = destination.read(1)
            destination.seek(-1, os.SEEK_CUR)
            destination.write(bytes([value[0] ^ 1]))
        status, output, diagnostics = execute(negative, nonblocking=True)
        require(status == 125 and output == b'' and b'E_DSH_MODULE_TREE_SEAL' in diagnostics,
                'CHANGED_ORIGINAL_BYTES_ACCEPTED')
        print('ORIGINAL_MODULE_STREAM_TRAILING_AND_HASH_MUTATION=DENY')
        print('ORIGINAL_NODE_ANDROID_ARM64_ENGINE_HTTP_READY=NOT_ATTESTED')


if __name__ == '__main__':
    main()
