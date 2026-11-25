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
        subprocess.run(['javac', '--release', '8', '-sourcepath', os.pathsep.join(roots),
                        '-d', str(work), str(source),
                        str(ROOT / 'host_candidate/p77_engine_tar_audit/test/com/dsh/android/p77/P77TarAuditTest.java')], check=True)
        subprocess.run(['java', '-cp', str(work), 'com.dsh.android.p77.P77TarAuditTest'], check=True)
        wire = work / 'original.modules'
        subprocess.run(['java', '-cp', str(work), 'ModuleStreamMain',
                        str(args.apk.resolve()), str(wire)], check=True)
        environment = {'PATH': os.environ.get('PATH', ''), 'HOME': '/dsh-home', 'DSH_HOME': '/dsh-home'}
        command = [node, '--permission', '--allow-worker', '--allow-fs-read=' + str(BOOTSTRAP), str(BOOTSTRAP)]

        def execute(payload):
            failures = []
            with (work / 'stdout').open('wb') as stdout, (work / 'stderr').open('wb') as stderr:
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=stdout,
                                           stderr=stderr, env=environment, cwd=work)

                def send():
                    try:
                        with payload.open('rb') as data:
                            shutil.copyfileobj(data, process.stdin, 65536)
                    except BrokenPipeError:
                        pass  # A bounded rejection need not consume the supplied stream.
                    except Exception as error:
                        failures.append(type(error).__name__)
                    finally:
                        try:
                            process.stdin.close()
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
        status, output, diagnostics = execute(negative)
        require(status == 125 and output == b'' and b'E_DSH_MODULE_TREE_SEAL' in diagnostics,
                'CHANGED_ORIGINAL_BYTES_ACCEPTED')
        print('ORIGINAL_MODULE_STREAM_TRAILING_AND_HASH_MUTATION=DENY')
        print('ORIGINAL_NODE_ANDROID_ARM64_ENGINE_HTTP_READY=NOT_ATTESTED')


if __name__ == '__main__':
    main()
