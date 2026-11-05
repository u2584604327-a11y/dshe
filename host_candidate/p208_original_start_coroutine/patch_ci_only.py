#!/usr/bin/env python3
"""P208 CI-only exact original v138 EngineManager.start$2.invokeSuspend first entry observer.

Never patch a released original, run on a user's phone or authorize Node.
Only ephemeral / .p43tmp/decoded smali on sole Draft PR #80.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPO="u2584604327-a11y/dshe"
BRANCH="dsh/p96-original-engine-stream-owner-narrow-20261030"
BUILDER=Path("host_candidate/p43_original_service/build_embedded_emulator_apk.sh")
BUILDER_SHA="62ad8b62d5c0bfadf7d3b98294fd8713fb8f686f"
JAVA=Path("host_candidate/p208_original_start_coroutine/android/com/dsh/android/p208/P208StartCoroutineWitness.java")
BRIDGE=(
    "    python3 host_candidate/p208_original_start_coroutine/patch_ci_only.py "
    "--inject-smali \"$DIR/decoded\"\n"
)
BRIDGE_BLOCK=(
    "if test \"${P208_CI_METHOD_ENTRY_ONLY:-0}\" = 1; then\n"
    + BRIDGE+
    "fi\n"
)
INSERT="    invoke-static {}, Lcom/dsh/android/p208/P208StartCoroutineWitness;->mark()V\n"
METHOD=re.compile(r"(?m)^\.method[^\n]*\sinvokeSuspend\(Ljava/lang/Object;\)Ljava/lang/Object;[ \t]*$")
INSTR=re.compile(
    r"(?m)^[ \t]+(?:move|const|invoke|new-|return|goto|if-|iget|iput|"
    r"sget|sput|aget|aput|check-cast|instance-of|monitor-|throw|"
    r"filled-new-array|array-length|nop|cmp|add-|sub-|mul-|div-|and-|or-)"
    r"[a-zA-Z0-9_/+-]*(?=\s|$)"
)
UNSAFE_RE=re.compile(r"(?m)^\s*(?:\.catch|\.catchall|\.packed-switch|"
                     r"\.sparse-switch|\.array-data|if-|goto|packed-switch|"
                     r"sparse-switch|fill-array-data|throw|monitor-)")
SOURCE_SHA="3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5"

class Refused(Exception):pass
def require(condition,code):
    if not condition:raise Refused("P208_DENY_"+code)
def sha256(data):return hashlib.sha256(data).hexdigest()
def git(*args):
    return subprocess.check_output(["git",*args],text=True,
                                   stderr=subprocess.DEVNULL).strip()
def exact(s,before,after,code):
    require(s.count(before)==1,"EXPECTED_ONE_"+code)
    return s.replace(before,after,1)

def patch_builder(s):
    old=("if test \"${P72_ACCESSOR_FIXTURE_ONLY:-0}\" = 1; then\n"
         "  test \"${P51_SIDE_BY_SIDE:-0}\" = 1 || {")
    s=exact(s,old,BRIDGE_BLOCK+old,"BUILDER_HOOK")
    line=("  host_candidate/p43_original_service/android/com/dsh/android/"
          "p43/P43ProbeActivity.java \\\n")
    extra=("  host_candidate/p208_original_start_coroutine/android/com/dsh/android/"
           "p206/P208StartCoroutineWitness.java \\\n")
    s=exact(s,line,line+extra,"JAVA_COMPILE")
    require(s.count("patch_ci_only.py --inject-smali")==1,
            "ONLY_ONE_ENTRY_HOOK")
    return s


def verify_signed_original_coroutine(apk):
    """Exact signed v138 original DEX; verify start$2 and original PC3912 without exposing runtime data."""
    import zipfile
    from androguard.core.dex import DEX
    require(apk.is_file() and sha256(apk.read_bytes())==SOURCE_SHA,
            "SIGNED_ORIGINAL_V138_SHA_MISMATCH")
    with zipfile.ZipFile(apk) as z:
        require(z.testzip() is None,"ORIGINAL_ZIP_CRC")
        dex=DEX(z.read("classes.dex"))
    owner="Lcom/dsh/android/EngineManager$start$2;"
    coroutine=[m for c in dex.get_classes() if c.get_name()==owner
      for m in c.get_methods() if m.get_name()=="invokeSuspend"]
    require(len(coroutine)==1 and coroutine[0].get_code() is not None and
      "".join(coroutine[0].get_descriptor().split())==
      "(Ljava/lang/Object;)Ljava/lang/Object;",
      "EXACT_ORIGINAL_START2_INVOKESUSPEND_SIGNATURE")
    inv=list(coroutine[0].get_instructions_idx())
    pc3912=[i for pc,i in inv if pc==3912]
    require(len(pc3912)==1 and pc3912[0].get_name()=="invoke-virtual" and
       "Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;" in pc3912[0].get_output(),
       "EXACT_ORIGINAL_MAIN_START_PC3912")
    for pc,needle in {
        3924:"Lcom/dsh/android/EngineManager;->access$setProcess$p(",
        3980:"Lcom/dsh/android/EngineManager$start$2",
        3986:"Ljava/lang/Thread;-><init>(",
        4010:"Ljava/lang/Thread;->start()",
        4026:"Ljava/util/concurrent/CountDownLatch;->await(",
        4674:"Lkotlinx/coroutines/flow/MutableStateFlow;->setValue(",
    }.items():
        ins=[i for at,i in inv if at==pc]
        require(len(ins)==1 and needle in ins[0].get_output(),
                "EXACT_ORIGINAL_LIFECYCLE_PC_"+str(pc))
    starts=[m for c in dex.get_classes() if
        c.get_name()=="Lcom/dsh/android/EngineManager;"
        for m in c.get_methods() if m.get_name()=="start"]
    require(len(starts)==1 and starts[0].get_code() is not None and
       "".join(starts[0].get_descriptor().split())==
        "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
       "EXACT_ORIGINAL_PARENT_START_SIGNATURE")
    references=[(pc,i.get_name()) for pc,i in starts[0].get_instructions_idx()
          if owner in i.get_output()]
    require(len(references)>=1 and len(references)<=8,
            "PARENT_START_TO_START2_SYMBOL_RELATION")
    print("P208_SIGNED_ORIGINAL_START2_INVOKESUSPEND_SIGNATURE=PASS")
    print("P208_ORIGINAL_PC3912_AND_LIFECYCLE_EDGES=PASS")
    print("P208_REAL_START_PARENT_REFERENCES_START2_COROUTINE=PASS")

def find_method(s):
    matches=list(METHOD.finditer(s))
    require(len(matches)==1,"EXACT_SINGLE_ORIGINAL_INVOKESUSPEND_METHOD")
    m=matches[0]
    stop=s.find(".end method",m.end())
    require(stop>=0,"SMALI_METHOD_CLOSURE")
    # A following .method must not start before this method ends.
    require(s.find("\n.method",m.end(),stop)<0,"NESTED_METHOD")
    end=stop+len(".end method")
    return m.start(),end,s[m.start():end]

def patch_original_smali(s):
    require(INSERT.strip() not in s,"ORIGINAL_ALREADY_INSTRUMENTED")
    a,b,method=find_method(s)
    require(200<len(method)<220000,"SUSPEND_METHOD_BYTES_BOUND")
    directives=list(re.finditer(r"(?m)^[ \t]+\.(?:registers|locals)[ \t]+\d+[ \t]*$",method))
    require(len(directives)==1,"EXACT_REGISTER_DIRECTIVE")
    require(method.count("Lcom/dsh/android/p40/P40ProcessBridge;->start(Ljava/lang/ProcessBuilder;)Ljava/lang/Process;")==1 and
            "Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;" not in method,
            "ORIGINAL_P40_BRIDGE_REQUIRED")
    # Insert strictly AFTER the one locals/registers directive, BEFORE the
    # first code label, debug directive or instruction. Existing branch labels,
    # exception handlers and coroutine state-machine code remain unchanged.
    reg=directives[0]
    pos=method.find("\n",reg.end())
    require(pos>=0,"REGISTER_DIRECTIVE_END")
    pos+=1
    newmethod=method[:pos]+INSERT+method[pos:]
    new=s[:a]+newmethod+s[b:]
    require(new.replace(INSERT,"",1)==s,"EXACT_ONE_INSTRUCTION_DIFF")
    require(new.count(INSERT.strip())==1,"ONE_INVOKE_ONLY")
    require(len(new)==len(s)+len(INSERT),"NO_OTHER_SMALI_CHANGES")
    return new

def validate_ci():
    require(os.environ.get("GITHUB_ACTIONS")=="true" and
        os.environ.get("GITHUB_REPOSITORY")==REPO and
        os.environ.get("GITHUB_EVENT_NAME")=="pull_request",
        "CI_PR_SCOPE")
    e=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    p=e.get("pull_request") or {}
    h=p.get("head") or {}
    require(p.get("number")==80 and h.get("ref")==BRANCH and
        (h.get("repo") or {}).get("full_name")==REPO,
        "ONLY_EXISTING_PR80_BRANCH")
    require(git("rev-parse","--show-toplevel")==str(Path.cwd().resolve()),
            "REPO_ROOT")
    require(git("remote","get-url","origin").rstrip(".git").endswith(REPO),
            "ORIGIN")
    for var,required in (
        ("P47_NO_HOST_FALLBACK","1"),
        ("P181_THREE_ORIGINAL_START_DENY","1"),
        ("P49_NODE_STAGE","0"),
        ("P51_SIDE_BY_SIDE","0")):
        require(os.environ.get(var, "0")==required,"NO_ENGINE_OR_FALLBACK_"+var)

def run_preparation():
    require(not git("status","--porcelain"),"REPO_MUST_START_CLEAN")
    require(git("hash-object",str(BUILDER))==BUILDER_SHA,
            "PINNED_ORIGINAL_BUILDER_SHA")
    require(JAVA.is_file(),"TEST_MARKER_JAVA_MISSING")
    original=BUILDER.read_text()
    changed=patch_builder(original)
    require(changed!=original,"NO_BUILDER_PATCH")
    BUILDER.write_text(changed)
    require(git("diff","--name-only").splitlines()==[str(BUILDER)],
            "ONLY_TEST_BUILDER_MODIFIED")
    print("P208_ONLY_EPHEMERAL_TEST_BUILDER_PATCHED=PASS")
    print("P208_UNMODIFIED_REAL_MAINACTIVITY_AND_ENGINE_SOURCES=YES")

def run_injection(decoded):
    require(os.environ.get("P208_CI_METHOD_ENTRY_ONLY")=="1",
            "CI_INSTRUMENTATION_DISABLED")
    expected_root=(Path.cwd()/".p43tmp/decoded").resolve()
    require(decoded.resolve()==expected_root and not decoded.is_symlink() and
            decoded.is_dir(),"DISPOSABLE_ORIGINAL_DECODED_ONLY")
    original=(Path.cwd()/".p43tmp/DSH-vc138-P0-OFFLINE-TEST-fixed-signature.apk")
    require(original.is_file(),"SIGNED_ORIGINAL_APK_REQUIRED")
    f=decoded/"smali/com/dsh/android/EngineManager$start$2.smali"
    require(f.is_file() and not f.is_symlink(),"PINNED_ORIGINAL_START_COROUTINE_SMALI_ONLY")
    # Do not touch untouched classes2.dex, native libs or app-owned files.
    unchanged=f.read_text()
    verify_signed_original_coroutine(original)
    changed=patch_original_smali(unchanged)
    f.write_text(changed)
    require(f.read_text().replace(INSERT,"",1)==unchanged,
            "UNEXPECTED_ORIGINAL_METHOD_CHANGE")
    print("P208_CI_ONLY_EXACT_ORIGINAL_START2_ENTRY_MARKER=PASS")
    print("P208_ORIGINAL_START2_TEXT_EXCEPT_ONE_INVOKE=BYTE_IDENTICAL")
    print("P208_P47_DENY_AND_ORIGINAL_BUNDLE_PROTECTED=YES")

def main():
    a=argparse.ArgumentParser()
    group=a.add_mutually_exclusive_group(required=True)
    group.add_argument("--prepare-builder",action="store_true")
    group.add_argument("--inject-smali",type=Path)
    args=a.parse_args()
    try:
        validate_ci()
        if args.prepare_builder:run_preparation()
        else:run_injection(args.inject_smali)
    except Refused as error:
        # Only an allowlisted static refusal label, no private path or data.
        print(str(error),file=sys.stderr)
        sys.exit(2)
    except Exception:
        print("P208_CI_ONLY_UNEXPECTED_PATCH_ERROR",file=sys.stderr)
        sys.exit(2)
if __name__=="__main__":main()
