#!/usr/bin/env python3
"""P238: read-only SHA-pinned original EngineManager$start$2 receiver provenance.

Decide whether a future *disposable only* existing PC176 marker could observe
a captured EngineManager via an equal-width p0 argument. This NEVER edits DEX,
reads runtime state, inserts a marker or attests PC202/PC214 branch outcomes.
Outputs are fixed enums; no field names, register contents or user data.
"""
import argparse
import hashlib
from pathlib import Path
import re
import zipfile

SIGNED_SHA = "3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5"
START = "Lcom/dsh/android/EngineManager$start$2;"
ENGINE = "Lcom/dsh/android/EngineManager;"
DESC = "(Ljava/lang/Object;)Ljava/lang/Object;"
GETTER = ENGINE+"->access$getProcess$p("

class Denied(Exception):
    pass

def require(ok, code):
    if not ok:
        raise Denied("P238_SIGNED_CAPTURE_DENY_"+code)

def capture_verdict(descriptors, pc182_output):
    """Pure conservative classifier. No inference from class name alone."""
    nums = sum(d == ENGINE for d in descriptors)
    count_band = "NONE" if nums == 0 else "ONE" if nums == 1 else "MULTIPLE"
    output = "".join(pc182_output.split())
    # PC182 must load EngineManager from the live coroutine receiver p0.
    observed = (nums == 1 and
                re.search(r"^v[0-9]+,p0,"+re.escape(START)+
                          r"->[^,]+", output) is not None and
                ENGINE in output)
    return count_band, "CANDIDATE" if observed else "NOT_ATTESTED"

def signed_audit(apk):
    from androguard.core.dex import DEX
    path = Path(apk)
    require(path.is_file() and not path.is_symlink(), "PINNED_FILE")
    require(hashlib.sha256(path.read_bytes()).hexdigest() == SIGNED_SHA,
            "SIGNED_SHA_DRIFT")
    with zipfile.ZipFile(path) as z:
        require(z.testzip() is None, "ZIP_INTEGRITY")
        names = sorted(n for n in z.namelist()
                       if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex", n))
        require(names == ["classes.dex","classes2.dex"], "DEX_SET")
        dex = DEX(z.read("classes.dex"))
    classes = [c for c in dex.get_classes() if c.get_name() == START]
    require(len(classes) == 1, "ONE_START2_CLASS")
    cls = classes[0]
    fields = ["".join(f.get_descriptor().split()) for f in cls.get_fields()]
    methods = [m for m in cls.get_methods()
               if m.get_name() == "invokeSuspend" and
               "".join(m.get_descriptor().split()) == DESC]
    require(len(methods) == 1 and methods[0].get_code() is not None,
            "ONE_INVOKE_SUSPEND")
    m = methods[0]
    code = m.get_code()
    require(not (m.get_access_flags() & 0x8) and code.get_ins_size() == 2,
            "COROUTINE_THIS_AND_RESUME_ARG")
    instructions = dict(m.get_instructions_idx())
    require(all(i in instructions for i in (176,182,194,202,214,250,3912)),
            "REQUIRED_ORIGINAL_PC")
    pc176,pc182,pc194 = (instructions[i] for i in (176,182,194))
    require(pc176.get_name() == "invoke-static/range" and
            "Lkotlin/ResultKt;->throwOnFailure(" in
                "".join(pc176.get_output().split()) and
            176+pc176.get_length() == 182 and
            pc182.get_name() == "iget-object" and
            pc194.get_name().startswith("invoke-") and
            GETTER in "".join(pc194.get_output().split()),
            "PC176_182_194_SHAPE")
    for pc,op in ((202,"if-eqz"),(214,"if-ne")):
        ins=instructions[pc]
        require(ins.get_name() == op and pc+2*ins.get_ref_off() == 250,
                "ORIGINAL_PC202_214_TARGETS")
    kind,provenance = capture_verdict(fields,pc182.get_output())
    print("P238_SIGNED_V138_SHA_AND_START2_SIGNATURE=PASS")
    print("P238_PC176_182_194_202_214_PINNED=PASS")
    print("P238_ORIGINAL_COROUTINE_RECEIVER_P0=PASS")
    print("P238_DIRECT_ENGINE_CAPTURE_FIELD="+kind)
    print("P238_PC182_ENGINE_FROM_COROUTINE_P0="+provenance)
    print("P238_SAME_WIDTH_MARKER_REWRITE=NOT_ATTEMPTED")
    print("P238_BRANCH_OPCODE_WIDTH_TARGET_PARITY=REQUIRED_BEFORE_RUNTIME")
    print("P238_ENGINE_PROCESS_FIELD_RUNTIME_VALUE=NOT_ATTESTED")
    print("P238_PC202_PC214_DYNAMIC_BRANCH=NOT_ATTESTED")
    print("P238_ORIGINAL_APK_DEX_AND_USER_DATA_MODIFIED=NO")
    print("P238_V139_RELEASE=STRUCTURAL_BLOCKED")
    print("P238_READONLY_SIGNED_COROUTINE_CAPTURE_AUDIT=PASS")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("original_signed_v138")
    args=p.parse_args()
    try:
        signed_audit(args.original_signed_v138)
    except Denied as e:
        print(str(e))
        return 2
    except Exception:
        print("P238_SIGNED_CAPTURE_DENY_UNEXPECTED")
        return 2
    return 0

if __name__=="__main__":
    raise SystemExit(main())
