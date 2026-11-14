#!/usr/bin/env python3
"""P291 CI-only cloned P245 repair candidate, NEVER a production gate.

Keeps the SHA-pinned original P245 verifier byte-exact; substitutes precisely
one failing Log.i get_output() string predicate in a disposable verifier copy.
The replacement requires the raw 35c Log.i ID, exact argument registers,
full P285 eleven-factor source/original parity, and either original exact
display or the proved ASCII inter-type separator display. Unknown DENY.
Candidate PASS is not release/ART/ownership approval.
"""
import argparse,hashlib,re,sys
from pathlib import Path
sys.path[:0]=[
 "host_candidate/p246_exception_semantics",
 "host_candidate/p249_dual_diff",
 "host_candidate/p267_invoke_words",
 "host_candidate/p269_method_pool",
 "host_candidate/p281_helper_predicates",
 "host_candidate/p283_descriptor_normalization",
 "host_candidate/p285_shadow_verifier",
 "host_candidate/p287_gate_delta",
 "host_candidate/p289_strict_gate_proposal",
]
from p281_helper_predicates import helper_rows
from p285_shadow_verifier import audit as shadow_audit,FACTORS
from p287_gate_delta import display_shape
from p289_strict_gate_proposal import raw_log_target

ORIGINAL=Path("host_candidate/p245_build_only_probe/p245_build_only_probe.py")
TEMP=Path(".p291tmp/P291-TEMP-P245-VERIFIER-DO-NOT-RELEASE.py")
ORIGINAL_GIT_SHA="06f62f4d8c8ee141b6b2030ee6556c9a43d9e499"
OLD_TEXT='         "Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I" in output,\n'
NEW_TEXT='         p291_strict_log_call(h,base_dex,candidate_dex),\n'
IMPORT_ANCHOR='from p210_optional_node_usability import scope as base_scope,load_dex,method_index,exception_structure,need\n'
IMPORT_ADD='sys.path.insert(0,"host_candidate/p291_candidate_gate")\nfrom p291_candidate_gate import p291_strict_log_call\n'
LOG_TARGET="Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I"

def git_blob_sha(content):
    if type(content) is not bytes:return None
    return hashlib.sha1(b"blob "+str(len(content)).encode()+b"\0"+content).hexdigest()

def make_candidate(content):
    """Single text predicate replacement, with a strictly pinned old blob."""
    if git_blob_sha(content)!=ORIGINAL_GIT_SHA:
        raise ValueError("P291_ORIGINAL_SOURCE_SHA_MISMATCH")
    try:s=content.decode("utf-8")
    except UnicodeError:raise ValueError("P291_ORIGINAL_SOURCE_ENCODING")
    if (s.count(OLD_TEXT)!=1 or s.count(IMPORT_ANCHOR)!=1 or
        "p291_strict_log_call" in s):
        raise ValueError("P291_ONE_ANCHOR_ONLY")
    changed=s.replace(OLD_TEXT,NEW_TEXT,1).replace(
        IMPORT_ANCHOR,IMPORT_ANCHOR+IMPORT_ADD,1)
    if (changed.count(NEW_TEXT)!=1 or changed.count(IMPORT_ADD)!=1 or
        changed.count("P245_STATIC_BUILD_ONLY=PASS")!=1):
        raise ValueError("P291_COPY_INVARIANTS")
    # Exact reversibility and only the two stated textual transformations.
    restored=changed.replace(NEW_TEXT,OLD_TEXT,1).replace(IMPORT_ADD,"",1)
    if restored!=s:raise ValueError("P291_NON_REVERSIBLE")
    compile(changed,str(TEMP),"exec")
    return changed

def p291_strict_log_call(helper,base_dex,candidate_dex):
    """Replacement predicate: additionally demands 11 independent invariants."""
    try:
        rows=helper_rows(helper)
        if rows is None or len(rows)!=14 or rows[10][1]!="invoke-static":
            return False
        raw=raw_log_target(rows[10],candidate_dex)
        required=("RAW_LOG_35C_FORMAT","RAW_LOG_35C_REGISTERS",
                  "RAW_LOG_DEX_OWNER","RAW_LOG_DEX_METHOD",
                  "RAW_LOG_DEX_ARGS","RAW_LOG_DEX_RETURN")
        if set(raw)!=set(required) or not all(raw[x]=="PASS" for x in required):
            return False
        trace=shadow_audit(base_dex,candidate_dex)
        if (type(trace) is not dict or set(trace)!=set(FACTORS) or
            not all(trace[x]=="PASS" for x in FACTORS)):
            return False
        output=rows[10][4]
        if not isinstance(output,str) or len(output)>8192:return False
        return LOG_TARGET in output or display_shape(output)=="PASS"
    except Exception:
        return False

def create_copy():
    if TEMP.exists() or TEMP.is_symlink():
        raise ValueError("P291_TEMP_EXISTS")
    original=ORIGINAL.read_bytes()
    content=make_candidate(original)
    TEMP.parent.mkdir(parents=True,exist_ok=True)
    TEMP.write_bytes(content.encode("utf-8"))
    if (TEMP.is_symlink() or TEMP.read_bytes()!=content.encode("utf-8") or
        git_blob_sha(ORIGINAL.read_bytes())!=ORIGINAL_GIT_SHA):
        raise ValueError("P291_COPY_PARITY")
    print("P291_ORIGINAL_P245_SOURCE=BYTE_EXACT_UNMODIFIED")
    print("P291_TEMP_ONLY_SINGLE_TEXT_PREDICATE_REPLACED=PASS")
    print("P291_CANDIDATE_REVIEW_NOT_RELEASE=YES")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--create-copy",action="store_true")
    a=p.parse_args()
    try:
        if a.create_copy:create_copy()
        else:
            print("P291_SOURCE_ONLY=YES")
            print("P291_CANDIDATE_REAL_DEX=NOT_ATTESTED")
            print("P291_ORIGINAL_P245_GATE=UNMODIFIED")
            print("P291_RELEASE=DENY")
            print("P291_V139=STRUCTURAL_BLOCKED")
    except Exception:
        print("P291_DENY_SOURCE_INTEGRITY_OR_COPY",file=sys.stderr)
        return 2
    return 0

if __name__=="__main__":
    raise SystemExit(main())
