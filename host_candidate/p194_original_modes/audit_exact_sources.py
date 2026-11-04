#!/usr/bin/env python3
"""P194 exact v138 three-mode source contract. SOURCE-ONLY, no APK execution."""
from pathlib import Path
import re
import subprocess

PINNED = {
  "host_candidate/p35_original_engine_spawn_contract.py":
    "ff1b65e7fc915a8b23f363db93659cc221aaa6a0",
  "host_candidate/p47_no_fallback/p47_gate.py":
    "49f0d5d07cf7e8fa1e0323c945ddbb1eed946065",
  "host_candidate/p47_no_fallback/android/com/dsh/android/p47/P47LaunchGate.java":
    "44cd38245dc87b9eff960b15dc520e60a2754c2c",
  "host_candidate/p149_prelaunch_witness/src/com/dsh/android/p149/P149OriginalBuilderWitness.java":
    "997f51b5e61a5422b4823becfc6f969b5815cd0d",
  "host_candidate/p150_original_coroutine/src/com/dsh/android/p150/P150OriginalCoroutineObserver.java":
    "eb28cea66a80700af523921fb12f8011dba6729b",
  "host_candidate/p184_verified_child_receipt/src/com/dsh/android/p68/P184ChildStartReceipt.java":
    "3dac8177db81cb48ec85612b6eb31ff61ed4ee98",
  "host_candidate/p68_android_binder/android/com/dsh/android/p68/P68AndroidBinderIntake.java":
    "14073b42a0e02efe2cd4f32259f5a70e657ae63e",
  "host_candidate/p75_engine_rendezvous/src/com/dsh/android/p75/P75EngineStartRendezvous.java":
    "9a476e4254918c56377f5fe0bd30fea2326b653c",
}
def require(value, label):
    if not value:
        raise SystemExit("P194_SOURCE_CONTRACT_DENIED_" + label)

def src(part):
    matches=[p for p in PINNED if part in p]
    require(len(matches)==1, "SOURCE_AMBIGUITY")
    return Path(matches[0]).read_text("utf8")

def count(haystack, needle, expected=1):
    require(haystack.count(needle)==expected,"COUNT_"+re.sub(r"[^A-Z0-9]+","_",needle.upper())[:50])

def main():
    require(subprocess.check_output(["git","status","--porcelain"],text=True).strip()=="","DIRTY_CHECKOUT")
    for name, sha in PINNED.items():
        require(Path(name).is_file(), "FILE_MISSING")
        actual=subprocess.check_output(["git","hash-object",name],text=True).strip()
        require(actual==sha, "UNEXPECTED_BLOB_"+Path(name).name.replace(".","_").upper())

    original=src("p35_original_engine_spawn_contract.py")
    count(original,"EXPECTED='3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5'")
    count(original,"PC=3912")
    count(original,"3924:'Lcom/dsh/android/EngineManager;->access$setProcess$p('")
    count(original,"4026:'Ljava/util/concurrent/CountDownLatch;->await('")
    count(original,"4674:'Lkotlinx/coroutines/flow/MutableStateFlow;->setValue('")
    count(original,"'original_DSH_runtime_wiring':'NOT_IMPLEMENTED'")

    patch=src("p47_gate.py")
    count(patch,'"probeBoot": ("probeOrDeny", "probeOrDeny")')
    count(patch,'"runDumpConfig": ("configOrDeny", "configOrDeny")')
    count(patch,'m[target]["calls"].count(("invoke-static",TRAMPOLINE))==1')
    count(patch,'("invoke-static",DENY)')
    count(patch,'sum(row["calls"].count(("invoke-virtual",ORIGINAL))',2)
    count(patch,'print("P181_ORIGINAL_V138_THREE_ENGINE_SPAWN_SITES_NO_HOST_EXEC=PASS")')
    gate=src("P47LaunchGate.java")
    for signature in ("public static Process startOrDeny(", "public static Process probeOrDeny(",
                      "public static Process configOrDeny("):
        count(gate,signature)
    for statement in ("validateOriginalStreams(builder,3);",
                      "return secondaryDeny(builder,1);",
                      "return secondaryDeny(builder,2);"):
        count(gate,statement)
    require(gate.count('throw new IOException("P47_ISOLATED_SUPERVISOR_UNAVAILABLE_NO_HOST_FALLBACK");')==2,
            "P47_DEFAULT_DENY_BROKEN")
    require(not re.search(r"\bbuilder\.start\s*\(",gate),"HOST_EXECUTION_IN_DENY_GATE")
    witness=src("P149OriginalBuilderWitness.java")
    count(witness,"public synchronized void matchOnce(")
    count(witness,"MessageDigest.isEqual(tag,fresh)")
    count(witness,"Arrays.fill(key,(byte)0);",2)
    count(witness,"out.writeInt(kind);out.writeLong(sequence);")
    count(witness,"field(out,builder.directory().getPath(),8192);")
    count(witness,"field(out,builder.redirectError().toString(),8192);")
    stack=src("P150OriginalCoroutineObserver.java")
    count(stack,'x.getClassName().equals("com.dsh.android.EngineManager$start$2")')
    count(stack,"isOriginalStack(StackTraceElement[] frames)")
    receipt=src("P184ChildStartReceipt.java")
    count(receipt,"public synchronized boolean consume(")
    count(receipt,"public synchronized void revoke()")
    count(receipt,"process!=exactProcess")
    count(receipt,"expectedOwnerEpoch!=ownerEpoch")
    p68=src("P68AndroidBinderIntake.java")
    count(p68,"int sender=msg.sendingUid;")
    count(p68,"msg.what==P53StartOrder.CHILD_STARTED && p184OwnerEpoch>0")
    p75=src("P75EngineStartRendezvous.java")
    count(p75,"armForVerifiedChildReceipt(")
    count(p75,"authenticatedChildStartedWithReceipt(")
    count(p75,"!p.waiting || p.proxy!=null ||",2)

    print("P194_PINNED_V138_PRIMARY_COROUTINE_AND_LIFECYCLE_SOURCE=PASS")
    print("P194_THREE_DIFFERENT_DEX_P47_TYPED_DENY_ROUTES_SOURCE=PASS")
    print("P194_P149_FULL_BUILDER_HMAC_AND_P184_REAL_UID_RECEIPT_SOURCE=PASS")
    print("P194_SOURCE_CONTRACT=PASS")
    print("P194_REAL_ORIGINAL_DEX_THIS_JOB=NOT_READ")
    print("P194_REAL_ENGINE_MANAGER_HTTP_TOKEN_READY=NOT_WIRED")
if __name__=="__main__":
    main()
