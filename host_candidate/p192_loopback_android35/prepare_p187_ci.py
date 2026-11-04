#!/usr/bin/env python3
"""P192 CI-only P187 test-probe injection into exact original P43 source blobs.

Run only in GitHub Actions on PR #80 of the one approved branch.
Checks all old P43 blob SHA before changing disposable CI checkout; no APK
publication, user-device access or sensitive tool grants.
"""
import argparse
import hashlib
import pathlib
import subprocess
import sys

REPO = "u2584604327-a11y/dshe"
BRANCH = "dsh/p96-original-engine-stream-owner-narrow-20261030"
WORKER = "host_candidate/p43_original_service/android/com/dsh/android/p43/P43IsolatedWorker.java"
ACTIVITY = "host_candidate/p43_original_service/android/com/dsh/android/p43/P43ProbeActivity.java"
BUILDER = "host_candidate/p43_original_service/build_embedded_emulator_apk.sh"
ADDED = "host_candidate/p187_loopback_capability/src/com/dsh/android/p187/P187LoopbackCapability.java"
BLOBS = {WORKER:"feabcaf30f2458e85a044e0f789bbc31254f3269",
         ACTIVITY:"8a83ef4c53c8e527f604023ab5eec2be8f2e12a9",
         BUILDER:"d9dac2518ffa00833ba47429425657ff479fb28d"}

def git(*args):
    return subprocess.check_output(["git", *args], stderr=subprocess.STDOUT).decode().strip()

def replace_once(content, old, new, name):
    count = content.count(old)
    if count != 1:
        raise RuntimeError("P187_ANCHOR_DRIFT_" + name + "_COUNT_" + str(count))
    return content.replace(old, new)

WORKER_BINDER = '''      // P187: explicit emulator-only, one-shot 127.0.0.1 capability test.
      // Identity relies on framework Message.sendingUid, never a Bundle UID.
      if(message.what==P187_REQUEST) {
        if(!used || p187Used || !android.os.Process.isIsolated() ||
           message.sendingUid!=acceptedHostUid || message.replyTo==null ||
           acceptedSession==null)return;
        try {
          Bundle request=message.getData();
          if(request==null || request.keySet().size()!=1 ||
             !acceptedSession.equals(request.getString("session")))return;
        }catch(RuntimeException invalid){return;}
        p187Used=true;
        final String verifiedSession=acceptedSession;
        final Messenger trustedHost=message.replyTo;
        new Thread(()->{
          try(P187LoopbackCapability.Listener local=P187LoopbackCapability.bind()){
            if(!verifiedSession.equals(acceptedSession))return;
            Message ready=Message.obtain(null,P187_BIND_REPLY);
            Bundle r=new Bundle();
            r.putString("session",verifiedSession);
            r.putInt("port",local.port());
            r.putString("nonce",local.nonceHex());
            ready.setData(r);
            try{trustedHost.send(ready);}catch(RemoteException lost){return;}
            String result=local.acceptOnce();
            if(!verifiedSession.equals(acceptedSession))return;
            Message completed=Message.obtain(null,P187_DONE_REPLY);
            Bundle finalResult=new Bundle();
            finalResult.putString("session",verifiedSession);
            finalResult.putString("status",result);
            completed.setData(finalResult);
            try{trustedHost.send(completed);}catch(RemoteException ignored){}
          }catch(java.io.IOException | SecurityException denied){
            if(!verifiedSession.equals(acceptedSession))return;
            Message rejected=Message.obtain(null,P187_BIND_REPLY);
            Bundle status=new Bundle();
            status.putString("session",verifiedSession);
            status.putString("status",P187LoopbackCapability.failure("BIND",denied));
            rejected.setData(status);
            try{trustedHost.send(rejected);}catch(RemoteException ignored){}
          }
        },"p187-isolated-loopback-only").start();
        return;
      }
'''

HOST_REPLY = '''      // P187: response accepted only from the exact isolated UID that
      // already passed the original P43 host/session/hash handshake.
      if(m.what==P43IsolatedWorker.P187_BIND_REPLY ||
         m.what==P43IsolatedWorker.P187_DONE_REPLY){
        if(!received || failed || !p187Requested || p187Disposed ||
           m.sendingUid!=p187ExpectedUid ||
           !android.os.Process.isIsolatedUid(m.sendingUid))return;
        final Bundle p;
        try{p=m.getData();}catch(RuntimeException invalid){return;}
        if(p==null || !session.equals(p.getString("session")))return;
        if(m.what==P43IsolatedWorker.P187_BIND_REPLY){
          if(p187BindSeen)return;
          final int port=p.getInt("port",-1);
          final String nonce=p.getString("nonce");
          if(port>0 && port<=65535 && nonce!=null &&
             nonce.matches("[0-9a-f]{32}") && p.keySet().size()==3){
            p187BindSeen=true;
            p187ListenOk=true;
            log("P187_ISOLATED_BIND_127001=PASS");
            new Thread(()->{
              String status=P187LoopbackCapability.connect(port,nonce);
              main.post(()->{if(!p187Disposed)
                log("P187_HOST_TO_ISOLATED_CONNECT_127001="+status);});
            },"p187-host-cross-uid-client").start();
          }else if(p.keySet().size()==2 &&
                   P187LoopbackCapability.isValidStatus(p.getString("status"))){
            p187BindSeen=true;
            log("P187_ISOLATED_BIND_127001="+p.getString("status"));
          }
        }else{
          if(!p187ListenOk || p187DoneSeen || p.keySet().size()!=2 ||
             !P187LoopbackCapability.isValidStatus(p.getString("status")))return;
          p187DoneSeen=true;
          log("P187_ISOLATED_ACCEPT_NONCE="+p.getString("status"));
        }
        return;
      }
'''
HOST_START = '''      if("com.dsh.android".equals(getPackageName()) && getIntent()!=null &&
         getIntent().getBooleanExtra("p187_loopback",false)){
        p187Requested=true;
        new Thread(()->{
          String status=P187LoopbackCapability.probeSelf();
          main.post(()->{if(!p187Disposed)
            log("P187_HOST_UID_SELF_LOOPBACK="+status);});
        },"p187-host-self-loopback").start();
        Message request=Message.obtain(null,P43IsolatedWorker.P187_REQUEST);
        Bundle probe=new Bundle();probe.putString("session",session);
        request.setData(probe);request.replyTo=replies;
        try{remote.send(request);}catch(RemoteException bad){
          log("P187_REQUEST_BINDER_SEND=FAILED");
        }
        main.postDelayed(()->{
          if(!p187Disposed && !p187BindSeen)log("P187_ISOLATED_BIND_127001=TIMEOUT");
          else if(!p187Disposed && p187ListenOk && !p187DoneSeen)
            log("P187_ISOLATED_ACCEPT_NONCE=TIMEOUT");
        },5000L);
      }
'''

def patch_worker(s):
    s=replace_once(s,"import com.dsh.android.p76.P76EngineArchiveFdProbe;",
      "import com.dsh.android.p76.P76EngineArchiveFdProbe;\nimport com.dsh.android.p187.P187LoopbackCapability;","worker_import")
    s=replace_once(s,"  public static final int INIT=431, HELLO=432;",
      "  public static final int INIT=431, HELLO=432;\n  public static final int P187_REQUEST=1871,P187_BIND_REPLY=1872,P187_DONE_REPLY=1873;","worker_codes")
    s=replace_once(s,"  private String acceptedSession;","  private volatile String acceptedSession;","worker_session")
    s=replace_once(s,"  private boolean p76ArchiveUsed;","  private boolean p76ArchiveUsed;\n  private boolean p187Used;","worker_single_use")
    s=replace_once(s,"    @Override public void handleMessage(Message message) {\n      if(message.what==P76EngineArchiveFdProbe.TRANSFER){",
      "    @Override public void handleMessage(Message message) {\n"+WORKER_BINDER+"      if(message.what==P76EngineArchiveFdProbe.TRANSFER){","worker_dispatch")
    return s

def patch_activity(s):
    s=replace_once(s,"import com.dsh.android.p156.P156OriginalAppLibProbe;",
      "import com.dsh.android.p156.P156OriginalAppLibProbe;\nimport com.dsh.android.p187.P187LoopbackCapability;","activity_import")
    s=replace_once(s,"  private volatile java.lang.Process p75AuthenticatedProxy;",
      "  private volatile java.lang.Process p75AuthenticatedProxy;\n  private int p187ExpectedUid=-1;\n  private boolean p187Requested,p187BindSeen,p187ListenOk,p187DoneSeen;\n  private volatile boolean p187Disposed;","activity_fields")
    s=replace_once(s,"    @Override public void handleMessage(Message m){\n      if(received||failed)return;",
      "    @Override public void handleMessage(Message m){\n"+HOST_REPLY+"      if(received||failed)return;","activity_reply")
    s=replace_once(s,"      received=true;\n      // Original MainActivity is already launched by the emulator runner.",
      "      received=true;\n      p187ExpectedUid=m.sendingUid;\n"+HOST_START+"      // Original MainActivity is already launched by the emulator runner.","activity_start")
    s=replace_once(s,"  @Override protected void onDestroy(){\n    if(getIntent()!=null",
      "  @Override protected void onDestroy(){\n    p187Disposed=true;\n    if(getIntent()!=null","activity_destroy")
    return s

def patch_builder(s):
    return replace_once(s,
      "  host_candidate/p43_original_service/android/com/dsh/android/p43/P43ProbeActivity.java \\\n",
      "  host_candidate/p43_original_service/android/com/dsh/android/p43/P43ProbeActivity.java \\\n  host_candidate/p187_loopback_capability/src/com/dsh/android/p187/P187LoopbackCapability.java \\\n",
      "builder_java")

def main():
    import json, os
    parser=argparse.ArgumentParser()
    parser.add_argument("--apply-ci",action="store_true")
    args=parser.parse_args()
    if not args.apply_ci:
        raise RuntimeError("P192_REQUIRES_EXPLICIT_APPLY_CI")
    if (os.environ.get("GITHUB_ACTIONS")!="true" or
        os.environ.get("GITHUB_REPOSITORY")!=REPO or
        os.environ.get("GITHUB_EVENT_NAME")!="pull_request"):
        raise RuntimeError("P192_NOT_APPROVED_GITHUB_PR_CI")
    info=json.loads(pathlib.Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    pr=info.get("pull_request") or {}
    if (pr.get("number")!=80 or
        (pr.get("head") or {}).get("ref")!=BRANCH or
        ((pr.get("head") or {}).get("repo") or {}).get("full_name")!=REPO):
        raise RuntimeError("P192_PR_HEAD_REPO_OR_BRANCH_MISMATCH")
    root=pathlib.Path(git("rev-parse","--show-toplevel")).resolve()
    if pathlib.Path.cwd().resolve()!=root or git("status","--porcelain"):
        raise RuntimeError("P192_NOT_CLEAN_REPO_ROOT")
    remote=git("remote","get-url","origin")
    if not (remote.endswith(REPO+".git") or remote.endswith(REPO)):
        raise RuntimeError("P192_WRONG_REPOSITORY_REMOTE")
    if not (root/ADDED).is_file():
        raise RuntimeError("P192_PINNED_JAVA_SOURCE_MISSING")
    import_hash=git("hash-object",ADDED)
    if import_hash!="" and len(import_hash)!=40:
        raise RuntimeError("P192_BAD_JAVA_BLOB")
    old={}
    for name,expected in BLOBS.items():
        file=root/name
        if not file.is_file() or git("hash-object",name)!=expected:
            raise RuntimeError("P192_PINNED_P43_BLOB_CHANGED_"+name)
        old[name]=file.read_text(encoding="utf8")
    update={WORKER:patch_worker(old[WORKER]),
            ACTIVITY:patch_activity(old[ACTIVITY]),
            BUILDER:patch_builder(old[BUILDER])}
    for name,content in update.items():
        (root/name).write_text(content,encoding="utf8")
    changed=git("diff","--name-only").splitlines()
    if set(changed)!=set(BLOBS):
        raise RuntimeError("P192_PATCH_SCOPE_DRIFT")
    print("P192_PINNED_P43_BLOBS_AND_CI_ONLY_SCOPE=PASS")
    print("P192_ORIGINAL_APK_SOURCE_TEMPORARILY_PATCHED_IN_CI=YES")
    print("P192_PUBLIC_REPOSITORY_P43_FILES_UNCHANGED=YES")

if __name__=="__main__":
    try:main()
    except (RuntimeError,subprocess.CalledProcessError,KeyError,ValueError) as exc:
        print("P192_STOP_FAIL_CLOSED",str(exc),file=sys.stderr)
        sys.exit(2)
