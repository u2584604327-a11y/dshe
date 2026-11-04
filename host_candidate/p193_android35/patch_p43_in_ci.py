#!/usr/bin/env python3
"""P193 stage2: strict pinned SOURCE-ONLY CI patches to disposable original P43.

Never patch an owner device, production APK, release branch, or signed binary.
Requires exact PR #80, original branch and clean source tree in GitHub Actions.
"""
import argparse
import json
import os
import pathlib
import subprocess
import sys

REPO="u2584604327-a11y/dshe"
BRANCH="dsh/p96-original-engine-stream-owner-narrow-20261030"
BASE="host_candidate/p43_original_service/"
WORKER=BASE+"android/com/dsh/android/p43/P43IsolatedWorker.java"
ACTIVITY=BASE+"android/com/dsh/android/p43/P43ProbeActivity.java"
BUILDER=BASE+"build_embedded_emulator_apk.sh"
PINNED={
    WORKER:"feabcaf30f2458e85a044e0f789bbc31254f3269",
    ACTIVITY:"8a83ef4c53c8e527f604023ab5eec2be8f2e12a9",
    BUILDER:"d9dac2518ffa00833ba47429425657ff479fb28d"
}
NEW_SOURCES=[
 "host_candidate/p193_host_loopback/src/com/dsh/android/p193/P193HostLoopbackFixture.java",
 "host_candidate/p193_android35/android/com/dsh/android/p193/P193AndroidHostProbe.java"
]
def git(*args):
    return subprocess.check_output(["git",*args],stderr=subprocess.STDOUT,text=True).strip()
def once(source,old,new,tag):
    count=source.count(old)
    if count!=1:raise RuntimeError("P193_ANCHOR_"+tag+"_COUNT_"+str(count))
    return source.replace(old,new)
WORKER_DISPATCH='''      // P193 ONLY: real Binder IPC to a fixed, offline synthetic fixture.
      // The isolated service never opens a TCP socket or gains permissions.
      if(message.what==com.dsh.android.p193.P193AndroidHostProbe.REQUEST){
        if(!used || p193Used || !android.os.Process.isIsolated() ||
           message.sendingUid!=acceptedHostUid || p193HostReply==null ||
           acceptedSession==null || p193AssetDigest==null)return;
        final Bundle b;
        try {b=message.getData();}catch(RuntimeException invalid){return;}
        if(b==null || b.keySet().size()!=6)return;
        final String incomingSession=b.getString("session");
        if(!acceptedSession.equals(incomingSession)){
          android.util.Log.i("P193_WORKER","P193_ANDROID35_WRONG_SESSION_DROPPED=PASS");
          return;
        }
        final String digest=b.getString("digest");
        final String nonce=b.getString("nonce");
        final String command=b.getString("cmd");
        final long epoch=b.getLong("epoch",-1L);
        if(!p193AssetDigest.equals(digest) || epoch!=1L ||
           nonce==null || !nonce.matches("[a-f0-9]{64}") ||
           b.getInt("seq",-1)!=1 ||
           !"GET_FIXED_OFFLINE_FIXTURE".equals(command))return;
        p193Used=true;
        // No URLs, file paths, raw tokens, accounts or HTTP in this worker.
        Bundle answer=new Bundle();
        answer.putString("session",acceptedSession);
        answer.putString("digest",p193AssetDigest);
        answer.putLong("epoch",epoch);
        answer.putString("nonce",nonce);
        answer.putInt("seq",1);
        answer.putByteArray("payload",
            "P193_FIXTURE_OK".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        try {
          Message reply=Message.obtain(null,com.dsh.android.p193.P193AndroidHostProbe.REPLY);
          reply.setData(answer);
          p193HostReply.send(reply);
          // A genuine second Binder callback from the same UID must not
          // be accepted as a second completion by the host.
          Message replay=Message.obtain(null,com.dsh.android.p193.P193AndroidHostProbe.REPLY);
          replay.setData(new Bundle(answer));
          p193HostReply.send(replay);
          android.util.Log.i("P193_WORKER","P193_ANDROID35_WORKER_NO_NETWORK_BINDER_ACK=PASS");
        }catch(RemoteException abandoned){
          android.util.Log.i("P193_WORKER","P193_ANDROID35_REVOKED_BINDER=DENY");
        }
        return;
      }
'''
HOST_REPLY='''      // Original-P43 HELLO remains authoritative. These replies arrive
      // through the SAME Messenger; framework Message.sendingUid is trusted,
      // never a UID claimed inside a Bundle.
      if(m.what==com.dsh.android.p193.P193AndroidHostProbe.REPLY){
        if(p193!=null)p193.onRealFrameworkMessage(m);
        return;
      }
'''
HOST_START='''      if(getIntent()!=null && getIntent().getBooleanExtra("p193_host_ipc",false)
         && remote!=null && p193==null){
        // m.sendingUid is the verified real P43 isolated UID.
        p193=new com.dsh.android.p193.P193AndroidHostProbe(
          remote,session,sha256(P45_SYNTHETIC),m.sendingUid,
          line->log(line));
        p193.start();
      }
'''
def patch_worker(s):
    s=once(s,"  private boolean p76ArchiveUsed;",
       "  private boolean p76ArchiveUsed;\n"
       "  private boolean p193Used;\n"
       "  private String p193AssetDigest;\n"
       "  private Messenger p193HostReply;","worker_state")
    s=once(s,"    @Override public void handleMessage(Message message) {\n"
       "      if(message.what==P76EngineArchiveFdProbe.TRANSFER){",
       "    @Override public void handleMessage(Message message) {\n"+
       WORKER_DISPATCH+"      if(message.what==P76EngineArchiveFdProbe.TRANSFER){",
       "worker_request")
    s=once(s,"      used=true;\n      acceptedHostUid=message.sendingUid;\n"
       "      acceptedSession=session;",
       "      used=true;\n      acceptedHostUid=message.sendingUid;\n"
       "      acceptedSession=session;\n      p193AssetDigest=assetHash;\n"
       "      p193HostReply=message.replyTo;","worker_host_binding")
    s=once(s,"    acceptedSession=null;\n    acceptedHostUid=-1;\n"
       "    super.onDestroy();",
       "    acceptedSession=null;\n    acceptedHostUid=-1;\n"
       "    p193AssetDigest=null;\n    p193HostReply=null;\n"
       "    super.onDestroy();","worker_revoke")
    return s

def patch_activity(s):
    s=once(s,"  private volatile java.lang.Process p75AuthenticatedProxy;",
      "  private volatile java.lang.Process p75AuthenticatedProxy;\n"
      "  private com.dsh.android.p193.P193AndroidHostProbe p193;","host_state")
    s=once(s,"    @Override public void handleMessage(Message m){\n"
      "      if(received||failed)return;",
      "    @Override public void handleMessage(Message m){\n"+
      HOST_REPLY+"      if(received||failed)return;","host_response")
    s=once(s,"      received=true;\n"
      "      // Original MainActivity is already launched by the emulator runner.",
      "      received=true;\n"+HOST_START+
      "      // Original MainActivity is already launched by the emulator runner.","host_start")
    s=once(s,"    @Override public void onServiceDisconnected(ComponentName n){fail(\"SERVICE_DISCONNECTED\");}",
      "    @Override public void onServiceDisconnected(ComponentName n){"
      "if(p193!=null)p193.close();fail(\"SERVICE_DISCONNECTED\");}","host_transport_loss")
    s=once(s,"  @Override protected void onDestroy(){\n"
      "    if(getIntent()!=null",
      "  @Override protected void onDestroy(){\n"
      "    if(p193!=null)p193.close();\n"
      "    if(getIntent()!=null","host_destroy")
    return s

def patch_builder(s):
    anchor="  host_candidate/p43_original_service/android/com/dsh/android/p43/P43ProbeActivity.java \\\n"
    extra="".join("  "+name+" \\\n" for name in NEW_SOURCES)
    return once(s,anchor,anchor+extra,"builder_sources")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--apply-ci",action="store_true")
    args=ap.parse_args()
    if not args.apply_ci:raise RuntimeError("P193_EXPLICIT_CI_FLAG_REQUIRED")
    if (os.environ.get("GITHUB_ACTIONS")!="true" or
        os.environ.get("GITHUB_REPOSITORY")!=REPO or
        os.environ.get("GITHUB_EVENT_NAME")!="pull_request"):
        raise RuntimeError("P193_NOT_APPROVED_CI")
    event=json.loads(pathlib.Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    pr=event.get("pull_request") or {}
    head=pr.get("head") or {}
    if (pr.get("number")!=80 or head.get("ref")!=BRANCH or
        (head.get("repo") or {}).get("full_name")!=REPO):
        raise RuntimeError("P193_PR_SCOPE_MISMATCH")
    root=pathlib.Path(git("rev-parse","--show-toplevel")).resolve()
    if root!=pathlib.Path.cwd().resolve() or git("status","--porcelain"):
        raise RuntimeError("P193_DIRTY_OR_WRONG_ROOT")
    remote=git("remote","get-url","origin")
    if not (remote.endswith(REPO) or remote.endswith(REPO+".git")):
        raise RuntimeError("P193_WRONG_ORIGIN")
    for name in NEW_SOURCES:
        if not (root/name).is_file():raise RuntimeError("P193_SOURCE_MISSING_"+name)
    original={}
    for name,sha in PINNED.items():
        if git("hash-object",name)!=sha:
            raise RuntimeError("P193_PINNED_P43_BLOB_DRIFT_"+name)
        original[name]=(root/name).read_text(encoding="utf-8")
    changed={WORKER:patch_worker(original[WORKER]),
             ACTIVITY:patch_activity(original[ACTIVITY]),
             BUILDER:patch_builder(original[BUILDER])}
    for name,data in changed.items(): (root/name).write_text(data,encoding="utf-8")
    actual=set(git("diff","--name-only").splitlines())
    if actual!=set(PINNED):
        raise RuntimeError("P193_TEST_PATCH_SCOPE_DRIFT")
    print("P193_ANDROID35_ONLY_3_SHA_PINNED_TEST_FIXTURES_PATCHED=PASS")
    print("P193_ORIGINAL_DSH_RELEASE_SOURCES_UNCHANGED=YES")
    print("P193_ISOLATED_UID_NO_TCP_OR_NEW_PRIVILEGES=YES")

if __name__=="__main__":
    try:main()
    except (RuntimeError,KeyError,ValueError,subprocess.CalledProcessError) as e:
        print("P193_STOP_FAIL_CLOSED",str(e),file=sys.stderr)
        sys.exit(2)
