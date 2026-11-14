#!/usr/bin/env python3
"""Pinned exact-v138 P13 -> P120 AXML injection for a DENY-ALL isolated Service.
Laboratory source only: no original Node migration, signing or product release.
"""
import hashlib,struct
from pathlib import Path
from p13_manifest_inject import chunk,strings_from_pool,u32
PREIMAGE="39a825e40aff02cef83944ef40de61e310a4c6912d3a352169637ee72a9a0b5f"
RESULT="a15a5dbe52685787d722694b5051919ff0fda9a50d186ccecbad9b8f710975c2"
SERVICE="com.dsh.p120.P120IsolatedDenyService"
PROCESS=":p120_deny_isolated"
NS="http://schemas.android.com/apk/res/android"
ATTRS={"name":0x01010003,"exported":0x01010010,"process":0x01010011,"isolatedProcess":0x010103a9}
JAVA="""package com.dsh.p120;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.Process;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
/** Isolated UID only; synthetic ping + DENY_ALL; no original Node/tools. */
public final class P120IsolatedDenyService extends Service {
  public static final int PING=12001, PONG=12002;
  public static final int ASSET_PREFIX_FD=12003, ASSET_PREFIX_RECEIPT=12004;
  public static final int FULL_ENGINE_FD=12201, FULL_ENGINE_RECEIPT=12202;
  public static final int FIXED_CHILD_UID_PROBE=12401, FIXED_CHILD_UID_RECEIPT=12402;
  private static final int PREFIX_LIMIT=4096;
  private static final long FULL_ENGINE_BYTES=57724933L;
  private static final long FULL_ENGINE_MAX_BYTES=64L*1024L*1024L;
  private static final String FULL_ENGINE_SHA256=
      "adc7a3aa9eeef64e9155860340731316067b5fe97bc71a3eef6fea1daca504aa";
  private static final String ENGINE_PREFIX_SHA256="9a2cff4e385d679c384ccfab16252e086b7cef8546826807c9a8926b267777fb";
  private final AtomicBoolean assetBusy=new AtomicBoolean(false);
  private final AtomicBoolean childBusy=new AtomicBoolean(false);
  private final Messenger inbox=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message incoming){
      if(Build.VERSION.SDK_INT<34)return;
      if(!Process.isIsolated()||!Process.isIsolatedUid(Process.myUid())||
         incoming.sendingUid!=getApplicationInfo().uid||
         incoming.replyTo==null)return;
      // Type dispatch comes AFTER framework sender-UID verification.
      // A pinned FD request must not be rejected by the legacy PING check.
      if(incoming.what==ASSET_PREFIX_FD){receivePinnedEnginePrefix(incoming);return;}
      if(incoming.what==FULL_ENGINE_FD){receiveFullEngineFd(incoming);return;}
      if(incoming.what==FIXED_CHILD_UID_PROBE){probeFixedIsolatedChild(incoming);return;}
      if(incoming.what!=PING)return;
      Message output=Message.obtain(null,PONG);
      Bundle result=new Bundle();
      result.putBoolean("isolated",true);
      result.putInt("observedUid",Process.myUid());
      result.putString("toolAccess","DENY_ALL");
      output.setData(result);
      try{incoming.replyTo.send(output);}catch(RemoteException ignored){}
    }
  });
  /**
   * Bounded read-only original-APK asset transport proof, NOT executable Node.
   * Host selects the original asset; Binder transmits only an FD. This Service
   * never opens host-private paths and never supplies the model any raw bytes.
   */
  private static void sendAssetStatus(Messenger receiver,String code){
    Message receipt=Message.obtain(null,ASSET_PREFIX_RECEIPT);
    Bundle result=new Bundle();
    result.putString("assetPrefix",code);
    result.putString("toolAccess","DENY_ALL");
    receipt.setData(result);
    try{receiver.send(receipt);}catch(RemoteException ignored){}
  }
  private void receivePinnedEnginePrefix(Message request){
    final Messenger receiver=request.replyTo;
    ParcelFileDescriptor input=null;
    try{
      Bundle bundle=request.getData();
      bundle.setClassLoader(ParcelFileDescriptor.class.getClassLoader());
      input=(ParcelFileDescriptor)bundle.getParcelable("engine_fd");
    }catch(RuntimeException malformed){
      if(input!=null)try{input.close();}catch(Exception ignored){}
      sendAssetStatus(receiver,"REJECTED_BAD_FD_NO_EXEC");
      return;
    }
    if(input==null){
      sendAssetStatus(receiver,"REJECTED_BAD_FD_NO_EXEC");
      return;
    }
    if(!assetBusy.compareAndSet(false,true)){
      try{input.close();}catch(Exception ignored){}
      sendAssetStatus(receiver,"REJECTED_BUSY_NO_EXEC");
      return;
    }
    final ParcelFileDescriptor fd=input;
    final Handler main=new Handler(Looper.getMainLooper());
    final AtomicBoolean answered=new AtomicBoolean(false);
    final Runnable timeout=()->{
      try{fd.close();}catch(Exception ignored){}
      if(answered.compareAndSet(false,true))
        sendAssetStatus(receiver,"REJECTED_TIMEOUT_NO_EXEC");
    };
    main.postDelayed(timeout,5000);
    Thread checker=new Thread(()->{
      boolean valid=false;
      try(InputStream source=new ParcelFileDescriptor.AutoCloseInputStream(fd)){
        byte[] buffer=new byte[PREFIX_LIMIT];
        int count=0;
        while(count<PREFIX_LIMIT){
          int n=source.read(buffer,count,PREFIX_LIMIT-count);
          if(n<0)break;
          if(n==0)continue;
          count+=n;
        }
        if(count==PREFIX_LIMIT){
          byte[] digest=MessageDigest.getInstance("SHA-256").digest(buffer);
          StringBuilder hex=new StringBuilder(64);
          for(byte b:digest)hex.append(String.format(java.util.Locale.ROOT,"%02x",b&255));
          valid=ENGINE_PREFIX_SHA256.equals(hex.toString());
        }
      }catch(Exception rejected){
        // Fail closed and never log input contents, errors, paths or tokens.
      }finally{
        main.removeCallbacks(timeout);
        assetBusy.set(false);
        if(answered.compareAndSet(false,true))
          sendAssetStatus(receiver,
            valid?"PINNED_4096_SHA256_MATCH_NO_EXEC":"REJECTED_NO_EXEC");
      }
    },"p121-pinned-engine-fd-only");
    checker.setDaemon(true);
    checker.start();
  }
  /** Original full engine.bin source, fixed-byte content-addressed FD proof.
   * This worker never executes Node, unpacks tar, writes files or grants tools.
   * Memory O(64 KiB). No arbitrary names, paths or caller-supplied hashes.
   */
  private static void replyFullEngine(Messenger recipient,String status){
    Message reply=Message.obtain(null,FULL_ENGINE_RECEIPT);
    Bundle result=new Bundle();
    result.putString("fullEngine",status);
    result.putString("toolAccess","DENY_ALL");
    reply.setData(result);
    try{recipient.send(reply);}catch(RemoteException ignored){}
  }
  private void receiveFullEngineFd(Message request){
    final Messenger recipient=request.replyTo;
    ParcelFileDescriptor handle=null;
    try{
      Bundle args=request.getData();
      args.setClassLoader(ParcelFileDescriptor.class.getClassLoader());
      handle=(ParcelFileDescriptor)args.getParcelable("engine_fd");
    }catch(RuntimeException invalid){
      if(handle!=null)try{handle.close();}catch(Exception ignored){}
      replyFullEngine(recipient,"REJECTED_BAD_FD_NO_EXEC");
      return;
    }
    if(handle==null){
      replyFullEngine(recipient,"REJECTED_BAD_FD_NO_EXEC");return;
    }
    if(!assetBusy.compareAndSet(false,true)){
      try{handle.close();}catch(Exception ignored){}
      replyFullEngine(recipient,"REJECTED_BUSY_NO_EXEC");
      return;
    }
    final ParcelFileDescriptor fd=handle;
    final AtomicBoolean answered=new AtomicBoolean(false);
    final Handler handler=new Handler(Looper.getMainLooper());
    final Runnable timeout=()->{
      try{fd.close();}catch(Exception ignored){}
      if(answered.compareAndSet(false,true))
        replyFullEngine(recipient,"REJECTED_TIMEOUT_NO_EXEC");
    };
    handler.postDelayed(timeout,60000L);
    Thread worker=new Thread(()->{
      boolean accepted=false;
      try(InputStream stream=new ParcelFileDescriptor.AutoCloseInputStream(fd)){
        MessageDigest sha=MessageDigest.getInstance("SHA-256");
        byte[] chunk=new byte[65536];
        long total=0L;
        int read;
        while((read=stream.read(chunk))!=-1){
          if(read==0)continue;
          total+=read;
          if(total>FULL_ENGINE_MAX_BYTES)break;
          sha.update(chunk,0,read);
        }
        if(total==FULL_ENGINE_BYTES){
          byte[] digest=sha.digest();
          StringBuilder hex=new StringBuilder(64);
          for(byte b:digest)hex.append(String.format(
              java.util.Locale.ROOT,"%02x",b&255));
          accepted=FULL_ENGINE_SHA256.equals(hex.toString());
        }
      }catch(Exception rejected){
        // No paths, original file contents or throwable messages in logs.
      }finally{
        handler.removeCallbacks(timeout);
        assetBusy.set(false);
        if(answered.compareAndSet(false,true))
          replyFullEngine(recipient,accepted
              ?"PINNED_FULL_ENGINE_SHA256_MATCH_NO_EXEC":"REJECTED_CONTENT_NO_EXEC");
      }
    },"p122-original-full-engine-fd-hash");
    worker.setDaemon(true);
    worker.start();
  }

  /** P124: executable-domain capability probe in the actual original-host
   * isolated UID. Fixed Android system /system/bin/id -u only, no user/model
   * input, no shell, no APK executable or third-party libraries, no tools.
   * Never pass a caller-controlled command, path, environment or argument.
   */
  private static void replyFixedChild(Messenger recipient,String result,int uid){
    Message reply=Message.obtain(null,FIXED_CHILD_UID_RECEIPT);
    Bundle data=new Bundle();
    data.putString("isolatedChild",result);
    data.putInt("observedChildUid",uid);
    data.putString("toolAccess","DENY_ALL");
    reply.setData(data);
    try{recipient.send(reply);}catch(RemoteException ignored){}
  }
  private void probeFixedIsolatedChild(Message request){
    final Messenger receiver=request.replyTo;
    if(!childBusy.compareAndSet(false,true)){
      replyFixedChild(receiver,"REJECTED_BUSY_NO_TOOLS",-1);
      return;
    }
    Thread worker=new Thread(()->{
      java.lang.Process child=null;
      boolean matched=false;
      int childUid=-1;
      try{
        ProcessBuilder builder=new ProcessBuilder("/system/bin/id","-u");
        // Do not inherit arbitrary environment values or secrets.
        builder.environment().clear();
        builder.environment().put("PATH","/system/bin");
        builder.environment().put("ANDROID_ROOT","/system");
        builder.environment().put("ANDROID_DATA","/data");
        child=builder.start();
        boolean exited=child.waitFor(5,TimeUnit.SECONDS);
        if(exited&&child.exitValue()==0){
          byte[] small=new byte[24];
          try(InputStream stdout=child.getInputStream()){
            int n=stdout.read(small);
            if(n>0&&n<small.length){
              String value=new String(small,0,n,StandardCharsets.US_ASCII).trim();
              if(value.matches("[0-9]{1,10}")){
                childUid=Integer.parseInt(value);
                matched=Process.isIsolatedUid(childUid)&&childUid==Process.myUid();
              }
            }
          }
        }
      }catch(Exception denied){
        // No host path, environment, stdout/stderr, exception or stack trace in logs.
      }finally{
        if(child!=null){
          child.destroyForcibly();
          try{child.getInputStream().close();}catch(Exception ignored){}
          try{child.getErrorStream().close();}catch(Exception ignored){}
          try{child.getOutputStream().close();}catch(Exception ignored){}
        }
        childBusy.set(false);
        replyFixedChild(receiver,matched
            ?"FIXED_ANDROID_ID_CHILD_SAME_ISOLATED_UID_NO_TOOLS"
            :"REJECTED_CHILD_EXEC_OR_UID_NO_TOOLS",
            matched?childUid:-1);
      }
    },"p124-fixed-android-system-id-uid-only");
    worker.setDaemon(true);
    worker.start();
  }

  @Override public IBinder onBind(Intent intent){
    return Build.VERSION.SDK_INT>=34&&Process.isIsolated()&&Process.isIsolatedUid(Process.myUid())
      ?inbox.getBinder():null;
  }
  @Override public void onDestroy(){
    super.onDestroy();
  }
}
"""
def parts(b):
    p=8
    while p<len(b):
        typ,h,s=chunk(b,p)
        yield p,typ,h,s
        p+=s
    if p!=len(b):raise ValueError("CHUNK_SIZE_MISMATCH")
def patched_manifest(b):
    if hashlib.sha256(b).hexdigest()!=PREIMAGE:raise ValueError("P13_MANIFEST_PREIMAGE_MISMATCH")
    if chunk(b,0)!=(3,8,len(b)):raise ValueError("ROOT_LAYOUT_UNEXPECTED")
    ss=strings_from_pool(b)
    original=list(parts(b))
    if SERVICE in ss or PROCESS in ss:raise ValueError("SERVICE_ALREADY_PRESENT")
    poollen=chunk(b,8)[2]
    maps=[v for v in original if v[1]==0x180]
    if len(maps)!=1 or maps[0][0]!=8+poollen:raise ValueError("RESOURCE_MAP_POSITION")
    mp,_,_,msize=maps[0]
    oldids=list(struct.unpack_from("<"+"I"*((msize-8)//4),b,mp+8))
    for k,v in ATTRS.items():
        if k in ss and ss.index(k)<len(oldids) and oldids[ss.index(k)]!=v:
            raise ValueError("FRAMEWORK_RESOURCE_ID_MISMATCH_"+k)
    if NS not in ss:raise ValueError("MISSING_ANDROID_NAMESPACE")
    add=[v for v in ["process","isolatedProcess",SERVICE,PROCESS] if v not in ss]
    newss=ss+add
    idx={v:i for i,v in enumerate(newss)}
    oldpool=b[8:8+poollen]
    start=28+4*len(ss)
    if u32(oldpool,20)!=start:raise ValueError("POOL_LAYOUT_UNEXPECTED")
    dat=bytearray(oldpool[start:])
    offsets=list(struct.unpack_from("<"+"I"*len(ss),oldpool,28))
    for v in add:
        units=len(v.encode("utf-16le"))//2
        if units>=0x8000:raise ValueError("OVERLONG_NEW_STRING")
        offsets.append(len(dat))
        dat+=struct.pack("<H",units)+v.encode("utf-16le")+b"\0\0"
    dat+=b"\0"*(-len(dat)%4)
    pool=bytearray(oldpool[:28])
    struct.pack_into("<I",pool,8,len(newss))
    struct.pack_into("<I",pool,20,28+4*len(newss))
    pool+=struct.pack("<"+"I"*len(offsets),*offsets)+dat
    struct.pack_into("<I",pool,4,len(pool))
    ids=oldids+[0]*max(0,len(newss)-len(oldids))
    for k,v in ATTRS.items():ids[idx[k]]=v
    mapblob=bytearray(b[mp:mp+8])+struct.pack("<"+"I"*len(ids),*ids)
    struct.pack_into("<I",mapblob,4,len(mapblob))
    stack=[]
    insert=None
    services=0
    for p,t,h,s in original:
        if t==0x102:
            nm=ss[u32(b,p+20)]
            stack.append(nm)
            if nm=="service":services+=1
        elif t==0x103:
            if not stack or ss[u32(b,p+20)]!=stack.pop():raise ValueError("BAD_XML_NESTING")
            if ss[u32(b,p+20)]=="application":
                if insert is not None or stack!=["manifest"]:raise ValueError("UNEXPECTED_APPLICATION")
                insert=p
    if stack or services!=2 or insert is None:raise ValueError("UNEXPECTED_COMPONENTS")
    def attr(name,typ,value,raw=0xffffffff):
        return struct.pack("<IIIHBBI",idx[NS],idx[name],raw,8,0,typ,value)
    attrblob=b"".join((
        attr("name",3,idx[SERVICE],idx[SERVICE]),
        attr("exported",0x12,0),
        attr("process",3,idx[PROCESS],idx[PROCESS]),
        attr("isolatedProcess",0x12,1)))
    startblob=struct.pack("<HHI",0x102,16,36+len(attrblob))
    startblob+=struct.pack("<II",0,0xffffffff)
    startblob+=struct.pack("<IIHHHHHH",0xffffffff,idx["service"],20,20,4,0,0,0)+attrblob
    endblob=struct.pack("<HHI",0x103,16,24)
    endblob+=struct.pack("<IIII",0,0xffffffff,0xffffffff,idx["service"])
    out=bytearray(b[:8]+pool+mapblob+b[mp+msize:insert]+startblob+endblob+b[insert:])
    struct.pack_into("<I",out,4,len(out))
    out=bytes(out)
    if hashlib.sha256(out).hexdigest()!=RESULT:raise AssertionError("P120_MANIFEST_HASH_MISMATCH")
    if strings_from_pool(out)!=newss:raise AssertionError("P120_POOL_FAILURE")
    origchunks=[b[p:p+s] for p,t,h,s in original if t not in (1,0x180)]
    newchunks=[out[p:p+s] for p,t,h,s in parts(out) if t not in (1,0x180)]
    n=sum(1 for p,t,h,s in original if t not in (1,0x180) and p<insert)
    if newchunks!=origchunks[:n]+[startblob,endblob]+origchunks[n:]:
        raise AssertionError("OLD_AXML_CHUNKS_MUTATED")
    return out
if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("p13_manifest")
    parser.add_argument("--out",required=True)
    parser.add_argument("--java",required=True)
    args=parser.parse_args()
    out=patched_manifest(Path(args.p13_manifest).read_bytes())
    Path(args.out).write_bytes(out)
    file=Path(args.java)
    file.parent.mkdir(parents=True,exist_ok=True)
    file.write_text(JAVA)
    print("P120_PINNED_P13_TO_ISOLATED_MANIFEST=PASS")
    print("P120_REAL_OS_ISOLATED_NODE=NOT_PROVEN")
