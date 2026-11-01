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
import android.os.RemoteException;
/** Isolated UID only; synthetic ping + DENY_ALL; no original Node/tools. */
public final class P120IsolatedDenyService extends Service {
  public static final int PING=12001, PONG=12002;
  private final Messenger inbox=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message incoming){
      if(Build.VERSION.SDK_INT<34)return;
      if(!Process.isIsolated()||!Process.isIsolatedUid(Process.myUid())||
         incoming.sendingUid!=getApplicationInfo().uid||
         incoming.what!=PING||incoming.replyTo==null)return;
      Message output=Message.obtain(null,PONG);
      Bundle result=new Bundle();
      result.putBoolean("isolated",true);
      result.putInt("observedUid",Process.myUid());
      result.putString("toolAccess","DENY_ALL");
      output.setData(result);
      try{incoming.replyTo.send(output);}catch(RemoteException ignored){}
    }
  });
  @Override public IBinder onBind(Intent intent){
    return Build.VERSION.SDK_INT>=34&&Process.isIsolated()&&Process.isIsolatedUid(Process.myUid())
      ?inbox.getBinder():null;
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
