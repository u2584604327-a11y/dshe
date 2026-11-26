package com.dsh.android.engine;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.util.*;

/** Validates one bounded virtual namespace, never resolves a host path. */
final class SessionSnapshotCodec {
  static final int MAX_BYTES=20*1024*1024,MAX_DATA=16*1024*1024,MAX_ENTRIES=4096;
  private static final byte[] LEGACY_MAGIC={'D','S','H','F','S','0','0','1'}, LINK_MAGIC={'D','S','H','F','S','0','0','2'};
  private static final class Entry {
    final int type,mode;
    final long time;
    Entry(int type,int mode,long time){this.type=type;this.mode=mode;this.time=time;}
  }
  private SessionSnapshotCodec(){}
  static void validate(byte[] payload)throws IOException{
    if(payload==null||payload.length>MAX_BYTES)throw new IOException("SNAPSHOT_SIZE");
    DataInputStream input=new DataInputStream(new ByteArrayInputStream(payload));
    byte[] magic=new byte[8];input.readFully(magic);
    boolean links=Arrays.equals(magic,LINK_MAGIC);
    if(!links&&!Arrays.equals(magic,LEGACY_MAGIC))throw new IOException("SNAPSHOT_VERSION");
    int count=input.readInt();if(count<2||count>MAX_ENTRIES)throw new IOException("SNAPSHOT_COUNT");
    Map<String,Entry> names=new HashMap<>();long total=0;
    for(int i=0;i<count;i++){
      int length=input.readUnsignedShort();if(length<1||length>4096)throw new IOException("SNAPSHOT_PATH_SIZE");
      String name=readUtf8(input,length);
      if(!(name.equals("/dsh-home")||name.startsWith("/dsh-home/")||name.equals("/dsh-workspace")||name.startsWith("/dsh-workspace/"))||
          name.indexOf('\\')>=0||name.chars().anyMatch(c->c<32||c==127)||name.endsWith("/"))throw new IOException("SNAPSHOT_PATH");
      String[] parts=name.substring(1).split("/",-1);if(parts.length>64)throw new IOException("SNAPSHOT_DEPTH");
      for(String part:parts)if(part.isEmpty()||part.equals(".")||part.equals("..")||part.getBytes(StandardCharsets.UTF_8).length>255)throw new IOException("SNAPSHOT_PATH");
      int type=input.readUnsignedByte(),mode=input.readUnsignedShort();long time=input.readLong();int size=input.readInt();
      if(type>(links?2:1)||(mode&~0700)!=0||time<0||time>9007199254740991L||size<0||
          size>8*1024*1024||(type==1&&size!=0))throw new IOException("SNAPSHOT_ENTRY");
      if(names.containsKey(name))throw new IOException("SNAPSHOT_DUPLICATE");
      if(size>input.available())throw new IOException("SNAPSHOT_DATA");
      if(type==2){
        if(size<1||size>4096)throw new IOException("SNAPSHOT_LINK");
        String target=readUtf8(input,size);
        Entry primary=names.get(target);
        if(primary==null||primary.type!=0||primary.mode!=mode||primary.time!=time||
            !target.startsWith("/"+parts[0]+"/"))throw new IOException("SNAPSHOT_LINK");
      }else{
        total+=size;
        if(total>MAX_DATA)throw new IOException("SNAPSHOT_DATA");
        int remaining=size;
        while(remaining>0){int n=input.skipBytes(remaining);if(n<=0)throw new EOFException("SNAPSHOT_TRUNCATED");remaining-=n;}
      }
      names.put(name,new Entry(type,mode,time));
    }
    if(input.read()!=-1||!directory(names.get("/dsh-home"))||!directory(names.get("/dsh-workspace")))throw new IOException("SNAPSHOT_ROOTS_OR_TRAILING");
    for(String name:names.keySet()){
      int slash=name.lastIndexOf('/');
      if(slash>0&&!directory(names.get(name.substring(0,slash))))throw new IOException("SNAPSHOT_PARENT");
    }
  }

  private static boolean directory(Entry entry){return entry!=null&&entry.type==1;}

  private static String readUtf8(DataInputStream input,int length)throws IOException{
    byte[] encoded=new byte[length];input.readFully(encoded);
    try{
      return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(encoded)).toString();
    }catch(CharacterCodingException bad){throw new IOException("SNAPSHOT_PATH_UTF8");}
  }
}
