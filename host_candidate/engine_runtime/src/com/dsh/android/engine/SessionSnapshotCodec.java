package com.dsh.android.engine;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.util.*;

/** Validates one bounded virtual namespace, never resolves a host path. */
final class SessionSnapshotCodec {
  static final int MAX_BYTES=20*1024*1024,MAX_DATA=16*1024*1024,MAX_ENTRIES=4096;
  private SessionSnapshotCodec(){}
  static void validate(byte[] payload)throws IOException{
    if(payload==null||payload.length>MAX_BYTES)throw new IOException("SNAPSHOT_SIZE");
    DataInputStream input=new DataInputStream(new ByteArrayInputStream(payload));
    byte[] magic=new byte[8];input.readFully(magic);
    if(!Arrays.equals(magic,new byte[]{'D','S','H','F','S','0','0','1'}))throw new IOException("SNAPSHOT_VERSION");
    int count=input.readInt();if(count<2||count>MAX_ENTRIES)throw new IOException("SNAPSHOT_COUNT");
    Map<String,Boolean> names=new HashMap<>();long total=0;
    for(int i=0;i<count;i++){
      int length=input.readUnsignedShort();if(length<1||length>4096)throw new IOException("SNAPSHOT_PATH_SIZE");
      byte[] encoded=new byte[length];input.readFully(encoded);String name;
      try{name=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(encoded)).toString();}
      catch(CharacterCodingException bad){throw new IOException("SNAPSHOT_PATH_UTF8");}
      if(!(name.equals("/dsh-home")||name.startsWith("/dsh-home/")||name.equals("/dsh-workspace")||name.startsWith("/dsh-workspace/"))||
          name.indexOf('\\')>=0||name.chars().anyMatch(c->c<32||c==127)||name.endsWith("/"))throw new IOException("SNAPSHOT_PATH");
      String[] parts=name.substring(1).split("/",-1);if(parts.length>64)throw new IOException("SNAPSHOT_DEPTH");
      for(String part:parts)if(part.isEmpty()||part.equals(".")||part.equals("..")||part.getBytes(StandardCharsets.UTF_8).length>255)throw new IOException("SNAPSHOT_PATH");
      int type=input.readUnsignedByte(),mode=input.readUnsignedShort();long time=input.readLong();int size=input.readInt();
      if(type>1||(mode&~0700)!=0||time<0||size<0||size>8*1024*1024||(type==1&&size!=0))throw new IOException("SNAPSHOT_ENTRY");
      if(names.put(name,type==1)!=null)throw new IOException("SNAPSHOT_DUPLICATE");
      total+=size;if(total>MAX_DATA||size>input.available())throw new IOException("SNAPSHOT_DATA");
      int remaining=size;while(remaining>0){int n=input.skipBytes(remaining);if(n<=0)throw new EOFException("SNAPSHOT_TRUNCATED");remaining-=n;}
    }
    if(input.read()!=-1||!Boolean.TRUE.equals(names.get("/dsh-home"))||!Boolean.TRUE.equals(names.get("/dsh-workspace")))throw new IOException("SNAPSHOT_ROOTS_OR_TRAILING");
    for(String name:names.keySet()){
      int slash=name.lastIndexOf('/');if(slash>0&&!Boolean.TRUE.equals(names.get(name.substring(0,slash))))throw new IOException("SNAPSHOT_PARENT");
    }
  }
}
