package com.dsh.android.p153;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * ELF-only read-only inspector. Never loads, maps, launches or executes Node.
 * No file contents, paths, raw PT_INTERP or stack traces are returned.
 */
public final class P153ElfHeader {
  private static final long MAX_FILE=128L*1024L*1024L;
  private P153ElfHeader(){}

  private static int u16(byte[] b,int offset,boolean little){
    int a=b[offset]&255,c=b[offset+1]&255;
    return little?(a|(c<<8)):((a<<8)|c);
  }
  private static long u32(byte[] b,int offset,boolean little){
    long a=b[offset]&255L,c=b[offset+1]&255L,
         d=b[offset+2]&255L,e=b[offset+3]&255L;
    return little?(a|(c<<8)|(d<<16)|(e<<24)):
        ((a<<24)|(c<<16)|(d<<8)|e);
  }
  private static long u64(byte[] b,int offset,boolean little){
    long lo=little?u32(b,offset,true):u32(b,offset+4,false);
    long hi=little?u32(b,offset+4,true):u32(b,offset,false);
    if(hi>0x7fffffffL)return -1;
    return (hi<<32)|lo;
  }
  private static String machine(int id){
    switch(id){
      case 183:return "AARCH64";
      case 62:return "X86_64";
      case 40:return "ARM";
      case 3:return "X86";
      default:return "OTHER";
    }
  }
  private static int abiMachine(String abi){
    if("arm64-v8a".equals(abi))return 183;
    if("x86_64".equals(abi))return 62;
    if("armeabi-v7a".equals(abi))return 40;
    if("x86".equals(abi))return 3;
    return -1;
  }
  private static String linkCategory(byte[] b){
    int end=-1;
    for(int i=0;i<b.length;i++)if(b[i]==0){end=i;break;}
    if(end<1)return "INTERP_UNTERMINATED_OR_EMPTY";
    for(int i=0;i<end;i++)if((b[i]&255)>127)return "INTERP_NONASCII_REDACTED";
    String value=new String(b,0,end,StandardCharsets.US_ASCII);
    if("/system/bin/linker64".equals(value))return "ANDROID_LINKER64";
    if("/system/bin/linker".equals(value))return "ANDROID_LINKER32";
    return "INTERP_OTHER_REDACTED";
  }
  private static String check(File node,String abi){
    if(node==null||!node.isFile())return "NODE_NOT_FILE";
    if(Files.isSymbolicLink(node.toPath()))return "NODE_SYMLINK_DENIED";
    long length=node.length();
    if(length<64||length>MAX_FILE)return "NODE_SIZE_OUT_OF_BOUNDS";
    try(RandomAccessFile raf=new RandomAccessFile(node,"r")){
      byte[] h=new byte[64];
      raf.readFully(h);
      if(h[0]!=127||h[1]!='E'||h[2]!='L'||h[3]!='F')
        return "NODE_NOT_ELF";
      boolean elf64=h[4]==2,elf32=h[4]==1;
      if(!elf64&&!elf32)return "ELF_CLASS_UNSUPPORTED";
      if(h[5]!=1&&h[5]!=2)return "ELF_ENDIAN_UNSUPPORTED";
      boolean little=h[5]==1;
      int machineId=u16(h,18,little);
      int hostId=abiMachine(abi);
      boolean match=hostId>=0&&hostId==machineId &&
          ((elf64 && (hostId==183||hostId==62)) ||
           (elf32 && (hostId==40||hostId==3)));
      String type=elf64?"ELF64":"ELF32";
      String common=type+"_EM_"+machine(machineId)+"_ABI_"+
          (hostId<0?"UNKNOWN":(match?"MATCH":"MISMATCH"));
      long phoff=elf64?u64(h,32,little):u32(h,28,little);
      int phSize=u16(h,elf64?54:42,little);
      int count=u16(h,elf64?56:44,little);
      if(phoff<0||count>128||phSize<(elf64?56:32)||phSize>128 ||
          count>0&&(phoff>length || (long)count*phSize>length-phoff))
        return common+"_PHDR_INVALID";
      if(count==0)return common+"_INTERP_ABSENT";
      byte[] ph=new byte[phSize];
      boolean seen=false;
      String interpreter="INTERP_ABSENT";
      for(int i=0;i<count;i++){
        raf.seek(phoff+(long)i*phSize);
        raf.readFully(ph);
        if(u32(ph,0,little)!=3)continue;
        if(seen)return common+"_INTERP_MULTIPLE_INVALID";
        seen=true;
        long at=elf64?u64(ph,8,little):u32(ph,4,little);
        long bytes=elf64?u64(ph,32,little):u32(ph,16,little);
        if(at<0||bytes<2||bytes>256||at>length||bytes>length-at){
          interpreter="INTERP_BOUNDS_INVALID";continue;
        }
        byte[] data=new byte[(int)bytes];
        raf.seek(at);raf.readFully(data);
        interpreter=linkCategory(data);
        java.util.Arrays.fill(data,(byte)0);
      }
      java.util.Arrays.fill(ph,(byte)0);
      return common+"_"+interpreter;
    }catch(IOException | SecurityException unavailable){
      return "NODE_ELF_READ_UNAVAILABLE";
    }
  }
  /** Fixed source file only; reject any canonical escape from the app's prefix. */
  public static String sample(File privateFilesDir,String abi){
    if(privateFilesDir==null)return "PRIVATE_CONTEXT_UNAVAILABLE";
    try {
      File prefix=new File(privateFilesDir,"termux/usr");
      File node=new File(prefix,"bin/node");
      String canonical=prefix.getCanonicalPath();
      if(!node.getCanonicalPath().equals(
          new File(canonical,"bin/node").getCanonicalPath()))
        return "PRIVATE_NODE_PATH_INVALID";
      if(!node.getCanonicalPath().startsWith(canonical+File.separator))
        return "PRIVATE_NODE_PATH_INVALID";
      return check(node,abi);
    }catch(IOException | SecurityException invalid){
      return "PRIVATE_NODE_PATH_INVALID";
    }
  }
}
