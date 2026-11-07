package com.dsh.android.p153;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
public final class P153ElfHeaderTest {
  private static int assertions;
  private static void yes(boolean x){assertions++;if(!x)throw new AssertionError("P153_ELF_FAIL_OPEN");}
  private static void i16(byte[] a,int at,int n){a[at]=(byte)n;a[at+1]=(byte)(n>>8);}
  private static void i32(byte[] a,int at,long n){
    for(int j=0;j<4;j++)a[at+j]=(byte)(n>>(8*j));
  }
  private static byte[] fixture(int machine,boolean interpreter){
    byte[] a=new byte[interpreter?512:64];
    a[0]=127;a[1]='E';a[2]='L';a[3]='F';a[4]=2;a[5]=1;a[6]=1;
    i16(a,16,3);i16(a,18,machine);i32(a,20,1);
    i32(a,32,interpreter?64:0);
    i16(a,52,64);i16(a,54,56);i16(a,56,interpreter?1:0);
    if(interpreter){
      i32(a,64,3);i32(a,72,256);
      byte[] interp="/system/bin/linker64\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
      i32(a,96,interp.length);System.arraycopy(interp,0,a,256,interp.length);
    }
    return a;
  }
  private static void save(File file,byte[] bytes)throws Exception{
    try(FileOutputStream out=new FileOutputStream(file)){out.write(bytes);}
  }
  public static void main(String[] args)throws Exception{
    File root=Files.createTempDirectory("p153-synthetic").toFile();
    File dir=new File(root,"termux/usr/bin");
    yes(dir.mkdirs());
    File f=new File(dir,"node");
    try{
      save(f,fixture(183,true));
      String arm=P153ElfHeader.sample(root,"arm64-v8a");
      yes(arm.equals("ELF64_EM_AARCH64_ABI_MATCH_ANDROID_LINKER64"));
      String mismatch=P153ElfHeader.sample(root,"x86_64");
      yes(mismatch.equals("ELF64_EM_AARCH64_ABI_MISMATCH_ANDROID_LINKER64"));
      yes(!mismatch.contains("/system/"));
      save(f,fixture(62,false));
      yes(P153ElfHeader.sample(root,"x86_64").equals(
          "ELF64_EM_X86_64_ABI_MATCH_INTERP_ABSENT"));
      byte[] corrupted=fixture(62,true);corrupted[0]=0;save(f,corrupted);
      yes("NODE_NOT_ELF".equals(P153ElfHeader.sample(root,"x86_64")));
      save(f,fixture(62,true));
      yes(P153ElfHeader.sample(root,"x86_64").endsWith("ANDROID_LINKER64"));
      byte[] invalid=fixture(183,true);
      i32(invalid,72,999999);save(f,invalid);
      yes(P153ElfHeader.sample(root,"arm64-v8a").endsWith("INTERP_BOUNDS_INVALID"));
      yes("PRIVATE_CONTEXT_UNAVAILABLE".equals(P153ElfHeader.sample(null,"x86_64")));
      yes(assertions>=9);
      System.out.println("P153_SYNTHETIC_ELF_ABI_AND_INTERP_NEGATIVES=PASS");
      System.out.println("P153_PRODUCTION_NODE_OR_SCRIPT_EXECUTED=NO");
    }finally{
      Files.deleteIfExists(f.toPath());
      Files.deleteIfExists(dir.toPath());
      Files.deleteIfExists(dir.getParentFile().toPath());
      Files.deleteIfExists(dir.getParentFile().getParentFile().toPath());
      Files.deleteIfExists(root.toPath());
    }
  }
}
