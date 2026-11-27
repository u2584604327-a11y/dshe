package com.dsh.android.p156;
import java.nio.file.*;
import java.io.File;
public final class P156PrivateLibAuditTest {
  private static void eq(String actual,String expect){
    if(!expect.equals(actual))throw new AssertionError(expect+" != "+actual);
  }
  private static void elf(Path p,int machine,int size)throws Exception{
    byte[] b=new byte[size];
    b[0]=127;b[1]='E';b[2]='L';b[3]='F';b[4]=2;b[5]=1;
    b[18]=(byte)machine;b[19]=(byte)(machine>>>8);Files.write(p,b);
  }
  public static void main(String[] args)throws Exception {
    Path tmp=Files.createTempDirectory("p156-"),lib=tmp.resolve("files/termux/usr/lib");
    Files.createDirectories(lib);
    File root=tmp.resolve("files").toFile();
    eq(P156PrivateLibAudit.inspect(root,"libz.so.1"),"ABSENT");
    eq(P156PrivateLibAudit.inspect(root,"../../data"),"DENIED_NAME");
    elf(lib.resolve("libz.so.1"),183,96);
    eq(P156PrivateLibAudit.inspect(root,"libz.so.1"),"AARCH64_ELF_READ_UNPINNED");
    elf(lib.resolve("libcares.so"),62,96);
    eq(P156PrivateLibAudit.inspect(root,"libcares.so"),"X86_64_ELF_READ_UNPINNED");
    Files.write(lib.resolve("libz.so.1"),new byte[100]);
    eq(P156PrivateLibAudit.inspect(root,"libz.so.1"),"NOT_ELF");
    Files.write(lib.resolve("libz.so.1"),new byte[(int)P156PrivateLibAudit.CAP+1]);
    eq(P156PrivateLibAudit.inspect(root,"libz.so.1"),"TOO_LARGE");
    Files.delete(lib.resolve("libz.so.1"));
    Path outside=tmp.resolve("outside");
    elf(outside,183,96);
    Files.createSymbolicLink(lib.resolve("libz.so.1"),outside);
    eq(P156PrivateLibAudit.inspect(root,"libz.so.1"),"DENIED_FILE_ESCAPE");
    System.out.println("P156_FIXED_APP_UID_LIB_JAVA8_CASES=PASS");
    System.out.println("P156_EXECUTED_NODE_OR_ELF=NO");
  }
}
