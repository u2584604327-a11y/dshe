package com.dsh.android.p50;

import com.dsh.android.p77.P77TarAudit;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/** Immutable original resources only. Not a launcher or a production approval. */
public final class P50ModuleStream {
  private P50ModuleStream() {}

  /** Caller owns child stdin, including closing it after successful return or failure.
   * The receiver must independently validate the pinned tree before loading any module.
   * Failed TAR validation never emits the completion marker.
   */
  public static P77TarAudit.Result writeOriginal(InputStream compressed,OutputStream childStdin)
      throws IOException {
    if(compressed==null||childStdin==null)throw new IllegalArgumentException("P50_STREAM_REQUIRED");
    final DataOutputStream output=new DataOutputStream(childStdin);
    output.write("DSHMOD01".getBytes(StandardCharsets.US_ASCII));
    return P77TarAudit.inspectGzipTo(compressed,new P77TarAudit.MemberSink(){
      long remaining;
      boolean member;
      public void begin(String canonical,boolean directory,long size)throws IOException{
        if(member)throw new IOException("P50_MEMBER_INCOMPLETE");
        byte[] name=canonical.getBytes(StandardCharsets.UTF_8);
        if(name.length==0||name.length>4096)throw new IOException("P50_MODULE_PATH_BOUND");
        member=true;remaining=size;
        output.writeInt(name.length);output.write(name);
        output.writeByte(directory?1:0);output.writeLong(size);
      }
      public void accept(byte[] bytes,int offset,int length)throws IOException{
        if(!member||length<0||length>remaining)throw new IOException("P50_MODULE_LENGTH");
        output.write(bytes,offset,length);remaining-=length;
      }
      public void endMember()throws IOException{
        if(!member||remaining!=0)throw new IOException("P50_MEMBER_INCOMPLETE");
        member=false;
      }
      public void sealOriginal(P77TarAudit.Result complete)throws IOException{
        if(member||!complete.isExactOriginal())throw new IOException("P50_ORIGINAL_TREE_REQUIRED");
        output.writeInt(0);output.flush();
      }
    });
  }
}
