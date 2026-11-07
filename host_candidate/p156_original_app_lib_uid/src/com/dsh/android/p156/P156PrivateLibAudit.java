package com.dsh.android.p156;
import java.io.*;
/** Bounded read-only inspection: fixed private original files only, never run ELF. */
public final class P156PrivateLibAudit {
  public static final long CAP=8L*1024*1024;
  private P156PrivateLibAudit(){}
  public static String inspect(File files,String name) {
    if(!"libz.so.1".equals(name)&&!"libcares.so".equals(name))return "DENIED_NAME";
    if(files==null)return "MISSING_ROOT";
    try {
      String root=files.getCanonicalPath();
      File libdir=new File(files,"termux/usr/lib");
      String parent=libdir.getCanonicalPath();
      if(!parent.startsWith(root+File.separator))return "DENIED_PREFIX_ESCAPE";
      File f=new File(libdir,name);
      if(!f.getCanonicalPath().startsWith(parent+File.separator))
        return "DENIED_FILE_ESCAPE";
      if(!f.exists())return "ABSENT";
      if(!f.isFile())return "NOT_FILE";
      if(!f.canRead())return "UNREADABLE";
      if(f.length()>CAP)return "TOO_LARGE";
      long count=0;byte[] header=new byte[20];
      try(FileInputStream in=new FileInputStream(f)){
        byte[] chunk=new byte[4096];int n;
        while((n=in.read(chunk))!=-1){
          if(n==0)continue;
          if(n>CAP-count)return "STREAM_TOO_LARGE";
          for(int j=0;j<n&&count+j<20;j++)header[(int)(count+j)]=chunk[j];
          count+=n;
        }
      }catch(SecurityException sec){return "OPEN_DENIED";
      }catch(IOException io){return "READ_FAILED";}
      if(count<64||(header[0]&255)!=127||header[1]!='E'||header[2]!='L'||header[3]!='F')
        return "NOT_ELF";
      if(header[5]!=1)return "UNKNOWN_ENDIAN";
      int machine=(header[18]&255)|((header[19]&255)<<8);
      return machine==183?"AARCH64_ELF_READ_UNPINNED":
             machine==62?"X86_64_ELF_READ_UNPINNED":"OTHER_ELF_READ_UNPINNED";
    }catch(SecurityException denied){return "PRIVATE_ACCESS_DENIED";
    }catch(IOException invalid){return "PATH_UNAVAILABLE";}
  }
}
