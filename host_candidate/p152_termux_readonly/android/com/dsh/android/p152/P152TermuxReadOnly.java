package com.dsh.android.p152;
import android.content.Context;
import android.os.Build;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
/** Strictly read-only inspection. No Node/version execution; no private file bytes. */
public final class P152TermuxReadOnly {
  private P152TermuxReadOnly(){}
  private static boolean asset(Context context,String fixedName) {
    try(InputStream stream=context.getAssets().open(fixedName)) {
      return stream.read()!=-1;
    }catch(IOException absent){return false;}
  }
  public static String safeSnapshot(Context context) {
    if(context==null)return "CONTEXT_UNAVAILABLE";
    try {
      String abi=Build.SUPPORTED_ABIS.length>0?Build.SUPPORTED_ABIS[0]:"";
      String arch=P152CauseClassifier.assetArch(abi);
      File prefix=new File(context.getFilesDir(),"termux/usr");
      File node=new File(prefix,"bin/node");
      return P152CauseClassifier.classify(abi,
          asset(context,"bootstrap-"+arch+".zip"),
          asset(context,"node-runtime.bin"),
          prefix.isDirectory(),
          new File(prefix,".bootstrap_done").isFile(),
          node.isFile(),
          new File(prefix,".node_runtime_26.4.0-2").isFile(),
          node.isFile()&&node.length()>0);
    }catch(Throwable readOnlyUnavailable) {
      return "READ_ONLY_PROBE_UNAVAILABLE";
    }
  }
}
