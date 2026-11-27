package com.dsh.android.p153;
import android.content.Context;
import android.os.Build;
/** Android-context adapter: fixed original private node; never creates a Process. */
public final class P153OriginalNodeElfProbe {
  private P153OriginalNodeElfProbe(){}
  public static String safeSnapshot(Context context){
    if(context==null)return "PRIVATE_CONTEXT_UNAVAILABLE";
    try {
      String abi=Build.SUPPORTED_ABIS.length>0?Build.SUPPORTED_ABIS[0]:"";
      return P153ElfHeader.sample(context.getFilesDir(),abi);
    }catch(Throwable denied){return "PRIVATE_NODE_PROBE_UNAVAILABLE";}
  }
}
