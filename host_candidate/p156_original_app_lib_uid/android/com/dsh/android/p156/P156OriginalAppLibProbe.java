package com.dsh.android.p156;
import android.content.Context;
import android.os.Process;
/** Only a disposable original-package Activity may run this read-only probe. */
public final class P156OriginalAppLibProbe {
  private P156OriginalAppLibProbe(){}
  public static String safeSnapshot(Context context) {
    if(context==null)return "NO_CONTEXT";
    if(Process.isIsolated())return "DENY_ISOLATED";
    if(!"com.dsh.android".equals(context.getPackageName()))return "DENY_PACKAGE";
    if(context.getApplicationInfo()==null||
       Process.myUid()!=context.getApplicationInfo().uid)return "DENY_UID";
    return "APP_UID_VERIFIED_Z_"+P156PrivateLibAudit.inspect(
      context.getFilesDir(),"libz.so.1")+"_CARES_"+
      P156PrivateLibAudit.inspect(context.getFilesDir(),"libcares.so");
  }
}
