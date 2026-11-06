package com.dsh.b1probe;

import android.app.Application;
import android.content.Context;
import android.webkit.WebView;

/**
 * Strict PROCESS-GLOBAL setup: WebView data directory suffix must be assigned
 * before any other WebKit use. Main controller never touches a WebView.
 * This does NOT create separate app UIDs, work profiles or a protected VM.
 */
public final class ProbeApp extends Application {
  @Override protected void attachBaseContext(Context base) {
    super.attachBaseContext(base);
    final String process = Application.getProcessName();
    final String pkg = base.getPackageName();
    if ((pkg + ":slotA").equals(process)) {
      WebView.setDataDirectorySuffix("b1_slot_a");
    } else if ((pkg + ":slotB").equals(process)) {
      WebView.setDataDirectorySuffix("b1_slot_b");
    } else if (pkg.equals(process)) {
      WebView.disableWebView();
    } else {
      throw new SecurityException("B1_UNKNOWN_PROCESS_DENIED");
    }
  }
}
