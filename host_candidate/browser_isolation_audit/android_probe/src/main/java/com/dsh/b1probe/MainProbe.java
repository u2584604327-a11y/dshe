package com.dsh.b1probe;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

/** Strict sequence with real process change across Activity result Binder. */
public final class MainProbe extends Activity {
  private static final String TAG = "B1_PROBE";
  private int phase = -1;
  private boolean terminal;
  private boolean restart;
  private ConcurrentHarness concurrent;
  @Override protected void onCreate(Bundle state) {
    super.onCreate(state);
    if (state != null) { deny("ACTIVITY_RECREATED"); return; }
    if (!getPackageName().equals(android.app.Application.getProcessName())) {
      deny("MAIN_WRONG_PROCESS"); return;
    }
    // A launcher without a CI-selected mode must fail closed. Never guess a
    // data-migration or fresh profile mode from existing on-device state.
    final String mode = getIntent().getStringExtra("mode");
    if ("concurrent".equals(mode)) {
      concurrent = new ConcurrentHarness(this);
      concurrent.start();
      return;
    }
    if ("seed".equals(mode)) { phase = -1; restart = false; }
    else if ("restart".equals(mode)) { phase = 1; restart = true; }
    else { deny("MODE_REQUIRED"); return; }
    startNext();
  }
  private void startNext() {
    phase++;
    if (phase == 4) {
      if (restart) {
        Log.i(TAG,"B1_ANDROID35_RESTART_A_B_COOKIE_LOCALSTORAGE_ISOLATION=PASS");
        Log.i(TAG,"B1_ANDROID35_RESTART_A_B_INDEXEDDB_ISOLATION=PASS");
      } else {
        Log.i(TAG,"B1_ANDROID35_PROCESS_A_B_COOKIE_LOCALSTORAGE_ISOLATION=PASS");
        Log.i(TAG,"B1_ANDROID35_PROCESS_A_B_INDEXEDDB_ISOLATION=PASS");
      }
      Log.i(TAG,"B1_ANDROID35_MAIN_PROCESS_WEBVIEW_DISABLED=PASS");
      Log.i(TAG,"B1_ANDROID35_SAME_APP_UID_OS_ISOLATION=NOT_ATTESTED");
      Log.i(TAG,"B1_ANDROID35_AVF_PROTECTED_VM=NOT_ATTESTED");
      terminal = true;
      finish(); return;
    }
    if (phase < 0 || phase > 3 || (restart && phase < 2)) {
      deny("PHASE_OUT_OF_RANGE");return;
    }
    Class<?> clazz = phase == 0 || phase == 2 ? SlotA.class : SlotB.class;
    Intent call = new Intent(this, clazz);
    call.putExtra("phase",phase);
    startActivityForResult(call, 100 + phase);
  }
  @Override protected void onActivityResult(int code,int result,Intent data) {
    super.onActivityResult(code,result,data);
    if (terminal) return;
    if (code != 100 + phase || result != RESULT_OK || data != null) {
      deny("MISSING_EXACT_PHASE_PROOF");return;
    }
    startNext();
  }
  @Override protected void onDestroy() {
    if (concurrent != null) concurrent.close();
    super.onDestroy();
  }
  private void deny(String safeReason) {
    if (!terminal) Log.i(TAG,"B1_ANDROID35_" + safeReason + "=DENY");
    terminal = true;
    finish();
  }
}
