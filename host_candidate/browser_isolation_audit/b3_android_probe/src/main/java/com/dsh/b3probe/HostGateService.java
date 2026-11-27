package com.dsh.b3probe;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
/** Deliberately exported only in this disposable offline test for cross-UID denial. */
public final class HostGateService extends Service {
  @Override public IBinder onBind(Intent intent){return HostProbe.GATE;}
}
