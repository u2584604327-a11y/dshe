package com.dsh.android.p185;

/**
 * Optional, user-led in-WebView challenge handoff. This is a local UI gate,
 * never a challenge solver, security token issuer, or proof of site success.
 * The agent dispatcher must consult canAutomate() when wired in production.
 */
public final class P185ManualVerificationState {
  private boolean enabled;
  private boolean takeover;

  public synchronized boolean isEnabled() { return enabled; }
  public synchronized boolean isTakeover() { return takeover; }
  public synchronized boolean canAutomate() { return !takeover; }

  /** User-controlled opt-in; turning it off cancels an outstanding takeover. */
  public synchronized void setEnabled(boolean userEnabled) {
    enabled = userEnabled;
    if (!enabled) takeover = false;
  }

  /** Only an opted-in user action may enter manual mode. */
  public synchronized boolean beginFromUser() {
    if (!enabled || takeover) return false;
    takeover = true;
    return true;
  }

  /** Returning from manual mode is not proof of site verification. */
  public synchronized boolean endFromUser() {
    if (!takeover) return false;
    takeover = false;
    return true;
  }

  /** Owner/activity destruction cannot leave an implicit resume permit. */
  public synchronized void revoke() {
    takeover = false;
    enabled = false;
  }
}