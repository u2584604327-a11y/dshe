package com.dsh.android.browser;

/**
 * Single outstanding foreground browser operation and user-led takeover.
 * Pure Java 8, no Android APIs, credentials, cookies or site challenge code.
 * An old callback can never release the UI ownership of a newer operation.
 */
public final class BrowserOperationLease {
  private long epoch;
  private long active;
  private long lastCancelled;
  private boolean manual;

  /** 0 means user-led browser interaction blocks automation. */
  public synchronized long begin() {
    if (manual || active != 0L) return 0L;
    epoch++;
    active = epoch;
    lastCancelled = 0L;
    return active;
  }

  public synchronized boolean isCurrent(long lease) {
    return lease != 0L && !manual && active == lease;
  }

  /** Only a live lease may return a successful tool result or release UI. */
  public synchronized boolean complete(long lease) {
    if (!isCurrent(lease)) return false;
    active = 0L;
    lastCancelled = 0L;
    return true;
  }

  /** Revoke a timeout/error lease and permit cleanup only before a new start. */
  public synchronized boolean cancel(long lease) {
    if (!isCurrent(lease)) return false;
    active = 0L;
    lastCancelled = lease;
    return true;
  }

  public synchronized boolean mayCleanupCancelled(long lease) {
    return lease != 0L && !manual && active == 0L && lastCancelled == lease;
  }

  /** Explicit user action. Invalidates the in-flight lease; no auto replay. */
  public synchronized boolean enterManual() {
    if (manual) return false;
    manual = true;
    active = 0L;
    lastCancelled = 0L;
    epoch++;
    return true;
  }

  /** Explicit user action; does NOT authorize or replay an earlier command. */
  public synchronized boolean leaveManual() {
    if (!manual) return false;
    manual = false;
    epoch++;
    return true;
  }

  public synchronized boolean isManual() { return manual; }
}
