package com.dsh.android.engine;

import com.dsh.android.p47.P47LaunchGate;

import java.io.IOException;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** One-use handoff for the exact original receiver in the separate TEST APK. */
public final class OriginalMainOwnerHandoff implements AutoCloseable {
    private static final Map<Object, OriginalMainOwnerHandoff> pending = new IdentityHashMap<>();
    private static final long MAX_AGE = TimeUnit.SECONDS.toNanos(12);

    private final OriginalAndroidWebLaunch owner;
    private final OriginalMainTestSession session;
    private final HttpProcessTransport process;
    private final long issuedAt = System.nanoTime();
    private boolean revoked;

    private OriginalMainOwnerHandoff(OriginalAndroidWebLaunch owner, OriginalMainTestSession session,
            HttpProcessTransport process) {
        this.owner = owner;
        this.session = session;
        this.process = process;
    }

    static OriginalMainOwnerHandoff offer(OriginalAndroidWebLaunch owner, OriginalMainTestSession session,
            HttpProcessTransport process) throws IOException {
        owner.plan.requireSame(owner.original);
        synchronized (pending) {
            if (pending.containsKey(owner.engine) || pending.size() >= 8 || !session.reserveHandoff(owner, process)) {
                throw new IOException("MAIN_OWNER_HANDOFF_UNAVAILABLE");
            }
            OriginalMainOwnerHandoff handoff = new OriginalMainOwnerHandoff(owner, session, process);
            pending.put(owner.engine, handoff);
            return handoff;
        }
    }

    /** The exact receiver comes from the checked main-DEX callsite. */
    public static Process claimOrDeny(ProcessBuilder builder, Object receiver) throws IOException {
        OriginalMainOwnerHandoff handoff;
        synchronized (pending) { handoff = pending.remove(receiver); }
        if (handoff == null) return P47LaunchGate.startOrDeny(builder);
        boolean handedOff = false;
        try {
            synchronized (handoff) {
                handoff.owner.plan.requireSame(builder);
                long age = System.nanoTime() - handoff.issuedAt;
                if (handoff.revoked || age < 0 || age > MAX_AGE
                        || !handoff.session.ownsLaunch(handoff.owner, handoff.process)
                        || !handoff.process.hasCurrentReadyProof()) {
                    throw new IOException("MAIN_OWNER_HANDOFF_REVOKED");
                }
                handedOff = true;
                return handoff.process;
            }
        } finally {
            if (!handedOff) handoff.process.close();
        }
    }

    @Override public void close() {
        synchronized (this) { revoked = true; }
        synchronized (pending) { pending.remove(owner.engine, this); }
    }
}
