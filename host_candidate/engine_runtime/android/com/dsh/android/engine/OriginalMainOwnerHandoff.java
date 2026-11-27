package com.dsh.android.engine;

import android.os.Looper;

import com.dsh.android.p47.P47LaunchGate;
import com.dsh.p37.P37RemoteProcess;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** One-use activation for the exact original receiver in the separate TEST APK. */
public final class OriginalMainOwnerHandoff implements AutoCloseable {
    private static final Map<Object, OriginalMainOwnerHandoff> pending = new IdentityHashMap<>();
    private static final long MAX_AGE = TimeUnit.SECONDS.toNanos(12);

    static final class VerifiedLaunch {
        final HttpProcessTransport process;
        final OriginalMainStartup startup;
        final String cookie;

        private VerifiedLaunch(HttpProcessTransport process, OriginalMainStartup startup, String cookie) {
            this.process = process;
            this.startup = startup;
            this.cookie = cookie;
        }
    }

    private final OriginalAndroidWebLaunch owner;
    private final OriginalMainTestSession session;
    private final P37RemoteProcess child;
    private final DurableSessionSnapshot store;
    private final long issuedAt = System.nanoTime();
    private boolean revoked;
    private Thread preparedThread;
    private VerifiedLaunch verified;

    private OriginalMainOwnerHandoff(OriginalAndroidWebLaunch owner, OriginalMainTestSession session,
            P37RemoteProcess child, DurableSessionSnapshot store) {
        this.owner = owner;
        this.session = session;
        this.child = child;
        this.store = store;
    }

    static OriginalMainOwnerHandoff offer(OriginalAndroidWebLaunch owner, OriginalMainTestSession session,
            P37RemoteProcess child, DurableSessionSnapshot store) throws IOException {
        if (store == null) throw new IOException("MAIN_OWNER_STORE_REQUIRED");
        owner.plan.requireSame(owner.original);
        synchronized (pending) {
            if (pending.containsKey(owner.engine) || pending.size() >= 8 || !session.reserveHandoff(owner, child)) {
                throw new IOException("MAIN_OWNER_HANDOFF_UNAVAILABLE");
            }
            OriginalMainOwnerHandoff handoff = new OriginalMainOwnerHandoff(owner, session, child, store);
            pending.put(owner.engine, handoff);
            return handoff;
        }
    }

    /** Called by the guarded initial branch of the original TEST coroutine. */
    public static ProcessBuilder prepareOriginal(Object receiver) throws IOException {
        OriginalMainOwnerHandoff handoff;
        synchronized (pending) { handoff = pending.get(receiver); }
        if (handoff == null) throw new IOException("MAIN_OWNER_PRELAUNCH_NOT_ARMED");
        synchronized (handoff) {
            handoff.requireFresh();
            if (handoff.preparedThread != null) throw new IOException("MAIN_OWNER_PRELAUNCH_ALREADY_USED");
            handoff.owner.plan.requireSame(handoff.owner.original);
            handoff.preparedThread = Thread.currentThread();
            return handoff.owner.original;
        }
    }

    private void requireFresh() throws IOException {
        long age = System.nanoTime() - issuedAt;
        if (revoked || age < 0 || age > MAX_AGE) throw new IOException("MAIN_OWNER_HANDOFF_REVOKED");
    }

    /** The exact receiver comes from the checked main-DEX callsite. */
    public static Process claimOrDeny(ProcessBuilder builder, Object receiver) throws IOException {
        OriginalMainOwnerHandoff handoff;
        synchronized (pending) { handoff = pending.remove(receiver); }
        if (handoff == null) return P47LaunchGate.startOrDeny(builder);
        return handoff.activate(builder);
    }

    private Process activate(ProcessBuilder builder) throws IOException {
        boolean handedOff = false;
        try {
            owner.plan.requireSame(builder);
            synchronized (this) {
                requireFresh();
                if (preparedThread != Thread.currentThread()) throw new IOException("MAIN_OWNER_PRELAUNCH_REQUIRED");
                preparedThread = null;
            }
            if (Looper.myLooper() == Looper.getMainLooper()) throw new IOException("MAIN_OWNER_BACKGROUND_REQUIRED");
            if (Thread.currentThread().isInterrupted()) throw new InterruptedIOException("MAIN_OWNER_START_INTERRUPTED");
            HttpProcessTransport process = session.openLaunchTransport(child, owner, store);
            OriginalMainStartup startup = OriginalMainStartup.await(process);
            String cookie = startup.verifyForReady();
            OriginalMainStartup.requireVerifiedReady(process, startup.privateUrl());
            synchronized (this) {
                if (revoked || !session.ownsLaunch(owner, process) || !process.hasCurrentReadyProof()) throw new IOException("MAIN_OWNER_HANDOFF_REVOKED");
                verified = new VerifiedLaunch(process, startup, cookie);
                handedOff = true;
                return process;
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("MAIN_OWNER_START_INTERRUPTED");
        } finally {
            if (!handedOff) disposeUnclaimed();
        }
    }

    synchronized VerifiedLaunch verifiedLaunch() throws IOException {
        if (revoked || verified == null || !session.ownsLaunch(owner, verified.process)
                || !verified.process.hasCurrentReadyProof()) throw new IOException("MAIN_OWNER_HANDOFF_REVOKED");
        return verified;
    }

    private void disposeUnclaimed() {
        try {
            session.close();
        } finally {
            try { store.close(); } catch (IOException ignored) { /* Preserve the activation failure. */ }
        }
    }

    @Override public void close() {
        final boolean unclaimed;
        synchronized (this) {
            if (revoked) return;
            revoked = true;
            preparedThread = null;
            unclaimed = verified == null;
            verified = null;
        }
        synchronized (pending) { pending.remove(owner.engine, this); }
        if (unclaimed) disposeUnclaimed();
    }
}
