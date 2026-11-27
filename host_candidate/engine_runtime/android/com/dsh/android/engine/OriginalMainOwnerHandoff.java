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

    static final class ActivationFailure extends IOException {
        final String workerFailure, childState, transportFailure;

        private ActivationFailure(String code, OriginalMainTestSession session) {
            super(code);
            workerFailure = session.failure();
            childState = session.childState();
            transportFailure = session.transportFailure();
        }
    }

    private final OriginalAndroidWebLaunch owner;
    private final OriginalMainTestSession session;
    private final P37RemoteProcess child;
    private final DurableSessionSnapshot store;
    private final long issuedAt = System.nanoTime();
    private boolean revoked;
    private boolean accepted;
    private Thread preparedThread;
    private VerifiedLaunch verified;
    private ActivationFailure activationFailure;

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
            if (!handoff.session.ownsReservation(handoff.owner, handoff.child)) {
                throw new IOException("MAIN_OWNER_CHILD_UNAVAILABLE");
            }
            if (handoff.preparedThread != null) throw new IOException("MAIN_OWNER_PRELAUNCH_ALREADY_USED");
            handoff.owner.plan.requireSame(handoff.owner.original);
            handoff.preparedThread = Thread.currentThread();
            return handoff.owner.original;
        }
    }

    private void requireFresh() throws IOException {
        long age = System.nanoTime() - issuedAt;
        if (revoked) throw new IOException("MAIN_OWNER_HANDOFF_REVOKED");
        if (age < 0 || age > MAX_AGE) throw new IOException("MAIN_OWNER_LEASE_EXPIRED");
    }

    /** The exact receiver comes from the checked main-DEX callsite. */
    public static Process claimOrDeny(ProcessBuilder builder, Object receiver) throws IOException {
        OriginalMainOwnerHandoff handoff;
        synchronized (pending) {
            handoff = pending.get(receiver);
            if (handoff != null) {
                synchronized (handoff) {
                    if (handoff.preparedThread != Thread.currentThread()) {
                        throw new IOException("MAIN_OWNER_PRELAUNCH_REQUIRED");
                    }
                    pending.remove(receiver);
                }
            }
        }
        if (handoff == null) return P47LaunchGate.startOrDeny(builder);
        return handoff.activate(builder);
    }

    private Process activate(ProcessBuilder builder) throws IOException {
        String stage = "CLAIM";
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
            stage = "TRANSPORT";
            HttpProcessTransport process = session.openLaunchTransport(child, owner, store);
            stage = "STARTUP_OUTPUT";
            OriginalMainStartup startup = OriginalMainStartup.await(process);
            stage = "HTTP_READY";
            String cookie = startup.verifyForReady();
            stage = "READY_PROOF";
            OriginalMainStartup.requireVerifiedReady(process, startup.privateUrl());
            synchronized (this) {
                if (revoked || !session.ownsLaunch(owner, process) || !process.hasCurrentReadyProof()) throw new IOException("MAIN_OWNER_HANDOFF_REVOKED");
                verified = new VerifiedLaunch(process, startup, cookie);
                handedOff = true;
                return process;
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw failActivation("MAIN_OWNER_START_INTERRUPTED");
        } catch (OriginalMainStartup.Denied denied) {
            throw failActivation(denied.getMessage());
        } catch (IOException | RuntimeException | LinkageError failure) {
            if ("CLAIM".equals(stage) && failure instanceof IOException) {
                // This stage only calls the fixed plan and lease checks above.
                throw failActivation(failure.getMessage());
            }
            String phase = "TRANSPORT".equals(stage) ? session.launchPhase().name() : stage;
            throw failActivation("MAIN_OWNER_" + phase
                    + (failure instanceof LinkageError ? "_LINKAGE_FAILURE" : "_FAILED"));
        } finally {
            if (!handedOff) disposeUnclaimed();
        }
    }

    private synchronized ActivationFailure failActivation(String code) {
        // The original coroutine catches startup failures and returns Unit. Retain
        // only a fixed code so the TEST owner can recover it without reading logs,
        // paths, private URLs or exception text supplied by IO or the worker.
        if (activationFailure == null) activationFailure = new ActivationFailure(code, session);
        return activationFailure;
    }

    synchronized VerifiedLaunch verifiedLaunch() throws IOException {
        if (activationFailure != null) throw activationFailure;
        if (revoked) throw new IOException("MAIN_OWNER_HANDOFF_REVOKED");
        if (verified == null) throw new IOException("MAIN_OWNER_CLAIM_NOT_COMPLETED");
        if (!session.ownsLaunch(owner, verified.process)
                || !verified.process.hasCurrentReadyProof()) throw new IOException("MAIN_OWNER_HANDOFF_REVOKED");
        return verified;
    }

    synchronized void acceptOriginalReady(VerifiedLaunch launch) throws IOException {
        if (accepted || launch != verifiedLaunch()) throw new IOException("MAIN_OWNER_READY_ACK_DENIED");
        accepted = true;
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
            unclaimed = !accepted;
            verified = null;
        }
        synchronized (pending) { pending.remove(owner.engine, this); }
        if (unclaimed) disposeUnclaimed();
    }
}
