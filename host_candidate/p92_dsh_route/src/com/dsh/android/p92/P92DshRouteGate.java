package com.dsh.android.p92;

import com.dsh.android.p90.P90SendReceiptGate;

/** Contract for a single DSH-owned send to an already-installed OmniGate listener.
 * The actual OmniGate server MUST recheck owner on POST; /health is advisory.
 */
public final class P92DshRouteGate {
    public static final String ROUTE = "http://127.0.0.1:8787/v1/chat/completions";
    public static final String HEALTH = "http://127.0.0.1:8787/health";

    public enum Stage {
        NEW, PREFLIGHT_OK, DISPATCH_UNCONFIRMED, CONFIRMED,
        PRECHECK_REJECTED, HTTP_REJECTED, UNKNOWN_AFTER_DISPATCH
    }
    public static final class Health {
        public final boolean ok, reachable, verified, ambiguous;
        public final String listen, nativeOwner, runtimeRoute;
        public Health(boolean serviceOk,boolean upstreamReachable,boolean ownerVerified,
                      boolean ambiguousOwners,String listenAddress,String verifiedNativeOwner,
                      String observedRuntimeRoute) {
            ok=serviceOk;reachable=upstreamReachable;verified=ownerVerified;ambiguous=ambiguousOwners;
            listen=listenAddress;nativeOwner=verifiedNativeOwner;runtimeRoute=observedRuntimeRoute;
        }
    }
    private final P90SendReceiptGate editorReceipt;
    private Stage state=Stage.NEW;
    private String reason="NOT_CHECKED";
    private boolean clickReceiptApplied;

    public P92DshRouteGate(P90SendReceiptGate receipt) {
        if (receipt==null)throw new IllegalArgumentException("MISSING_EDITOR_RECEIPT");
        editorReceipt=receipt;
    }
    /**
     * Consumes read-only /health evidence; does not send, retry, login, change port or ownership.
     * Health status can race a new POST and NEVER grants permission to bypass server-side 409.
     */
    public synchronized boolean preflight(Health h) {
        if(state!=Stage.NEW)throw new IllegalStateException("P92_ALREADY_CHECKED");
        if(editorReceipt.state()!=P90SendReceiptGate.State.INPUT_VERIFIED) {
            state=Stage.PRECHECK_REJECTED;reason="DSH_EDITOR_NOT_VERIFIED";return false;
        }
        if(h==null || !h.ok || !"127.0.0.1:8787".equals(h.listen)) {
            state=Stage.PRECHECK_REJECTED;reason="OMNIGATE_LISTENER_NOT_VERIFIED";return false;
        }
        if(!h.reachable){state=Stage.PRECHECK_REJECTED;reason="NATIVE_LISTENER_UNAVAILABLE";return false;}
        if(!h.verified || h.ambiguous){
            state=Stage.PRECHECK_REJECTED;reason="NATIVE_RUNTIME_OWNER_UNVERIFIED";return false;
        }
        if(!(("main".equals(h.nativeOwner) && "main_socket_and_driver_match".equals(h.runtimeRoute)) ||
             ("overlay".equals(h.nativeOwner) && "overlay_socket_and_driver_match".equals(h.runtimeRoute)))) {
            state=Stage.PRECHECK_REJECTED;reason="OWNER_IDENTITY_ROUTE_CONFLICT";return false;
        }
        state=Stage.PREFLIGHT_OK;reason="ADVISORY_READY_FOR_ONE_ATTEMPT";return true;
    }
    /** Called before the one real DSH transport POST; no automatic resend on failure. */
    public synchronized boolean consumeOneAttempt() {
        if(state!=Stage.PREFLIGHT_OK)return false;
        state=Stage.DISPATCH_UNCONFIRMED;reason="TRANSPORT_RESULT_NOT_CONFIRMED";return true;
    }
    /** HTTP status is transport-only. A 200 is not confirmation of user turn delivery. */
    public synchronized void onHttpStatus(int status) {
        if(state!=Stage.DISPATCH_UNCONFIRMED)return;
        if(status==409){state=Stage.HTTP_REJECTED;reason="ORIGINAL_RUNTIME_OWNER_MISMATCH";}
        else if(status==503){state=Stage.HTTP_REJECTED;reason="NATIVE_API_UNAVAILABLE";}
        else if(status==401 || status==403){state=Stage.HTTP_REJECTED;reason="AUTH_REJECTED";}
        else if(status==200){reason="HTTP_200_WAITING_FOR_REAL_TURN";}
        else if(status>0){state=Stage.HTTP_REJECTED;reason="HTTP_OTHER_REJECTED";}
    }
    /** Does not infer a turn from SSE [DONE], model content, or transport HTTP200. */
    public synchronized void onTrustedUserTurn(String turnId,boolean actuallyPresent) {
        if(state!=Stage.DISPATCH_UNCONFIRMED)return;
        if(!clickReceiptApplied) {
            editorReceipt.clickReceipt("SENT");
            clickReceiptApplied=true;
        }
        editorReceipt.onTrustedUserTurn(turnId,actuallyPresent);
        if(editorReceipt.reportSent()){
            state=Stage.CONFIRMED;reason="TRUSTED_USER_TURN_OBSERVED";
        }
    }
    public synchronized void onConnectionLost() {
        if(state==Stage.DISPATCH_UNCONFIRMED){
            editorReceipt.connectionLost();
            state=Stage.UNKNOWN_AFTER_DISPATCH;
            reason="NO_RETRY_AMBIGUOUS_DISCONNECT";
        }
    }
    public synchronized Stage stage(){return state;}
    public synchronized String reason(){return reason;}
    public synchronized boolean canAutoRetry(){return false;}
    public synchronized boolean isConfirmed(){return state==Stage.CONFIRMED;}
}
