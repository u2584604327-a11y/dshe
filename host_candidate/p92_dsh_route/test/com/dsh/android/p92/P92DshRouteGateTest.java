package com.dsh.android.p92;
import com.dsh.android.p90.P90SendReceiptGate;
public final class P92DshRouteGateTest {
    static void ok(boolean good,String reason){if(!good)throw new AssertionError(reason);}
    static P90SendReceiptGate editor(boolean valid) {
        P90SendReceiptGate gate=new P90SendReceiptGate("turn_p92_12345",4);
        gate.injectionReceipt(true,valid?4:0,!valid,valid);
        return gate;
    }
    static P92DshRouteGate.Health health(boolean verified,String nativeOwner,String route) {
        return new P92DshRouteGate.Health(true,true,verified,false,
            "127.0.0.1:8787",nativeOwner,route);
    }
    public static void main(String[] ignored) {
        P92DshRouteGate invalid=new P92DshRouteGate(editor(false));
        ok(!invalid.preflight(health(true,"main","main_socket_and_driver_match")),"len0 must block");
        ok(!invalid.consumeOneAttempt(),"must not POST empty text");
        P92DshRouteGate unknown=new P92DshRouteGate(editor(true));
        ok(!unknown.preflight(health(false,"unknown","port_not_owned_by_main")),"mismatch must block");
        ok(!unknown.consumeOneAttempt(),"no unknown owner POST");
        P92DshRouteGate overlay=new P92DshRouteGate(editor(true));
        ok(overlay.preflight(health(true,"overlay","overlay_socket_and_driver_match")),"valid overlay");
        ok(overlay.consumeOneAttempt(),"single attempt");
        ok(!overlay.consumeOneAttempt(),"no second attempt");
        overlay.onHttpStatus(200);
        ok(!overlay.isConfirmed(),"HTTP200 is not model-turn confirmation");
        overlay.onTrustedUserTurn("wrongturn",true);
        ok(!overlay.isConfirmed(),"wrong turn does not confirm");
        overlay.onTrustedUserTurn("turn_p92_12345",true);
        ok(overlay.isConfirmed(),"verified correlated turn");
        P92DshRouteGate changed=new P92DshRouteGate(editor(true));
        ok(changed.preflight(health(true,"main","main_socket_and_driver_match")),"main ready");
        ok(changed.consumeOneAttempt(),"dispatch ready");
        changed.onHttpStatus(409);
        ok(changed.stage()==P92DshRouteGate.Stage.HTTP_REJECTED
           && "ORIGINAL_RUNTIME_OWNER_MISMATCH".equals(changed.reason()),"server 409 must be final");
        ok(!changed.canAutoRetry(),"409 no retry");
        P92DshRouteGate disconnected=new P92DshRouteGate(editor(true));
        ok(disconnected.preflight(health(true,"main","main_socket_and_driver_match")),"main preflight");
        ok(disconnected.consumeOneAttempt(),"one attempt");
        disconnected.onConnectionLost();
        ok(disconnected.stage()==P92DshRouteGate.Stage.UNKNOWN_AFTER_DISPATCH &&
           !disconnected.canAutoRetry(),"connection lost no blind retry");
        P92DshRouteGate ambiguous=new P92DshRouteGate(editor(true));
        ok(!ambiguous.preflight(new P92DshRouteGate.Health(true,true,true,true,
           "127.0.0.1:8787","main","main_socket_and_driver_match")),"ambiguous owner");
        P92DshRouteGate wrongListen=new P92DshRouteGate(editor(true));
        ok(!wrongListen.preflight(new P92DshRouteGate.Health(true,true,true,false,
           "127.0.0.1:1604","main","main_socket_and_driver_match")),"no direct 1604");
        System.out.println("P92_DSH_EDITOR_FAIL_CLOSED_BEFORE_OMNIGATE=PASS");
        System.out.println("P92_8787_VERIFIED_OWNER_PREFLIGHT_AND_409_FAIL_CLOSED=PASS");
        System.out.println("P92_ONE_SHOT_NO_AUTO_RETRY_AND_HTTP200_NOT_DELIVERY=PASS");
        System.out.println("P92_MAIN_AND_OVERLAY_OWNER_EXCLUSIVE=PASS");
    }
}
