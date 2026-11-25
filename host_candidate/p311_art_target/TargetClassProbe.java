package com.dsh.p311;

import dalvik.system.PathClassLoader;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/** Disposable shell-UID class-load and original coroutine entry controls. */
public final class TargetClassProbe {
    private static final String TARGET = "com.dsh.android.EngineManager$start$2";
    private static final String MISSING = "com.dsh.android.__P311_NEVER_EXISTS_37192";
    private TargetClassProbe() {}
    public static void main(String[] args) {
        if (args == null || args.length != 2 ||
                !("missing".equals(args[0]) || "target".equals(args[0]) ||
                  "failure".equals(args[0]) || "post-return".equals(args[0])) ||
                !args[1].startsWith("/data/app/") || !args[1].endsWith("/base.apk")) {
            System.out.println("P311_INPUT_SCOPE=DENY");
            System.exit(2);
            return;
        }
        try {
            PathClassLoader loader = new PathClassLoader(args[1],
                    TargetClassProbe.class.getClassLoader());
            if ("missing".equals(args[0])) {
                try {
                    Class.forName(MISSING, false, loader);
                    System.out.println("P311_NEGATIVE_MISSING_CLASS=DENY");
                    System.exit(2);
                } catch (ClassNotFoundException expected) {
                    System.out.println("P311_NEGATIVE_MISSING_CLASS=PASS");
                }
                return;
            }
            Class<?> found = Class.forName(TARGET, false, loader);
            if (!TARGET.equals(found.getName()) || found.getClassLoader() != loader) {
                System.out.println("P311_TARGET_LOADER_IDENTITY=DENY");
                System.exit(2);
                return;
            }
            System.out.println("P311_ANDROID35_TARGET_CLASS_LOADER=PASS_NARROW");
            Method method = found.getDeclaredMethod("invokeSuspend", Object.class);
            if (method.getReturnType() != Object.class ||
                    !TARGET.equals(method.getDeclaringClass().getName())) {
                System.out.println("P311_TARGET_REFLECTIVE_SIGNATURE=DENY");
                System.exit(2);
                return;
            }
            System.out.println("P311_TARGET_INVOKESUSPEND_SIGNATURE=PASS_NARROW");
            if ("target".equals(args[0])) {
                System.out.println("P311_TARGET_CLASS_INITIALIZED=NO_BY_CLASS_FORNAME_FALSE");
                System.out.println("P311_TARGET_METHOD_INVOKED=NO");
                return;
            }
            exerciseCoroutine(loader, found, method, "failure".equals(args[0]));
        } catch (Throwable denied) {
            // Do not disclose method refs, APK paths, private fields, logs or messages.
            System.out.println("P311_ART_TARGET_CLASS_LINK=DENY");
            System.exit(2);
        }
    }

    private static void exerciseCoroutine(ClassLoader loader, Class<?> target, Method entry,
            boolean failBeforeHelper) throws ReflectiveOperationException {
        Class<?> owner = Class.forName("com.dsh.android.EngineManager", false, loader);
        Class<?> continuation = Class.forName("kotlin.coroutines.Continuation", false, loader);
        Constructor<?> constructor = target.getDeclaredConstructor(owner, continuation);
        constructor.setAccessible(true);
        entry.setAccessible(true);
        // The null owner bounds this probe to entry. The positive control must
        // reach the original owner access immediately after the P245 helper.
        Object coroutine = constructor.newInstance(null, null);
        IOException injected = new IOException("P311_CONTROLLED_RESUME_FAILURE");
        Object result;
        if (failBeforeHelper) {
            Class<?> resultKt = Class.forName("kotlin.ResultKt", false, loader);
            result = resultKt.getMethod("createFailure", Throwable.class).invoke(null, injected);
        } else {
            result = Class.forName("kotlin.Unit", false, loader).getField("INSTANCE").get(null);
        }
        System.out.println("P311_PROBE_PID=" + android.os.Process.myPid());
        try {
            entry.invoke(coroutine, result);
        } catch (InvocationTargetException observed) {
            Throwable cause = observed.getCause();
            if (failBeforeHelper && cause == injected) {
                System.out.println("P311_INVOKESUSPEND_RESUME_FAILURE_RETHROWN=PASS");
                return;
            }
            if (!failBeforeHelper && cause instanceof NullPointerException) {
                StackTraceElement[] trace = cause.getStackTrace();
                if (trace.length >= 2 && owner.getName().equals(trace[0].getClassName()) &&
                        "access$getProcess$p".equals(trace[0].getMethodName()) &&
                        TARGET.equals(trace[1].getClassName()) && "invokeSuspend".equals(trace[1].getMethodName())) {
                    System.out.println("P311_INVOKESUSPEND_POST_HELPER_OWNER_GUARD=PASS");
                    return;
                }
            }
        }
        throw new IllegalStateException("unexpected coroutine control flow");
    }
}
