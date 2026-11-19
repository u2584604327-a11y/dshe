package com.dsh.p311;

import dalvik.system.PathClassLoader;
import java.lang.reflect.Method;

/** P311 disposable Android35 shell-user probe: Class.forName(false), no app init. */
public final class TargetClassProbe {
    private static final String TARGET = "com.dsh.android.EngineManager$start$2";
    private static final String MISSING = "com.dsh.android.__P311_NEVER_EXISTS_37192";
    private TargetClassProbe() {}
    public static void main(String[] args) {
        if (args == null || args.length != 2 ||
                !("missing".equals(args[0]) || "target".equals(args[0])) ||
                !args[1].startsWith("/data/app/") || !args[1].endsWith("/base.apk")) {
            System.out.println("P311_INPUT_SCOPE=DENY");
            System.exit(2);
            return;
        }
        try {
            // Loader, not target class, is constructed. Nothing invokes original code.
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
            System.out.println("P311_TARGET_CLASS_INITIALIZED=NO_BY_CLASS_FORNAME_FALSE");
            System.out.println("P311_TARGET_METHOD_INVOKED=NO");
        } catch (Throwable denied) {
            // Do not disclose method refs, APK paths, private fields, logs or messages.
            System.out.println("P311_ART_TARGET_CLASS_LINK=DENY");
            System.exit(2);
        }
    }
}
