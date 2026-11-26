package com.dsh.android.engine;

import android.content.Context;
import android.content.ContextWrapper;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.List;

/** Prepares the reviewed original workspace launch subset in a fresh TEST owner. */
final class OriginalAndroidWebLaunch {
    final Object engine;
    final ProcessBuilder original;
    final OriginalWebLaunch plan;

    private OriginalAndroidWebLaunch(Object engine, ProcessBuilder original, OriginalWebLaunch plan) {
        this.engine = engine;
        this.original = original;
        this.plan = plan;
    }

    static OriginalAndroidWebLaunch prepare(Context host, Integer port) throws Exception {
        if (!"com.dsh.p51.networkprobe".equals(host.getPackageName()) || android.os.Process.isIsolated()) {
            throw new SecurityException("MAIN_LAUNCH_TEST_OWNER_REQUIRED");
        }
        Path root = Files.createTempDirectory(host.getCacheDir().toPath(), "original-launch-");
        Path home = root.resolve("home"), dshHome = home.resolve(".dsh");
        Path patch = dshHome.resolve(OriginalWebLaunch.WORKSPACE_PATCH);
        Path browserPatch = dshHome.resolve(OriginalBrowserPane.PATCH);
        Path browserEntry = dshHome.resolve(OriginalBrowserPane.ENTRY);
        Path workspace = root.resolve("workspace");
        try {
            Files.createDirectories(dshHome);
            Files.createDirectory(workspace);
            OriginalBrowserPane browser;
            try (InputStream input = host.getAssets().open(OriginalBrowserPane.ASSET)) {
                browser = OriginalBrowserPane.read(input);
            }
            // The original generator checks that this entry is a regular file.
            // Stage the verified bytes in this invocation's private TEST layout.
            Files.createDirectories(browserEntry.getParent());
            Files.write(browserEntry, browser.entryBytes(), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            Context owner = new ContextWrapper(host) {
                @Override public File getFilesDir() { return root.toFile(); }
                @Override public Context getApplicationContext() { return this; }
            };
            Class<?> type = Class.forName("com.dsh.android.EngineManager", true, host.getClassLoader());
            Constructor<?> constructor = type.getDeclaredConstructor(Context.class);
            constructor.setAccessible(true);
            Object engine = constructor.newInstance(owner);
            byte[] browserPatchBytes = generatePatch(type, engine, "writeBrowserPanePatch", browserPatch);
            byte[] workspacePatchBytes = generatePatch(type, engine, "writeWorkspacePatch", patch);
            File node = root.resolve("termux/usr/bin/node").toFile();
            File entry = root.resolve("engine").resolve(OriginalWebLaunch.ENTRY).toFile();
            Method buildEngineArgs = type.getDeclaredMethod("buildEngineArgs", File.class, File.class,
                    String.class, List.class, Integer.class);
            buildEngineArgs.setAccessible(true);
            @SuppressWarnings("unchecked")
            List<String> argv = (List<String>) buildEngineArgs.invoke(engine, node, entry, "web",
                    Arrays.asList(browserPatch.toFile(), patch.toFile()), port);
            ProcessBuilder original = new ProcessBuilder(argv).directory(workspace.toFile()).redirectErrorStream(true);
            OriginalWebLaunch plan = OriginalWebLaunch.capture(original, node, entry, workspace.toFile(),
                    patch.toFile(), workspacePatchBytes, browserPatch.toFile(), browserPatchBytes, browser);
            return new OriginalAndroidWebLaunch(engine, original, plan);
        } finally {
            Path lib = browserEntry.getParent();
            for (Path path : new Path[]{browserEntry, lib, lib.getParent(), lib.getParent().getParent(),
                    browserPatch, patch, workspace, dshHome, home, root}) Files.deleteIfExists(path);
        }
    }

    private static byte[] generatePatch(Class<?> type, Object engine, String method, Path patch) throws Exception {
        Method write = type.getDeclaredMethod(method);
        write.setAccessible(true);
        if (!patch.toFile().equals(write.invoke(engine)) || !Files.isRegularFile(patch, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("MAIN_LAUNCH_TEST_PATCH_REQUIRED");
        }
        try (InputStream input = Files.newInputStream(patch, LinkOption.NOFOLLOW_LINKS)) {
            return OriginalBrowserPane.readBounded(input, OriginalWebLaunch.MAX_PATCH_BYTES);
        }
    }
}
