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
final class OriginalAndroidWebLaunch implements AutoCloseable {
    final Object engine;
    final ProcessBuilder original;
    final OriginalWebLaunch plan;
    private final Path root;

    private OriginalAndroidWebLaunch(Object engine, ProcessBuilder original, OriginalWebLaunch plan, Path root) {
        this.engine = engine;
        this.original = original;
        this.plan = plan;
        this.root = root;
    }

    static OriginalAndroidWebLaunch prepare(Context host, Integer port) throws Exception {
        if (!"com.dsh.p51.networkprobe".equals(host.getPackageName()) || android.os.Process.isIsolated()) {
            throw new SecurityException("MAIN_LAUNCH_TEST_OWNER_REQUIRED");
        }
        Path root = Files.createTempDirectory(host.getCacheDir().toPath(), "original-launch-");
        Path home = root.resolve("home"), dshHome = home.resolve(".dsh");
        Path patch = dshHome.resolve(OriginalWebLaunch.WORKSPACE_PATCH);
        OriginalClientPlugin.Kind mobileKind = OriginalClientPlugin.Kind.MOBILE;
        OriginalClientPlugin.Kind browserKind = OriginalClientPlugin.Kind.BROWSER;
        Path mobilePatch = dshHome.resolve(mobileKind.patch), mobileEntry = dshHome.resolve(mobileKind.entry);
        Path browserPatch = dshHome.resolve(browserKind.patch), browserEntry = dshHome.resolve(browserKind.entry);
        Path workspace = root.resolve("workspace");
        try {
            Files.createDirectories(dshHome);
            Files.createDirectory(workspace);
            OriginalClientPlugin mobile = stagePlugin(host, mobileKind, mobileEntry);
            OriginalClientPlugin browser = stagePlugin(host, browserKind, browserEntry);
            Context owner = new ContextWrapper(host) {
                @Override public File getFilesDir() { return root.toFile(); }
                @Override public Context getApplicationContext() { return this; }
            };
            Class<?> type = Class.forName("com.dsh.android.EngineManager", true, host.getClassLoader());
            Constructor<?> constructor = type.getDeclaredConstructor(Context.class);
            constructor.setAccessible(true);
            Object engine = constructor.newInstance(owner);
            byte[] mobilePatchBytes = generatePatch(type, engine, "writeMobileUiPatch", mobilePatch);
            byte[] browserPatchBytes = generatePatch(type, engine, "writeBrowserPanePatch", browserPatch);
            byte[] workspacePatchBytes = generatePatch(type, engine, "writeWorkspacePatch", patch);
            File node = root.resolve("termux/usr/bin/node").toFile();
            File entry = root.resolve("engine").resolve(OriginalWebLaunch.ENTRY).toFile();
            Method buildEngineArgs = type.getDeclaredMethod("buildEngineArgs", File.class, File.class,
                    String.class, List.class, Integer.class);
            buildEngineArgs.setAccessible(true);
            @SuppressWarnings("unchecked")
            List<String> argv = (List<String>) buildEngineArgs.invoke(engine, node, entry, "web",
                    Arrays.asList(mobilePatch.toFile(), browserPatch.toFile(), patch.toFile()), port);
            ProcessBuilder original = new ProcessBuilder(argv).directory(workspace.toFile()).redirectErrorStream(true);
            OriginalWebLaunch plan = OriginalWebLaunch.capture(original, node, entry, workspace.toFile(),
                    patch.toFile(), workspacePatchBytes, mobilePatch.toFile(), mobilePatchBytes, mobile,
                    browserPatch.toFile(), browserPatchBytes, browser);
            return new OriginalAndroidWebLaunch(engine, original, plan, root);
        } catch (Exception | LinkageError failure) {
            try { removeLayout(root); } catch (IOException cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    @Override public void close() throws IOException {
        removeLayout(root);
    }

    private static void removeLayout(Path root) throws IOException {
        Path home = root.resolve("home"), dshHome = home.resolve(".dsh");
        for (OriginalClientPlugin.Kind kind : OriginalClientPlugin.Kind.values()) {
            clearPlugin(dshHome.resolve(kind.entry));
            Files.deleteIfExists(dshHome.resolve(kind.patch));
        }
        for (Path path : new Path[]{dshHome.resolve(OriginalWebLaunch.WORKSPACE_PATCH),
                root.resolve("workspace"), dshHome, home, root}) {
            Files.deleteIfExists(path);
        }
    }

    private static OriginalClientPlugin stagePlugin(Context host, OriginalClientPlugin.Kind kind, Path entry)
            throws IOException {
        OriginalClientPlugin plugin;
        try (InputStream input = host.getAssets().open(kind.asset)) {
            plugin = OriginalClientPlugin.read(kind, input);
        }
        // The signed patch generator requires a regular entry in this private layout.
        Files.createDirectories(entry.getParent());
        Files.write(entry, plugin.entryBytes(), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        return plugin;
    }

    private static void clearPlugin(Path entry) throws IOException {
        Path lib = entry.getParent();
        for (Path path : new Path[]{entry, lib, lib.getParent(), lib.getParent().getParent()}) {
            Files.deleteIfExists(path);
        }
    }

    private static byte[] generatePatch(Class<?> type, Object engine, String method, Path patch) throws Exception {
        Method write = type.getDeclaredMethod(method);
        write.setAccessible(true);
        if (!patch.toFile().equals(write.invoke(engine)) || !Files.isRegularFile(patch, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("MAIN_LAUNCH_TEST_PATCH_REQUIRED");
        }
        try (InputStream input = Files.newInputStream(patch, LinkOption.NOFOLLOW_LINKS)) {
            return OriginalClientPlugin.readBounded(input, OriginalWebLaunch.MAX_PATCH_BYTES);
        }
    }
}
