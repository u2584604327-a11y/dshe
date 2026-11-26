package com.dsh.android.engine;

import android.content.Context;
import android.content.ContextWrapper;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Collections;
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
        Path workspace = root.resolve("workspace");
        try {
            Files.createDirectories(dshHome);
            Files.createDirectory(workspace);
            Context owner = new ContextWrapper(host) {
                @Override public File getFilesDir() { return root.toFile(); }
                @Override public Context getApplicationContext() { return this; }
            };
            Class<?> type = Class.forName("com.dsh.android.EngineManager", true, host.getClassLoader());
            Constructor<?> constructor = type.getDeclaredConstructor(Context.class);
            constructor.setAccessible(true);
            Object engine = constructor.newInstance(owner);
            Method writeWorkspacePatch = type.getDeclaredMethod("writeWorkspacePatch");
            writeWorkspacePatch.setAccessible(true);
            if (!patch.toFile().equals(writeWorkspacePatch.invoke(engine)) ||
                    !Files.isRegularFile(patch, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("MAIN_LAUNCH_TEST_PATCH_REQUIRED");
            }
            File node = root.resolve("termux/usr/bin/node").toFile();
            File entry = root.resolve("engine").resolve(OriginalWebLaunch.ENTRY).toFile();
            Method buildEngineArgs = type.getDeclaredMethod("buildEngineArgs", File.class, File.class,
                    String.class, List.class, Integer.class);
            buildEngineArgs.setAccessible(true);
            @SuppressWarnings("unchecked")
            List<String> argv = (List<String>) buildEngineArgs.invoke(engine, node, entry, "web",
                    Collections.singletonList(patch.toFile()), port);
            ProcessBuilder original = new ProcessBuilder(argv).directory(workspace.toFile()).redirectErrorStream(true);
            try (InputStream input = Files.newInputStream(patch, LinkOption.NOFOLLOW_LINKS)) {
                ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                byte[] block = new byte[1024];
                for (int count; (count = input.read(block)) != -1; ) {
                    if (count > OriginalWebLaunch.MAX_PATCH_BYTES - bytes.size()) {
                        throw new IOException("MAIN_WORKSPACE_PATCH_SIZE");
                    }
                    bytes.write(block, 0, count);
                }
                OriginalWebLaunch plan = OriginalWebLaunch.capture(original, node, entry, workspace.toFile(),
                        patch.toFile(), bytes.toByteArray());
                return new OriginalAndroidWebLaunch(engine, original, plan);
            }
        } finally {
            for (Path path : new Path[]{patch, workspace, dshHome, home, root}) Files.deleteIfExists(path);
        }
    }
}
