package com.dsh.android.engine;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Captures the web-launch subset backed by an approved owner and workspace overlay. */
final class OriginalWebLaunch {
    static final String WORKSPACE_PATCH = "workspace.patch.yml";
    static final String ENTRY = "node_modules/@deepseek-ai/dsh/lib/bin.js";
    static final int MAX_PATCH_BYTES = 4096;
    // The fixed output of signed v138 writeWorkspacePatch() before its path line.
    private static final String WORKSPACE_PREFIX_SHA =
            "1c32ae4dd581f4ffcfa4fd4370c55ed3cd0f28984f732f34aebafc67e22c5e27";

    private final List<String> argv;
    private final Map<String, String> environment;
    private final File directory;
    private final Integer port;

    private OriginalWebLaunch(ProcessBuilder original, List<String> argv, Integer port) {
        this.argv = argv;
        environment = new HashMap<>(original.environment());
        directory = original.directory();
        this.port = port;
    }

    /** The caller supplies these paths and the bounded file from the trusted owner's layout. */
    static OriginalWebLaunch capture(ProcessBuilder original, File node, File entry,
            File workspace, File workspacePatch, byte[] patchBytes) throws IOException {
        require(original != null && node != null && entry != null && workspace != null && workspacePatch != null,
                "MAIN_LAUNCH_OWNER_LAYOUT");
        require(workspace.isAbsolute() && workspace.toPath().normalize().equals(workspace.toPath())
                && workspace.getPath().matches("/[A-Za-z0-9._/-]{1,1024}"), "MAIN_LAUNCH_WORKSPACE");
        require(node.isAbsolute() && entry.isAbsolute() && workspacePatch.isAbsolute()
                && WORKSPACE_PATCH.equals(workspacePatch.getName()), "MAIN_LAUNCH_OWNER_LAYOUT");
        require(workspace.equals(original.directory()) && validPipes(original), "MAIN_LAUNCH_STREAMS");
        List<String> argv = new ArrayList<>(original.command());
        List<String> fixed = Arrays.asList(node.getPath(), entry.getPath(), "--profile", "web",
                "--patch", workspacePatch.getPath());
        require((argv.size() == 7 || argv.size() == 9) && argv.subList(0, 6).equals(fixed)
                && "--no-open".equals(argv.get(argv.size() - 1)), "MAIN_LAUNCH_ARGUMENTS");
        Integer port = null;
        if (argv.size() == 9) {
            String value = argv.get(7);
            require("--port".equals(argv.get(6)) && value != null
                    && value.matches("0|[1-9][0-9]{0,4}"), "MAIN_LAUNCH_PORT");
            port = Integer.valueOf(value);
            require(port <= 65535, "MAIN_LAUNCH_PORT");
        }
        verifyWorkspacePatch(workspace, patchBytes);
        return new OriginalWebLaunch(original, argv, port);
    }

    private static void verifyWorkspacePatch(File workspace, byte[] bytes) throws IOException {
        byte[] suffix = ("    documentsDirectory: '" + workspace.getPath() + "'\n")
                .getBytes(StandardCharsets.UTF_8);
        require(bytes != null && bytes.length <= MAX_PATCH_BYTES && bytes.length > suffix.length,
                "MAIN_WORKSPACE_PATCH_SIZE");
        int prefixLength = bytes.length - suffix.length;
        require(Arrays.equals(suffix, Arrays.copyOfRange(bytes, prefixLength, bytes.length)),
                "MAIN_WORKSPACE_PATCH_OWNER");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(bytes, 0, prefixLength);
            StringBuilder hex = new StringBuilder(64);
            for (byte value : digest.digest()) {
                hex.append(Character.forDigit((value >>> 4) & 15, 16));
                hex.append(Character.forDigit(value & 15, 16));
            }
            require(WORKSPACE_PREFIX_SHA.contentEquals(hex), "MAIN_WORKSPACE_PATCH_SOURCE");
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IOException("MAIN_WORKSPACE_PATCH_SHA", unavailable);
        }
    }

    private static boolean validPipes(ProcessBuilder builder) {
        return builder.redirectErrorStream()
                && builder.redirectInput() == ProcessBuilder.Redirect.PIPE
                && builder.redirectOutput() == ProcessBuilder.Redirect.PIPE
                && builder.redirectError() == ProcessBuilder.Redirect.PIPE;
    }

    void requireSame(ProcessBuilder original) throws IOException {
        require(original != null && validPipes(original) && directory.equals(original.directory())
                && argv.equals(original.command()) && environment.equals(original.environment()),
                "MAIN_LAUNCH_CHANGED");
    }

    Integer port() { return port; }

    private static void require(boolean value, String code) throws IOException {
        if (!value) throw new IOException(code);
    }
}
