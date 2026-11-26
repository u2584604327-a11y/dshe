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
    private static final String BROWSER_PREFIX_SHA =
            "b50b9f51870598bca0783374c4c2650fb0548a93042028a8c45698f95394e424";

    private final List<String> argv;
    private final Map<String, String> environment;
    private final File directory;
    private final Integer port;
    final OriginalBrowserPane browser;

    private OriginalWebLaunch(ProcessBuilder original, List<String> argv, Integer port, OriginalBrowserPane browser) {
        this.argv = argv;
        environment = new HashMap<>(original.environment());
        directory = original.directory();
        this.port = port;
        this.browser = browser;
    }

    /** The caller supplies these paths and the bounded file from the trusted owner's layout. */
    static OriginalWebLaunch capture(ProcessBuilder original, File node, File entry,
            File workspace, File workspacePatch, byte[] patchBytes, File browserPatch,
            byte[] browserPatchBytes, OriginalBrowserPane browser) throws IOException {
        require(original != null && node != null && entry != null && workspace != null && workspacePatch != null
                        && browserPatch != null && browser != null,
                "MAIN_LAUNCH_OWNER_LAYOUT");
        require(workspace.isAbsolute() && workspace.toPath().normalize().equals(workspace.toPath())
                && workspace.getPath().matches("/[A-Za-z0-9._/-]{1,1024}"), "MAIN_LAUNCH_WORKSPACE");
        require(node.isAbsolute() && entry.isAbsolute() && workspacePatch.isAbsolute()
                && WORKSPACE_PATCH.equals(workspacePatch.getName())
                && new File(workspacePatch.getParentFile(), OriginalBrowserPane.PATCH).equals(browserPatch),
                "MAIN_LAUNCH_OWNER_LAYOUT");
        require(workspace.equals(original.directory()) && validPipes(original), "MAIN_LAUNCH_STREAMS");
        List<String> argv = new ArrayList<>(original.command());
        List<String> fixed = Arrays.asList(node.getPath(), entry.getPath(), "--profile", "web",
                "--patch", browserPatch.getPath(), "--patch", workspacePatch.getPath());
        int options = fixed.size();
        require((argv.size() == options + 1 || argv.size() == options + 3) && argv.subList(0, options).equals(fixed)
                && "--no-open".equals(argv.get(argv.size() - 1)), "MAIN_LAUNCH_ARGUMENTS");
        Integer port = null;
        if (argv.size() == options + 3) {
            String value = argv.get(options + 1);
            require("--port".equals(argv.get(options)) && value != null
                    && value.matches("0|[1-9][0-9]{0,4}"), "MAIN_LAUNCH_PORT");
            port = Integer.valueOf(value);
            require(port <= 65535, "MAIN_LAUNCH_PORT");
        }
        verifyWorkspacePatch(workspace, patchBytes);
        verifyBrowserPatch(new File(browserPatch.getParentFile(), OriginalBrowserPane.ENTRY), browserPatchBytes);
        return new OriginalWebLaunch(original, argv, port, browser);
    }

    private static void verifyBrowserPatch(File entry, byte[] bytes) throws IOException {
        require(entry.getPath().matches("/[A-Za-z0-9._/-]{1,1024}")
                && entry.toPath().normalize().equals(entry.toPath()), "MAIN_BROWSER_PATCH_OWNER");
        byte[] suffix = (entry.getPath() + "'\n").getBytes(StandardCharsets.UTF_8);
        require(bytes != null && bytes.length <= MAX_PATCH_BYTES && bytes.length > suffix.length, "MAIN_BROWSER_PATCH_SIZE");
        int prefixLength = bytes.length - suffix.length;
        require(Arrays.equals(suffix, Arrays.copyOfRange(bytes, prefixLength, bytes.length)), "MAIN_BROWSER_PATCH_OWNER");
        require(BROWSER_PREFIX_SHA.equals(OriginalBrowserPane.sha(bytes, prefixLength)), "MAIN_BROWSER_PATCH_SOURCE");
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
