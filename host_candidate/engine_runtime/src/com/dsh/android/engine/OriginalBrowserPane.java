package com.dsh.android.engine;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** The single browser-pane archive distributed by the signed v138 APK. */
final class OriginalBrowserPane {
    static final String ASSET = "browser-pane.zip";
    static final String PATCH = "browser-pane.patch.yml";
    static final String ENTRY = "browser-pane/dsh-android-browser-pane/lib/index.js";
    private static final int ARCHIVE_LENGTH = 14501;
    private static final String ARCHIVE_SHA = "87066b836f6c0d9396520b011eacd918e11ecf6323a9a17709e58287a175e377";
    // Fixed order on the authenticated pipe. No path comes from the wire.
    private static final String[] MEMBERS = {"package.json", "lib/index.js", "lib/client.js"};
    private static final int[] LENGTHS = {565, 1402, 34879};
    private final byte[][] contents;

    private OriginalBrowserPane(byte[][] contents) { this.contents = contents; }

    static OriginalBrowserPane read(InputStream source) throws IOException {
        byte[] sealed = readBounded(source, ARCHIVE_LENGTH);
        if (sealed.length != ARCHIVE_LENGTH || !ARCHIVE_SHA.equals(sha(sealed, sealed.length))) {
            throw new IOException("MAIN_BROWSER_ARCHIVE_SEAL");
        }
        Map<String, byte[]> files = new HashMap<>();
        boolean directory = false;
        try (ZipInputStream archive = new ZipInputStream(new ByteArrayInputStream(sealed))) {
            for (ZipEntry entry; (entry = archive.getNextEntry()) != null; ) {
                String path = entry.getName();
                if (entry.isDirectory() && "lib/".equals(path) && !directory) {
                    directory = true;
                    if (archive.read() != -1) throw new IOException("MAIN_BROWSER_ARCHIVE_LAYOUT");
                    continue;
                }
                int slot = -1;
                for (int i = 0; i < MEMBERS.length; i++) if (MEMBERS[i].equals(path)) slot = i;
                if (slot == -1 || entry.isDirectory() || files.containsKey(path)) {
                    throw new IOException("MAIN_BROWSER_ARCHIVE_LAYOUT");
                }
                byte[] data = readBounded(archive, LENGTHS[slot]);
                if (data.length != LENGTHS[slot]) throw new IOException("MAIN_BROWSER_ARCHIVE_MEMBER_LENGTH");
                files.put(path, data);
            }
        }
        if (!directory || files.size() != MEMBERS.length) throw new IOException("MAIN_BROWSER_ARCHIVE_LAYOUT");
        byte[][] ordered = new byte[MEMBERS.length][];
        for (int i = 0; i < MEMBERS.length; i++) ordered[i] = files.get(MEMBERS[i]);
        return new OriginalBrowserPane(ordered);
    }

    byte[] entryBytes() { return contents[1].clone(); }
    byte[] clientBytes() { return contents[2].clone(); }

    byte[] framedBytes() {
        ByteArrayOutputStream joined = new ByteArrayOutputStream();
        for (byte[] bytes : contents) joined.write(bytes, 0, bytes.length);
        return joined.toByteArray();
    }

    static byte[] readBounded(InputStream input, int limit) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] block = new byte[1024];
        for (int count; (count = input.read(block)) != -1; ) {
            if (count == 0 || count > limit - bytes.size()) throw new IOException("MAIN_BROWSER_RESOURCE_BOUND");
            bytes.write(block, 0, count);
        }
        return bytes.toByteArray();
    }

    static String sha(byte[] data, int length) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(data, 0, length);
            StringBuilder hex = new StringBuilder(64);
            for (byte value : digest.digest()) {
                hex.append(Character.forDigit((value >>> 4) & 15, 16));
                hex.append(Character.forDigit(value & 15, 16));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IOException("MAIN_BROWSER_RESOURCE_SHA", unavailable);
        }
    }
}
