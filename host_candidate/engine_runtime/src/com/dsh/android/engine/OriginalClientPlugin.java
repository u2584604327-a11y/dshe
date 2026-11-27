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

/** Fixed client plugin archives distributed by the signed v138 APK. */
final class OriginalClientPlugin {
    enum Kind {
        BROWSER("browser-pane", "dsh-android-browser-pane", 14501,
                "87066b836f6c0d9396520b011eacd918e11ecf6323a9a17709e58287a175e377",
                "b50b9f51870598bca0783374c4c2650fb0548a93042028a8c45698f95394e424",
                565, 1402, 34879),
        MOBILE("mobile-ui", "dsh-android-mobile", 269232,
                "8a7bcd8884d8e71c6359d574c19d4547b57df841f13d415e22ae92a026b99e03",
                "2d726f94e2393eee6c90e41707ef7ce4a2744455cf6215d1b1be0a93a9039d9d",
                572, 15983, 621475);

        final String asset, patch, entry, script, archiveSha, patchPrefixSha;
        private final int archiveLength;
        private final int[] lengths;

        Kind(String directory, String id, int archiveLength, String archiveSha, String patchPrefixSha,
                int... lengths) {
            asset = directory + ".zip";
            patch = directory + ".patch.yml";
            entry = directory + "/" + id + "/lib/index.js";
            script = id + "/client.js";
            this.archiveLength = archiveLength;
            this.archiveSha = archiveSha;
            this.patchPrefixSha = patchPrefixSha;
            this.lengths = lengths;
        }

        String failure(String reason) { return "MAIN_" + name() + "_" + reason; }
    }

    // Fixed order on the authenticated pipe. No path comes from the wire.
    private static final String[] MEMBERS = {"package.json", "lib/index.js", "lib/client.js"};
    final Kind kind;
    private final byte[][] contents;

    private OriginalClientPlugin(Kind kind, byte[][] contents) {
        this.kind = kind;
        this.contents = contents;
    }

    static OriginalClientPlugin read(Kind kind, InputStream source) throws IOException {
        byte[] sealed = readBounded(source, kind.archiveLength);
        if (sealed.length != kind.archiveLength || !kind.archiveSha.equals(sha(sealed, sealed.length))) {
            throw new IOException(kind.failure("ARCHIVE_SEAL"));
        }
        Map<String, byte[]> files = new HashMap<>();
        boolean directory = false;
        try (ZipInputStream archive = new ZipInputStream(new ByteArrayInputStream(sealed))) {
            for (ZipEntry entry; (entry = archive.getNextEntry()) != null; ) {
                String path = entry.getName();
                if (entry.isDirectory() && "lib/".equals(path) && !directory) {
                    directory = true;
                    if (archive.read() != -1) throw new IOException(kind.failure("ARCHIVE_LAYOUT"));
                    continue;
                }
                int slot = -1;
                for (int i = 0; i < MEMBERS.length; i++) if (MEMBERS[i].equals(path)) slot = i;
                if (slot == -1 || entry.isDirectory() || files.containsKey(path)) {
                    throw new IOException(kind.failure("ARCHIVE_LAYOUT"));
                }
                byte[] data = readBounded(archive, kind.lengths[slot]);
                if (data.length != kind.lengths[slot]) throw new IOException(kind.failure("ARCHIVE_MEMBER_LENGTH"));
                files.put(path, data);
            }
        }
        if (!directory || files.size() != MEMBERS.length) throw new IOException(kind.failure("ARCHIVE_LAYOUT"));
        byte[][] ordered = new byte[MEMBERS.length][];
        for (int i = 0; i < MEMBERS.length; i++) ordered[i] = files.get(MEMBERS[i]);
        return new OriginalClientPlugin(kind, ordered);
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
            if (count == 0 || count > limit - bytes.size()) throw new IOException("MAIN_CLIENT_PLUGIN_RESOURCE_BOUND");
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
            throw new IOException("MAIN_CLIENT_PLUGIN_RESOURCE_SHA", unavailable);
        }
    }
}
