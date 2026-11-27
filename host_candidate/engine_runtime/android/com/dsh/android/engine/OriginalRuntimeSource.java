package com.dsh.android.engine;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Process;

import com.dsh.android.p50.P50ModuleStream;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Base-APK source for the fixed, independently sealed runtime assets. */
final class OriginalRuntimeSource implements AutoCloseable {
    private static final String ORIGINAL_PACKAGE = "com.dsh.android";
    private static final String TEST_PACKAGE = "com.dsh.p51.networkprobe";
    private static final String ORIGINAL_CERTIFICATE =
            "90072b7de43e96999be92d99869ce5e5b7639b5f2449417b99a1790831b60ff8";
    private static final long MODULE_ARCHIVE_BYTES = 57_724_933L;

    private final ZipFile archive;

    private OriginalRuntimeSource(ZipFile archive) {
        this.archive = archive;
    }

    static OriginalRuntimeSource open(Context context) throws IOException {
        if (context == null || Process.isIsolated()) throw denied("MAIN_OWNER_RESOURCE_HOST");
        Context app = context.getApplicationContext();
        if (app == null) throw denied("MAIN_OWNER_RESOURCE_HOST");
        String packageName = app.getPackageName();
        boolean original = ORIGINAL_PACKAGE.equals(packageName);
        if (!original && !TEST_PACKAGE.equals(packageName)) throw denied("MAIN_OWNER_RESOURCE_PACKAGE");

        PackageInfo installed;
        try {
            // A lookup through this application context is scoped to its Android user.
            installed = app.getPackageManager().getPackageInfo(packageName,
                    original ? PackageManager.GET_SIGNING_CERTIFICATES : 0);
        } catch (PackageManager.NameNotFoundException missing) {
            throw denied("MAIN_OWNER_RESOURCE_PACKAGE");
        }
        if (installed == null) throw denied("MAIN_OWNER_RESOURCE_PACKAGE");
        ApplicationInfo live = installed.applicationInfo;
        ApplicationInfo current = app.getApplicationInfo();
        if (!packageName.equals(installed.packageName) || live == null || current == null
                || live.uid != Process.myUid() || current.uid != live.uid
                || live.sourceDir == null || !live.sourceDir.equals(current.sourceDir)
                || (live.splitSourceDirs != null && live.splitSourceDirs.length != 0)) {
            throw denied("MAIN_OWNER_RESOURCE_HOST");
        }
        if (original) {
            if (installed.signingInfo == null || installed.signingInfo.hasMultipleSigners()) {
                throw denied("MAIN_OWNER_RESOURCE_SIGNER");
            }
            Signature[] signers = installed.signingInfo.getApkContentsSigners();
            if (signers == null || signers.length != 1 || signers[0] == null) {
                throw denied("MAIN_OWNER_RESOURCE_SIGNER");
            }
            byte[] certificate = signers[0].toByteArray();
            if (!ORIGINAL_CERTIFICATE.equals(OriginalClientPlugin.sha(certificate, certificate.length))) {
                throw denied("MAIN_OWNER_RESOURCE_SIGNER");
            }
        }
        File baseApk = new File(live.sourceDir);
        if (!baseApk.isAbsolute()) throw denied("MAIN_OWNER_RESOURCE_HOST");
        try {
            return new OriginalRuntimeSource(new ZipFile(baseApk));
        } catch (IOException unreadable) {
            throw denied("MAIN_OWNER_RESOURCE_APK_OPEN");
        }
    }

    void streamEngine(OutputStream childInput) throws IOException {
        ZipEntry entry = archive.getEntry("assets/engine.bin");
        if (entry == null || entry.isDirectory() || entry.getSize() != MODULE_ARCHIVE_BYTES) {
            throw denied("MAIN_OWNER_RESOURCE_ENTRY");
        }
        try (InputStream original = archive.getInputStream(entry)) {
            P50ModuleStream.writeOriginalForService(original, childInput);
        }
    }

    OriginalClientPlugin clientPlugin(OriginalClientPlugin.Kind kind) throws IOException {
        ZipEntry entry = archive.getEntry("assets/" + kind.asset);
        if (entry == null || entry.isDirectory()) throw denied(kind.failure("ARCHIVE_LAYOUT"));
        try (InputStream source = archive.getInputStream(entry)) {
            return OriginalClientPlugin.read(kind, source);
        }
    }

    @Override public void close() throws IOException {
        archive.close();
    }

    static final class Denied extends IOException {
        private Denied(String code) { super(code); }
    }

    private static Denied denied(String code) { return new Denied(code); }
}
