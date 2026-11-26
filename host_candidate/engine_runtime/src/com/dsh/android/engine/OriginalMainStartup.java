package com.dsh.android.engine;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Checks the original web service while its launch URL is still private. */
public final class OriginalMainStartup {
    private static final String PREFIX = "dsh web: ";
    private static final String RETURNED = "ORIGINAL_MAIN_ENTRY_RETURNED_NOT_READY_ATTESTATION";
    private static final String FRONTEND_SCRIPT = "/assets/index-CN7NIWNw.js";
    private static final String FRONTEND_SHA =
            "4bc914bfbb6adbdd63953a29f63835eb7127defd2a973149d64cdab489f1a9a5";
    private static final Pattern TARGET = Pattern.compile("/\\?token=[A-Za-z0-9_-]{43}");
    private static final Pattern CHILD_DENIAL = Pattern.compile("ORIGINAL_MAIN_DENY=[A-Z0-9_]{1,64}");
    private static final Pattern PLUGIN_COMBO = Pattern.compile(
            "plugins/\\?\\?([A-Za-z0-9_@./,-]{1,3000})&(?:amp;)?rev=([a-f0-9]{12})(?![a-f0-9])");
    private static final String BROWSER_SCRIPT = "dsh-android-browser-pane/client.js";
    private final HttpProcessTransport process;
    private final int port;
    private final String target;
    private final Capture capture;
    private final AtomicBoolean verificationStarted = new AtomicBoolean();

    private OriginalMainStartup(HttpProcessTransport process, int port, Capture capture) {
        this.process = process;
        this.port = port;
        this.capture = capture;
        this.target = capture.target;
    }

    private static final class Capture {
        final String target;
        final String row;
        final InputStream tail;

        Capture(String target, String row, InputStream tail) {
            this.target = target;
            this.row = row;
            this.tail = tail;
        }
    }

    /** Read stdout privately through the startup marker, retaining its buffered tail. */
    static OriginalMainStartup await(HttpProcessTransport process)
            throws IOException, InterruptedException {
        int port = process.port();
        CompletableFuture<Capture> output = new CompletableFuture<>();
        InputStream stdout = process.claimMainStartupOutput();
        Thread reader = new Thread(() -> collect(stdout, port, output),
                "dsh-private-startup-output");
        reader.setDaemon(true);
        reader.start();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        try {
            Capture capture = output.get(deadline - System.nanoTime(), TimeUnit.NANOSECONDS);
            long remaining = Math.max(0, deadline - System.nanoTime());
            if (!process.awaitListening(remaining, TimeUnit.NANOSECONDS)) throw denied("MAIN_LISTEN");
            require(process.ownsListener(port), "MAIN_LISTENER_REVOKED");
            return new OriginalMainStartup(process, port, capture);
        } catch (TimeoutException failure) {
            throw denied("MAIN_STARTUP_OUTPUT_TIMEOUT");
        } catch (ExecutionException failure) {
            if (failure.getCause() instanceof IOException) throw (IOException) failure.getCause();
            throw denied("MAIN_STARTUP_OUTPUT");
        }
    }

    private static void collect(InputStream stdout, int port, CompletableFuture<Capture> output) {
        InputStream input = new BufferedInputStream(stdout);
        try {
            String candidate = null;
            String launchLine = null;
            int bytes = 0;
            String row;
            while ((row = line(input, 8192)) != null) {
                bytes += row.length() + 1;
                require(bytes <= 65536, "MAIN_STARTUP_OUTPUT_BOUND");
                require(!CHILD_DENIAL.matcher(row).matches(), "MAIN_CHILD_REJECTED");
                if (row.startsWith(PREFIX)) {
                    require(candidate == null, "MAIN_DUPLICATE_STARTUP_URL");
                    candidate = launchTarget(row, port);
                    launchLine = row;
                }
                if (RETURNED.equals(row)) {
                    require(candidate != null, "MAIN_STARTUP_URL_MISSING");
                    output.complete(new Capture(candidate, launchLine, input));
                    return;
                }
            }
            output.completeExceptionally(denied("MAIN_STARTUP_OUTPUT_EOF"));
        } catch (IOException failure) {
            output.completeExceptionally(failure instanceof Denied ? failure : denied("MAIN_STARTUP_OUTPUT"));
        }
        try { input.close(); } catch (IOException ignored) { /* Original failure remains primary. */ }
    }

    static String launchTarget(String row, int port) throws IOException {
        String ownPrefix = PREFIX + "http://127.0.0.1:" + port;
        require(port > 0 && port <= 65535 && row.startsWith(ownPrefix), "MAIN_PRIVATE_URL");
        String target = row.substring(ownPrefix.length());
        require(TARGET.matcher(target).matches(), "MAIN_PRIVATE_URL");
        return target;
    }

    int port() { return port; }
    String privateTarget() { return target; }
    String privateUrl() { return "http://127.0.0.1:" + port + target; }

    /** A proof can be issued only after this transport's actual HTTP checks. */
    static final class ReadyProof {
        private final HttpProcessTransport owner;
        private final int port;
        private final byte[] urlDigest;
        private final int urlLength;

        private ReadyProof(HttpProcessTransport owner, int port, String url) {
            this.owner = owner;
            this.port = port;
            urlDigest = sha(url.getBytes(StandardCharsets.UTF_8));
            urlLength = url.length();
        }

        boolean isCurrent(HttpProcessTransport transport) {
            return owner == transport && owner.ownsListener(port);
        }

        boolean matches(HttpProcessTransport transport, String url) {
            return url != null && url.length() == urlLength && isCurrent(transport)
                    && MessageDigest.isEqual(urlDigest, sha(url.getBytes(StandardCharsets.UTF_8)))
                    && isCurrent(transport);
        }

        InputStream verifiedOutput(Capture capture) {
            final byte[] row = (capture.row + "\n").getBytes(StandardCharsets.US_ASCII);
            InputStream prefix = new ByteArrayInputStream(row) {
                @Override public synchronized int read() { return isCurrent(owner) ? super.read() : -1; }
                @Override public synchronized int read(byte[] bytes, int offset, int size) {
                    return isCurrent(owner) ? super.read(bytes, offset, size) : -1;
                }
                @Override public synchronized void close() { Arrays.fill(row, (byte) 0); }
            };
            return new SequenceInputStream(prefix, capture.tail);
        }
    }

    String verifyForReady() throws IOException {
        require(verificationStarted.compareAndSet(false, true), "MAIN_READY_PROOF_ALREADY_ATTEMPTED");
        String cookie = authenticate();
        verifyFrontend(cookie);
        ReadyProof proof = new ReadyProof(process, port, privateUrl());
        InputStream output = proof.verifiedOutput(capture);
        try {
            process.attachReadyProof(proof, output);
        } catch (IOException failure) {
            try { output.close(); } catch (IOException ignored) { /* Keep the admission error. */ }
            throw failure;
        }
        return cookie;
    }

    /** Invoked at the original regex call, before it can release the Ready latch. */
    public static boolean permitsVerifiedAnnouncement(Process process, CharSequence line) {
        if (!(process instanceof HttpProcessTransport) || !(line instanceof String)) return false;
        String announcement = (String) line;
        return announcement.startsWith(PREFIX) && announcement.length() <= 128
                && ((HttpProcessTransport) process).hasVerifiedReadyUrl(announcement.substring(PREFIX.length()));
    }

    /** Invoked again immediately before the original Ready state publisher. */
    public static void requireVerifiedReady(Process process, String url) throws IOException {
        require(process instanceof HttpProcessTransport
                && ((HttpProcessTransport) process).hasVerifiedReadyUrl(url), "MAIN_READY_PROOF_REQUIRED");
    }

    /** Use only a socket owned by this transport. No shared cookie jar or redirect. */
    private String authenticate() throws IOException {
        require(request("/", null, 16384).status == 401, "MAIN_UNAUTHENTICATED");
        Reply login = request(target, null, 16384);
        require(login.status == 303 && "./".equals(login.headers.get("location"))
                && "no-store".equals(login.headers.get("cache-control"))
                && "no-referrer".equals(login.headers.get("referrer-policy")), "MAIN_AUTH_REDIRECT");
        String header = login.headers.get("set-cookie");
        require(header != null, "MAIN_COOKIE_MISSING");
        int separator = header.indexOf(';');
        require(separator > 0, "MAIN_COOKIE_ATTRIBUTES");
        String cookie = header.substring(0, separator);
        String authority = port == 80 ? "127.0.0.1" : "127.0.0.1:" + port;
        String name = Base64.getUrlEncoder().withoutPadding().encodeToString(
                sha(authority.getBytes(StandardCharsets.US_ASCII)));
        require(cookie.matches("dsh-auth-" + name + "=v1\\.[A-Za-z0-9_-]{1,512}\\.[A-Za-z0-9_-]{43}"),
                "MAIN_COOKIE_AUTHORITY");
        String attributes = header.substring(separator);
        require(attributes.contains("; Path=/;") && attributes.endsWith("; HttpOnly; SameSite=Strict"),
                "MAIN_COOKIE_ATTRIBUTES");
        return cookie;
    }

    private void verifyFrontend(String cookie) throws IOException {
        Reply index = request("/", cookie, 65536);
        String html = new String(index.body, StandardCharsets.UTF_8);
        require(index.status == 200 && html.contains("src=\"." + FRONTEND_SCRIPT + "\""), "MAIN_FRONTEND");
        Reply script = request(FRONTEND_SCRIPT, null, 1024 * 1024);
        require(script.status == 200 && FRONTEND_SHA.equals(hex(sha(script.body))), "MAIN_ORIGINAL_JS_BYTES");
        OriginalBrowserPane browser = process.browserPane();
        if (browser != null) verifyBrowserBundle(html, cookie, browser);
        require(process.ownsListener(port), "MAIN_LISTENER_REVOKED");
    }

    private void verifyBrowserBundle(String html, String cookie, OriginalBrowserPane browser) throws IOException {
        Matcher combos = PLUGIN_COMBO.matcher(html);
        while (combos.find()) {
            String members = combos.group(1);
            if (!Arrays.asList(members.split(",")).contains(BROWSER_SCRIPT)) continue;
            Reply bundle = request("/plugins/??" + members + "&rev=" + combos.group(2), cookie, 2 * 1024 * 1024);
            require(bundle.status == 200 && new String(bundle.body, StandardCharsets.ISO_8859_1)
                    .contains(new String(browser.clientBytes(), StandardCharsets.ISO_8859_1)), "MAIN_BROWSER_CLIENT_BYTES");
            return;
        }
        throw denied("MAIN_BROWSER_CLIENT_NOT_MOUNTED");
    }

    void verifyRetiredCredentials(String retiredTarget, String retiredCookie) throws IOException {
        require(retiredTarget != null && retiredCookie != null && TARGET.matcher(retiredTarget).matches(),
                "MAIN_RETIRED_CREDENTIALS");
        require(request(retiredTarget, null, 16384).status == 401, "MAIN_OLD_TOKEN");
        require(request("/", retiredCookie, 16384).status == 401, "MAIN_OLD_COOKIE");
    }

    private Reply request(String path, String cookie, int limit) throws IOException {
        require(process.ownsListener(port), "MAIN_LISTENER_REVOKED");
        require(cookie == null || cookie.matches("dsh-auth-[A-Za-z0-9_-]{43}=v1\\.[A-Za-z0-9_-]{1,512}\\.[A-Za-z0-9_-]{43}"),
                "MAIN_COOKIE_FORMAT");
        try (Socket socket = new Socket(Proxy.NO_PROXY)) {
            InetAddress loopback = InetAddress.getByAddress(new byte[]{127, 0, 0, 1});
            socket.connect(new InetSocketAddress(loopback, port), 5000);
            // After connect, check again before sending a secret. If the port
            // has been released and rebound, the original owner is revoked.
            require(process.ownsListener(port), "MAIN_LISTENER_REVOKED");
            String wire = "GET " + path + " HTTP/1.0\r\nHost: 127.0.0.1:" + port
                    + "\r\nConnection: close\r\n" + (cookie == null ? "" : "Cookie: " + cookie + "\r\n")
                    + "\r\n";
            socket.getOutputStream().write(wire.getBytes(StandardCharsets.US_ASCII));
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
            InputStream bounded = new FilterInputStream(socket.getInputStream()) {
                @Override public int read(byte[] bytes, int offset, int size) throws IOException {
                    long left = deadline - System.nanoTime();
                    require(left > 0, "MAIN_HTTP_RESPONSE_TIMEOUT");
                    socket.setSoTimeout((int) Math.min(5000, 1 + TimeUnit.NANOSECONDS.toMillis(left)));
                    return super.read(bytes, offset, size);
                }
            };
            return readReply(new BufferedInputStream(bounded), limit, deadline);
        } catch (Denied failure) {
            throw failure;
        } catch (IOException failure) {
            // A network exception can carry a URL or other peer-controlled text.
            throw denied("MAIN_HTTP_EXCHANGE");
        }
    }

    private static Reply readReply(InputStream input, int limit, long deadline) throws IOException {
        String status = line(input, 512);
        require(status != null && status.matches("HTTP/1\\.[01] [1-5][0-9]{2}( .*)?"), "MAIN_HTTP_STATUS");
        Map<String, String> headers = new HashMap<>();
        for (int count = 0; ; count++) {
            require(count < 64 && System.nanoTime() - deadline < 0, "MAIN_HTTP_HEADER_BOUND");
            String row = line(input, 8192);
            require(row != null, "MAIN_HTTP_HEADERS_EOF");
            if (row.isEmpty()) break;
            int colon = row.indexOf(':');
            require(colon > 0, "MAIN_HTTP_HEADER");
            String name = row.substring(0, colon).toLowerCase(Locale.ROOT);
            String value = row.substring(colon + 1).trim();
            require(name.matches("[a-z0-9-]+"), "MAIN_HTTP_HEADER");
            if (headers.putIfAbsent(name, value) != null) {
                require(!name.equals("content-length") && !name.equals("set-cookie")
                        && !name.equals("location") && !name.equals("cache-control")
                        && !name.equals("referrer-policy"), "MAIN_HTTP_DUPLICATE_HEADER");
            }
        }
        require(!headers.containsKey("transfer-encoding"), "MAIN_HTTP_10_FRAMING");
        int length = -1;
        String declared = headers.get("content-length");
        if (declared != null) {
            require(declared.matches("[0-9]{1,8}"), "MAIN_HTTP_LENGTH");
            length = Integer.parseInt(declared);
            require(length <= limit, "MAIN_HTTP_BODY_BOUND");
        }
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        while (length < 0 || body.size() < length) {
            require(System.nanoTime() - deadline < 0, "MAIN_HTTP_BODY_TIMEOUT");
            int wanted = length < 0 ? buffer.length : Math.min(buffer.length, length - body.size());
            int count = input.read(buffer, 0, wanted);
            if (count < 0) break;
            require(count <= limit - body.size(), "MAIN_HTTP_BODY_BOUND");
            body.write(buffer, 0, count);
        }
        require(length < 0 || body.size() == length, "MAIN_HTTP_TRUNCATED_BODY");
        return new Reply(Integer.parseInt(status.substring(9, 12)), headers, body.toByteArray());
    }

    private static String line(InputStream input, int limit) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int ch;
        while ((ch = input.read()) >= 0 && ch != '\n') {
            require(bytes.size() < limit, "MAIN_LINE_BOUND");
            bytes.write(ch);
        }
        if (ch < 0) return null;
        String value = new String(bytes.toByteArray(), StandardCharsets.UTF_8);
        return value.endsWith("\r") ? value.substring(0, value.length() - 1) : value;
    }

    private static byte[] sha(byte[] bytes) {
        try { return MessageDigest.getInstance("SHA-256").digest(bytes); }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte value : bytes) result.append(String.format(Locale.ROOT, "%02x", value & 255));
        return result.toString();
    }

    private static void require(boolean condition, String code) throws IOException {
        if (!condition) throw denied(code);
    }

    private static Denied denied(String code) { return new Denied(code); }

    private static final class Denied extends IOException {
        Denied(String code) { super(code); }
    }

    private static final class Reply {
        final int status;
        final Map<String, String> headers;
        final byte[] body;

        Reply(int status, Map<String, String> headers, byte[] body) {
            this.status = status;
            this.headers = headers;
            this.body = body;
        }
    }
}
