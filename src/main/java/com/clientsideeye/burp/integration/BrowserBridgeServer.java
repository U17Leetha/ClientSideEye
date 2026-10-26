package com.clientsideeye.burp.integration;

import burp.api.montoya.MontoyaApi;
import com.clientsideeye.burp.core.Finding;
import com.clientsideeye.burp.core.FindingType;
import com.clientsideeye.burp.ui.ClientSideEyeTab;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLDecoder;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.RejectedExecutionException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.security.SecureRandom;

public final class BrowserBridgeServer {
    private static final String HOST = "127.0.0.1";
    private static final int PORT = 17373;
    private static final int MAX_PORT_ATTEMPTS = 10;
    private static final int SOCKET_READ_TIMEOUT_MS = 5000;
    private static final int MAX_FORM_BODY_BYTES = 64 * 1024;
    private static final String TOKEN_HEADER = "x-clientsideeye-token";

    private final MontoyaApi api;
    private final ClientSideEyeTab tab;
    private final ExecutorService acceptExec;
    private final ExecutorService clientExec;
    private final String authToken;
    private volatile boolean running;
    private ServerSocket serverSocket;
    private volatile int boundPort = -1;
    private final Set<Socket> clients = ConcurrentHashMap.newKeySet();
    private static final int MAX_LINE_BYTES = 8 * 1024;
    private static final int MAX_HEADER_BYTES = 16 * 1024;
    private static final int MAX_HEADER_COUNT = 100;

    public BrowserBridgeServer(MontoyaApi api, ClientSideEyeTab tab) {
        this.api = api;
        this.tab = tab;
        this.acceptExec = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "ClientSideEye-bridge");
            t.setDaemon(true);
            return t;
        });
        this.clientExec = new ThreadPoolExecutor(4, 4, 0, TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(8), r -> {
                Thread t = new Thread(r, "ClientSideEye-bridge-client");
                t.setDaemon(true);
                return t;
            });
        this.authToken = generateToken();
    }

    public synchronized void start() {
        if (running) return;
        if (acceptExec.isShutdown()) throw new IllegalStateException("Bridge has been stopped.");
        IOException last = null;
        for (int i = 0; i < MAX_PORT_ATTEMPTS; i++) {
            int candidatePort = PORT + i;
            try {
                serverSocket = new ServerSocket();
                serverSocket.setReuseAddress(true);
                serverSocket.bind(new InetSocketAddress(HOST, candidatePort), 50);
                serverSocket.setSoTimeout(1000);
                boundPort = candidatePort;
                running = true;
                acceptExec.submit(this::acceptLoop);
                api.logging().logToOutput("[ClientSideEye] Browser bridge listening on http://" + HOST + ":" + boundPort + " (/api/health, /api/finding)");
                if (boundPort != PORT) {
                    api.logging().logToOutput("[ClientSideEye] Default port " + PORT + " was busy. Using fallback port " + boundPort + ".");
                }
                return;
            } catch (IOException e) {
                last = e;
                try {
                    if (serverSocket != null) serverSocket.close();
                } catch (IOException ignored) {}
                serverSocket = null;
            }
        }
        api.logging().logToError("[ClientSideEye] Browser bridge failed to start after " + MAX_PORT_ATTEMPTS + " port attempts from " + PORT + ": " + last);
    }

    public synchronized void stop() {
        running = false;
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException ignored) {
            // best-effort close
        } finally {
            serverSocket = null;
        }
        for (Socket client : clients) {
            try { client.close(); } catch (IOException ignored) { }
        }
        clients.clear();
        boundPort = -1;
        acceptExec.shutdownNow();
        clientExec.shutdownNow();
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket client = serverSocket.accept();
                long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(SOCKET_READ_TIMEOUT_MS);
                clients.add(client);
                if (!running) { clients.remove(client); client.close(); break; }
                try { clientExec.execute(() -> handleClient(client, deadline)); }
                catch (RejectedExecutionException full) {
                    clients.remove(client);
                    client.close();
                }
            } catch (SocketTimeoutException ignored) {
                // periodic loop check
            } catch (Exception e) {
                if (running) {
                    api.logging().logToError("[ClientSideEye] Bridge accept error: " + e);
                }
            }
        }
    }

    private void handleClient(Socket socket, long deadline) {
        try (socket) {
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            try {
                String requestLine = readLine(in, socket, deadline);
                String[] request = requestLine.split(" ", -1);
                if (request.length != 3 || !request[2].equals("HTTP/1.1") || !request[1].startsWith("/"))
                    throw new BadRequest(400, "Invalid request line");
                Map<String, String> headers = new HashMap<>();
                int bytes = requestLine.length(), count = 0;
                while (true) {
                    String line = readLine(in, socket, deadline);
                    if (line.isEmpty()) break;
                    bytes += line.length() + 2;
                    if (++count > MAX_HEADER_COUNT || bytes > MAX_HEADER_BYTES)
                        throw new BadRequest(431, "Headers exceed budget");
                    int colon = line.indexOf(':');
                    if (colon <= 0) throw new BadRequest(400, "Invalid header");
                    String name = line.substring(0, colon).toLowerCase(Locale.ROOT);
                    String value = line.substring(colon + 1).trim();
                    if (!name.matches("[a-z0-9!#$%&'*+.^_`|~-]+") || value.chars().anyMatch(ch -> ch < 32 || ch == 127) ||
                        headers.putIfAbsent(name, value) != null)
                        throw new BadRequest(400, "Invalid or duplicate header");
                }
                String origin = headers.get("origin");
                if (headers.containsKey("transfer-encoding")) throw new BadRequest(400, "Unsupported transfer encoding");
                int length = 0;
                if (headers.containsKey("content-length")) {
                    String declared = headers.get("content-length");
                    if (!declared.matches("[0-9]{1,9}")) throw new BadRequest(400, "Invalid content length");
                    length = Integer.parseInt(declared);
                    if (length > MAX_FORM_BODY_BYTES) throw new BadRequest(413, "Body exceeds budget");
                }
                String method = request[0];
                String path = request[1].split("\\?", 2)[0];
                String health = "{\"product\":\"ClientSideEye\",\"protocol\":1,\"status\":\"ok\",\"authRequired\":true}";
                if (method.equals("OPTIONS")) {
                    writeResponse(out, 204, "application/json", "", origin); return;
                }
                if (path.equals("/api/health") && method.equals("GET")) {
                    writeResponse(out, 200, "application/json", health, origin); return;
                }
                if (!path.equals("/api/finding") && !path.equals("/api/session"))
                    throw new BadRequest(404, "Not found");
                if ((path.equals("/api/finding") && !method.equals("POST")) ||
                    (path.equals("/api/session") && !method.equals("GET")))
                    throw new BadRequest(405, "Method not allowed");
                if (validateFindingRequest(authToken, safe(headers.get(TOKEN_HEADER)), length) != 200)
                    throw new BadRequest(401, "Unauthorized");
                if (path.equals("/api/session")) {
                    writeResponse(out, 200, "application/json", health, origin); return;
                }
                if (!headers.getOrDefault("content-type", "").split(";", 2)[0].trim().equalsIgnoreCase("application/x-www-form-urlencoded"))
                    throw new BadRequest(415, "Expected form encoding");
                byte[] body = new byte[length];
                int offset = 0;
                while (offset < length) {
                    setReadDeadline(socket, deadline);
                    int read = in.read(body, offset, length - offset);
                    if (read < 0) throw new BadRequest(400, "Incomplete body");
                    offset += read;
                }
                try { handleFindingPost(out, new String(body, StandardCharsets.UTF_8), origin); }
                catch (IllegalArgumentException invalid) { throw new BadRequest(400, "Invalid finding form"); }
            } catch (BadRequest invalid) {
                writeResponse(out, invalid.status, "application/json", "{\"error\":\"" + invalid.getMessage() + "\"}", null);
            }
        } catch (IOException disconnected) {
            // A deadline, disconnect, or unload closes this one request; no request data is logged.
        } finally { clients.remove(socket); }
    }

    private static final class BadRequest extends IOException {
        final int status;
        BadRequest(int status, String message) { super(message); this.status = status; }
    }

    private static void setReadDeadline(Socket socket, long deadline) throws IOException {
        long remaining = deadline - System.nanoTime();
        if (remaining <= 0) throw new SocketTimeoutException("Request deadline expired");
        socket.setSoTimeout((int) Math.max(1, TimeUnit.NANOSECONDS.toMillis(remaining)));
    }

    private static String readLine(InputStream in, Socket socket, long deadline) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        while (line.size() <= MAX_LINE_BYTES) {
            setReadDeadline(socket, deadline);
            int ch = in.read();
            if (ch < 0) throw new BadRequest(400, "Incomplete headers");
            if (ch == '\n') {
                byte[] bytes = line.toByteArray();
                if (bytes.length == 0 || bytes[bytes.length - 1] != '\r') throw new BadRequest(400, "Expected CRLF");
                return new String(bytes, 0, bytes.length - 1, StandardCharsets.ISO_8859_1);
            }
            line.write(ch);
        }
        throw new BadRequest(431, "Line exceeds budget");
    }

    private void handleFindingPost(OutputStream out, String body, String origin) throws IOException {
        Map<String, String> form = parseFormEncoded(body);
        String url = safe(form.get("url"));
        if (url.isBlank()) {
            writeResponse(out, 400, "application/json; charset=utf-8", "{\"error\":\"url is required\"}", origin);
            return;
        }

        try {
            URL target = new URL(url);
            if (!Set.of("http", "https").contains(target.getProtocol()) || target.getHost().isBlank() || url.chars().anyMatch(Character::isISOControl))
                throw new IllegalArgumentException("Invalid target URL");
        } catch (java.net.MalformedURLException invalid) { throw new IllegalArgumentException("Invalid target URL", invalid); }
        String type = normalizeType(form.get("type"));
        Finding.Severity severity = parseSeverity(form.get("severity"));
        int confidence = parseInt(form.get("confidence"), 55);
        String title = defaultIfBlank(form.get("title"), "Browser-reported client-side control finding");
        String summary = defaultIfBlank(form.get("summary"),
                "A browser extension submitted a client-side control signal for review.");
        String evidence = defaultIfBlank(form.get("evidence"), "(no evidence)");
        String recommendation = defaultIfBlank(form.get("recommendation"),
                "Validate server-side authorization for this action. Do not rely on client-side disabled/hidden states.");
        String host = hostFromUrl(url);
        String identity = defaultIfBlank(form.get("identity"), type + "|" + Integer.toHexString(evidence.hashCode()));

        Finding finding = new Finding(
                type,
                severity,
                confidence,
                url,
                host,
                title,
                summary,
                evidence,
                recommendation,
                identity
        );

        List<Finding> findings = new ArrayList<>();
        findings.add(finding);
        tab.addFindings(findings);

        String source = defaultIfBlank(form.get("source"), "browser-extension");

        writeResponse(out, 200, "application/json; charset=utf-8", "{\"accepted\":1}", origin);
    }

    private static void writeResponse(OutputStream out, int status, String contentType, String body, String origin) throws IOException {
        String statusText = switch (status) {
            case 200 -> "OK";
            case 204 -> "No Content";
            case 401 -> "Unauthorized";
            case 413 -> "Payload Too Large";
            case 400 -> "Bad Request";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            case 415 -> "Unsupported Media Type";
            case 431 -> "Request Header Fields Too Large";
            default -> "Error";
        };
        byte[] bodyBytes = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
        StringBuilder headers = new StringBuilder("HTTP/1.1 " + status + " " + statusText + "\r\n");
        headers.append("Content-Type: ").append(contentType).append("\r\nContent-Length: ").append(bodyBytes.length).append("\r\n");
        if (isAllowedExtensionOrigin(origin)) {
            headers.append("Access-Control-Allow-Origin: ").append(origin).append("\r\nVary: Origin\r\n")
                .append("Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n")
                .append("Access-Control-Allow-Headers: Content-Type, X-ClientSideEye-Token\r\n");
        }
        headers.append("Connection: close\r\n\r\n");
        out.write(headers.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.write(bodyBytes);
        out.flush();
    }

    private static boolean isAllowedExtensionOrigin(String origin) {
        if (origin == null || origin.isBlank()) return false;
        return origin.startsWith("chrome-extension://")
                || origin.startsWith("moz-extension://")
                || origin.startsWith("safari-web-extension://");
    }

    static int validateFindingRequest(String expectedToken, String providedToken, int contentLength) {
        if (contentLength > MAX_FORM_BODY_BYTES) return 413;
        if (contentLength < 0 || safe(expectedToken).isEmpty() ||
            !java.security.MessageDigest.isEqual(safe(expectedToken).getBytes(StandardCharsets.UTF_8), safe(providedToken).getBytes(StandardCharsets.UTF_8))) return 401;
        return 200;
    }

    private static Map<String, String> parseFormEncoded(String body) {
        Map<String, String> out = new HashMap<>();
        if (body == null || body.isBlank()) return out;
        String[] parts = body.split("&");
        for (String p : parts) {
            if (p == null || p.isBlank()) continue;
            int idx = p.indexOf('=');
            String k = idx >= 0 ? p.substring(0, idx) : p;
            String v = idx >= 0 ? p.substring(idx + 1) : "";
            k = URLDecoder.decode(k, StandardCharsets.UTF_8);
            v = URLDecoder.decode(v, StandardCharsets.UTF_8);
            out.put(k, v);
        }
        return out;
    }

    private static String normalizeType(String type) {
        String t = safe(type).trim();
        if (t.isBlank()) return FindingType.HIDDEN_OR_DISABLED_CONTROL.name();
        for (FindingType ft : FindingType.values()) {
            if (ft.name().equalsIgnoreCase(t)) return ft.name();
        }
        return FindingType.HIDDEN_OR_DISABLED_CONTROL.name();
    }

    private static Finding.Severity parseSeverity(String s) {
        String x = safe(s).trim().toUpperCase(Locale.ROOT);
        try {
            return Finding.Severity.valueOf(x);
        } catch (Exception e) {
            return Finding.Severity.MEDIUM;
        }
    }

    private static int parseInt(String s, int dflt) {
        try {
            return Integer.parseInt(safe(s).trim());
        } catch (Exception e) {
            return dflt;
        }
    }

    private static String defaultIfBlank(String s, String dflt) {
        String x = safe(s).trim();
        return x.isBlank() ? dflt : x;
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }

    private static String hostFromUrl(String url) {
        try {
            URL u = new URL(url);
            return u.getHost() == null ? "" : u.getHost();
        } catch (Exception e) {
            return "";
        }
    }

    private static String generateToken() {
        byte[] bytes = new byte[24];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public int boundPort() {
        return boundPort;
    }

    public String authToken() {
        return authToken;
    }
}
