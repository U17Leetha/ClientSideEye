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
import java.net.URI;
import java.net.URLDecoder;
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
    private int boundPort = -1;

    public BrowserBridgeServer(MontoyaApi api, ClientSideEyeTab tab) {
        this.api = api;
        this.tab = tab;
        this.acceptExec = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "ClientSideEye-bridge");
            t.setDaemon(true);
            return t;
        });
        this.clientExec = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "ClientSideEye-bridge-client");
            t.setDaemon(true);
            return t;
        });
        this.authToken = generateToken();
    }

    public synchronized void start() {
        if (running) return;
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
                api.logging().logToOutput("[ClientSideEye] Browser bridge token: " + authToken);
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
        acceptExec.shutdownNow();
        clientExec.shutdownNow();
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket s = serverSocket.accept();
                s.setSoTimeout(SOCKET_READ_TIMEOUT_MS);
                clientExec.submit(() -> handleClient(s));
            } catch (SocketTimeoutException ignored) {
                // periodic loop check
            } catch (Exception e) {
                if (running) {
                    api.logging().logToError("[ClientSideEye] Bridge accept error: " + e);
                }
            }
        }
    }

    private static final int MAX_LINE_BYTES = 8 * 1024;
    private static final int MAX_HEADER_COUNT = 100;

    private void handleClient(Socket socket) {
        try (socket;
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
             BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8))) {

            String requestLine;
            try {
                requestLine = readBoundedLine(in, MAX_LINE_BYTES);
            } catch (IOException tooLong) {
                writeResponse(out, 431, "application/json; charset=utf-8", "{\"error\":\"line too long\"}", null);
                return;
            }
            if (requestLine == null || requestLine.isBlank()) {
                writeResponse(out, 400, "application/json; charset=utf-8", "{\"error\":\"bad request\"}", null);
                return;
            }

            String[] reqParts = requestLine.split(" ");
            if (reqParts.length < 2) {
                writeResponse(out, 400, "application/json; charset=utf-8", "{\"error\":\"bad request\"}", null);
                return;
            }
            String method = reqParts[0].trim().toUpperCase(Locale.ROOT);
            String rawPath = reqParts[1].trim();
            String path = rawPath;
            int qIdx = rawPath.indexOf('?');
            if (qIdx >= 0) {
                path = rawPath.substring(0, qIdx);
            }

            int contentLength = 0;
            String origin = null;
            Map<String, String> headers = new HashMap<>();
            String line;
            int headerCount = 0;
            while (true) {
                try {
                    line = readBoundedLine(in, MAX_LINE_BYTES);
                } catch (IOException tooLong) {
                    writeResponse(out, 431, "application/json; charset=utf-8", "{\"error\":\"header too long\"}", null);
                    return;
                }
                if (line == null || line.isEmpty()) break;
                if (++headerCount > MAX_HEADER_COUNT) {
                    writeResponse(out, 431, "application/json; charset=utf-8", "{\"error\":\"too many headers\"}", null);
                    return;
                }
                String lower = line.toLowerCase(Locale.ROOT);
                int colon = line.indexOf(':');
                if (colon > 0) {
                    String headerName = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                    String headerValue = line.substring(colon + 1).trim();
                    headers.put(headerName, headerValue);
                    if ("origin".equals(headerName)) {
                        origin = headerValue;
                    }
                }
                if (lower.startsWith("content-length:")) {
                    try {
                        contentLength = Integer.parseInt(line.substring("content-length:".length()).trim());
                    } catch (Exception ignored) {
                        contentLength = 0;
                    }
                }
            }

            if (contentLength > MAX_FORM_BODY_BYTES) {
                writeResponse(out, 413, "application/json; charset=utf-8", "{\"error\":\"request too large\"}", origin);
                return;
            }

            String body = "";
            if (contentLength > 0) {
                char[] buf = new char[contentLength];
                int read = 0;
                while (read < contentLength) {
                    int n = in.read(buf, read, contentLength - read);
                    if (n < 0) break;
                    read += n;
                }
                body = new String(buf, 0, read);
            }

            if ("OPTIONS".equals(method)) {
                writeResponse(out, 204, "text/plain; charset=utf-8", "", origin);
                return;
            }

            if ("/api/health".equals(path)) {
                if (!"GET".equals(method)) {
                    writeResponse(out, 405, "application/json; charset=utf-8", "{\"error\":\"method not allowed\"}", origin);
                    return;
                }
                writeResponse(out, 200, "application/json; charset=utf-8", "{\"status\":\"ok\",\"authRequired\":true}", origin);
                return;
            }

            if ("/api/finding".equals(path)) {
                if (!"POST".equals(method)) {
                    writeResponse(out, 405, "application/json; charset=utf-8", "{\"error\":\"method not allowed\"}", origin);
                    return;
                }
                String providedToken = safe(headers.get(TOKEN_HEADER));
                int validationStatus = validateFindingRequest(authToken, providedToken, contentLength);
                if (validationStatus != 200) {
                    String bodyText = validationStatus == 401 ? "{\"error\":\"unauthorized\"}" : "{\"error\":\"request too large\"}";
                    writeResponse(out, validationStatus, "application/json; charset=utf-8", bodyText, origin);
                    return;
                }
                handleFindingPost(out, body, origin);
                return;
            }

            writeResponse(out, 404, "application/json; charset=utf-8", "{\"error\":\"not found\"}", origin);
        } catch (Exception e) {
            api.logging().logToError("[ClientSideEye] Bridge client error: " + e);
        }
    }

    private void handleFindingPost(BufferedWriter out, String body, String origin) throws IOException {
        Map<String, String> form = parseFormEncoded(body);
        String url = safe(form.get("url"));
        if (url.isBlank()) {
            writeResponse(out, 400, "application/json; charset=utf-8", "{\"error\":\"url is required\"}", origin);
            return;
        }

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
        api.logging().logToOutput("[ClientSideEye] Bridge accepted finding from " + source + " | " + type + " | " + severity + " (" + confidence + ") | " + url);
        writeResponse(out, 200, "application/json; charset=utf-8", "{\"accepted\":1}", origin);
    }

    private static void writeResponse(BufferedWriter out, int status, String contentType, String body, String origin) throws IOException {
        String statusText = switch (status) {
            case 200 -> "OK";
            case 204 -> "No Content";
            case 401 -> "Unauthorized";
            case 413 -> "Payload Too Large";
            case 400 -> "Bad Request";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            case 431 -> "Request Header Fields Too Large";
            default -> "Error";
        };
        byte[] bodyBytes = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
        out.write("HTTP/1.1 " + status + " " + statusText + "\r\n");
        out.write("Content-Type: " + contentType + "\r\n");
        out.write("Content-Length: " + bodyBytes.length + "\r\n");
        if (isAllowedExtensionOrigin(origin)) {
            out.write("Access-Control-Allow-Origin: " + origin + "\r\n");
            out.write("Vary: Origin\r\n");
            out.write("Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n");
            out.write("Access-Control-Allow-Headers: Content-Type, X-ClientSideEye-Token\r\n");
        }
        out.write("Connection: close\r\n");
        out.write("\r\n");
        if (bodyBytes.length > 0) {
            out.write(new String(bodyBytes, StandardCharsets.UTF_8));
        }
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
        if (!safe(expectedToken).equals(safe(providedToken))) return 401;
        return 200;
    }

    private static String readBoundedLine(BufferedReader in, int maxLen) throws IOException {
        StringBuilder sb = new StringBuilder();
        int ch;
        while ((ch = in.read()) != -1) {
            if (ch == '\n') {
                int len = sb.length();
                if (len > 0 && sb.charAt(len - 1) == '\r') sb.setLength(len - 1);
                return sb.toString();
            }
            if (sb.length() >= maxLen) {
                throw new IOException("line exceeds maximum length of " + maxLen);
            }
            sb.append((char) ch);
        }
        return sb.length() == 0 ? null : sb.toString();
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
            URI u = URI.create(url);
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
