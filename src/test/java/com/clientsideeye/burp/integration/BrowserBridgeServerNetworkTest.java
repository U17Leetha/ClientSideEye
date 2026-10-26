package com.clientsideeye.burp.integration;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.clientsideeye.burp.ui.ClientSideEyeTab;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * End-to-end regression tests for the local Browser Bridge listener's defenses against
 * maliciously large/adversarial requests. The bridge is a hand-rolled HTTP/1.1 server bound to
 * 127.0.0.1, so it is responsible for its own protocol-level hardening (unlike code that goes
 * through Burp's HTTP stack).
 */
class BrowserBridgeServerNetworkTest {

    private BrowserBridgeServer server;

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop();
        }
    }

    @Test
    void rejectsRequestLineExceedingMaxLineLength() throws Exception {
        server = startServer();

        try (Socket socket = new Socket("127.0.0.1", server.boundPort())) {
            socket.setSoTimeout(5000);
            OutputStream out = socket.getOutputStream();
            // 16 KB request line (no newline) - well beyond the 8 KB per-line cap. A malicious
            // local process should not be able to make the bridge buffer unbounded line data.
            String hugePath = "/" + "a".repeat(16 * 1024);
            out.write(("GET " + hugePath + " HTTP/1.1\r\n\r\n").getBytes(StandardCharsets.UTF_8));
            out.flush();

            String statusLine = readStatusLine(socket);
            assertTrue(statusLine.contains("431"), "expected 431 for an oversized request line, got: " + statusLine);
        }
    }

    @Test
    void rejectsExcessiveHeaderCount() throws Exception {
        server = startServer();

        try (Socket socket = new Socket("127.0.0.1", server.boundPort())) {
            socket.setSoTimeout(5000);
            OutputStream out = socket.getOutputStream();
            StringBuilder request = new StringBuilder("GET /api/health HTTP/1.1\r\n");
            for (int i = 0; i < 500; i++) {
                request.append("X-Filler-").append(i).append(": value\r\n");
            }
            request.append("\r\n");
            out.write(request.toString().getBytes(StandardCharsets.UTF_8));
            out.flush();

            String statusLine = readStatusLine(socket);
            assertTrue(statusLine.contains("431"), "expected 431 for excessive header count, got: " + statusLine);
        }
    }

    @Test
    void healthEndpointStillWorksForWellFormedRequests() throws Exception {
        server = startServer();

        try (Socket socket = new Socket("127.0.0.1", server.boundPort())) {
            socket.setSoTimeout(5000);
            OutputStream out = socket.getOutputStream();
            out.write("GET /api/health HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();

            String statusLine = readStatusLine(socket);
            assertEquals("HTTP/1.1 200 OK", statusLine.trim());
        }
    }

    @Test
    void rejectsUnauthenticatedBodyBeforeReadingIt() throws Exception {
        server = startServer();
        assertEquals("HTTP/1.1 401 Unauthorized", exchange("POST /api/finding HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\n\r\n").trim());
    }

    @Test
    void rejectsAmbiguousFramingAndMalformedForms() throws Exception {
        server = startServer();
        assertTrue(exchange("POST /api/finding HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n").contains("400"));
        assertTrue(exchange("POST /api/finding HTTP/1.1\r\nContent-Length: -1\r\n\r\n").contains("400"));
        assertTrue(exchange("POST /api/finding HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").contains("400"));
    }

    @Test
    void authenticatesSessionAndReadsUtf8ByByteLength() throws Exception {
        server = startServer();
        String token = "X-ClientSideEye-Token: " + server.authToken() + "\r\n";
        assertTrue(exchange("GET /api/session HTTP/1.1\r\n" + token + "\r\n").contains("200"));
        String body = "url=https://example.test/open?q=\"><tag>&evidence=Unicode-λ";
        String request = "POST /api/finding HTTP/1.1\r\n" + token + "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n\r\n" + body;
        assertTrue(exchange(request).contains("200"));
        assertTrue(exchange("POST /api/finding HTTP/1.1\r\n" + token + "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 8\r\n\r\nurl=%ZZZ").contains("400"));
    }

    @Test
    void stopClosesIncompleteAcceptedClients() throws Exception {
        server = startServer();
        try (Socket socket = new Socket("127.0.0.1", server.boundPort())) {
            socket.setSoTimeout(1500);
            socket.getOutputStream().write('G');
            Thread.sleep(50);
            server.stop();
            try { assertEquals(-1, socket.getInputStream().read()); }
            catch (java.net.SocketException reset) { /* A reset is also an explicit close. */ }
        }
    }

    private String exchange(String request) throws Exception {
        try (Socket socket = new Socket("127.0.0.1", server.boundPort())) {
            socket.setSoTimeout(1500);
            socket.getOutputStream().write(request.getBytes(StandardCharsets.UTF_8));
            socket.getOutputStream().flush();
            return readStatusLine(socket);
        }
    }

    private static BrowserBridgeServer startServer() {
        MontoyaApi api = mock(MontoyaApi.class);
        when(api.logging()).thenReturn(mock(Logging.class));
        ClientSideEyeTab tab = mock(ClientSideEyeTab.class);
        BrowserBridgeServer s = new BrowserBridgeServer(api, tab);
        s.start();
        assertTrue(s.boundPort() > 0, "server failed to bind a port");
        return s;
    }

    private static String readStatusLine(Socket socket) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        String line = reader.readLine();
        return line == null ? "" : line;
    }
}
