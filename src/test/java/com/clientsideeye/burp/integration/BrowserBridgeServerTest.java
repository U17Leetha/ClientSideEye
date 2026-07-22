package com.clientsideeye.burp.integration;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BrowserBridgeServerTest {

    @Test
    void rejectsMissingToken() {
        assertEquals(401, BrowserBridgeServer.validateFindingRequest("expected", "", 10));
    }

    @Test
    void rejectsOversizedBody() {
        assertEquals(413, BrowserBridgeServer.validateFindingRequest("expected", "expected", 70 * 1024));
    }

    @Test
    void acceptsAuthorizedBoundedRequest() {
        assertEquals(200, BrowserBridgeServer.validateFindingRequest("expected", "expected", 1024));
    }
}
