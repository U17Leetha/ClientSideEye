package com.clientsideeye.burp.core;

/** Explicit per-response budgets; callers report rejections rather than partial clean results. */
public final class AnalysisLimits {
    public static final int MAX_BODY_BYTES = 2 * 1024 * 1024;
    public static final int MAX_FINDINGS = 1000;
    public static final int MAX_NODES = 10000;
    public static final int MAX_DEPTH = 64;
    private AnalysisLimits() {}
    public static void checkBody(String body) {
        if (body != null && body.length() > MAX_BODY_BYTES)
            throw new IllegalArgumentException("Response exceeds the 2 MiB analysis budget; narrow the selection.");
    }
    public static void checkFindings(int count) {
        if (count > MAX_FINDINGS)
            throw new IllegalArgumentException("Response exceeds the 1000-finding budget; narrow the selection.");
    }
}
