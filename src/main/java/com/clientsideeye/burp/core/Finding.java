package com.clientsideeye.burp.core;

import java.time.Instant;
import java.util.Objects;

public final class Finding {

    public enum Severity {
        HIGH, MEDIUM, LOW, INFO
    }

    private final String type;          // FindingType name (string for stability)
    private final Severity severity;    // HIGH/MEDIUM/LOW/INFO
    private final int confidence;       // 0-100

    private final String url;
    private final String host;
    private final String title;
    private final String summary;
    private final String evidence;
    private final String recommendation;
    private final String identity;
    private final String firstSeen;     // ISO-ish string

    public Finding(
            String type,
            Severity severity,
            int confidence,
            String url,
            String host,
            String title,
            String summary,
            String evidence,
            String recommendation
    ) {
        this(type, severity, confidence, url, host, title, summary, evidence, recommendation, "", Instant.now().toString());
    }

    public Finding(
            String type,
            Severity severity,
            int confidence,
            String url,
            String host,
            String title,
            String summary,
            String evidence,
            String recommendation,
            String identity
    ) {
        this(type, severity, confidence, url, host, title, summary, evidence, recommendation, identity, Instant.now().toString());
    }

    public Finding(
            String type,
            Severity severity,
            int confidence,
            String url,
            String host,
            String title,
            String summary,
            String evidence,
            String recommendation,
            String identity,
            String firstSeen
    ) {
        this.type = Objects.requireNonNull(type, "type");
        this.severity = Objects.requireNonNull(severity, "severity");
        this.confidence = clamp(confidence, 0, 100);

        this.url = safe(url);
        this.host = safe(host);
        this.title = safe(title);
        this.summary = safe(summary);
        this.evidence = safe(evidence);
        this.recommendation = safe(recommendation);
        this.identity = safe(identity);
        this.firstSeen = safe(firstSeen);
    }

    // --- existing getters used by UI ---
    public String type() { return type; }
    public String url() { return url; }
    public String host() { return host; }
    public String title() { return title; }
    public String summary() { return summary; }
    public String evidence() { return evidence; }
    public String recommendation() { return recommendation; }
    public String identity() { return identity; }
    public String firstSeen() { return firstSeen; }

    // --- new ---
    public Severity severity() { return severity; }
    public int confidence() { return confidence; }

    // Stable dedupe key (type+url+evidence signature)
    public String stableKey() {
        String basis = identity;
        if (basis.isBlank()) {
            basis = title + "|" + evidence;
        }
        if (basis.length() > 400) basis = basis.substring(0, 400);
        return type + "|" + url + "|" + Integer.toHexString(basis.hashCode());
    }

    private static int clamp(int v, int lo, int hi) {
        return Math.max(lo, Math.min(hi, v));
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }
}
