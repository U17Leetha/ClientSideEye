package com.clientsideeye.burp.core;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.clientsideeye.burp.core.Finding.Severity;

public final class JavaScriptAnalyzer {

    private static final Pattern ENDPOINT_PATTERN = Pattern.compile(
            "(?i)(?:fetch|axios\\.(?:get|post|put|delete|patch)|xhr\\.open|open\\s*\\()\\s*\\(?\\s*['\"]([^'\"]{2,200})['\"]"
    );
    private static final Pattern ROUTE_PATTERN = Pattern.compile(
            "(?i)['\"]((?:/|https?://)[^'\"\\s]{2,200})['\"]"
    );
    private static final Pattern GRAPHQL_PATTERN = Pattern.compile(
            "(?is)\\b(query|mutation|subscription)\\b\\s+[A-Za-z0-9_]+|/graphql\\b"
    );
    private static final Pattern POSTMESSAGE_PATTERN = Pattern.compile(
            "(?is)(addEventListener\\s*\\(\\s*['\"]message['\"]|onmessage\\s*=|postMessage\\s*\\()"
    );
    private static final Pattern SINK_PATTERN = Pattern.compile(
            "(?is)(innerHTML\\s*=|outerHTML\\s*=|insertAdjacentHTML\\s*\\(|document\\.write\\s*\\(|eval\\s*\\(|new\\s+Function\\s*\\(|setTimeout\\s*\\(\\s*['\"]|setInterval\\s*\\(\\s*['\"]|dangerouslySetInnerHTML|\\[innerHTML\\]|v-html\\s*=|bypassSecurityTrustHtml\\s*\\(|bypassSecurityTrustScript\\s*\\(|bypassSecurityTrustResourceUrl\\s*\\()"
    );
    private static final Pattern PROTOTYPE_POLLUTION_PATTERN = Pattern.compile(
            "(?is)(__proto__\\s*[\\[.=]|_\\.merge\\w*\\s*\\(|deepmerge\\s*\\(|\\$\\.extend\\s*\\(\\s*true\\s*,|Object\\.assign\\s*\\([^)]{0,80}JSON\\.parse)"
    );
    private static final Pattern REALTIME_ENDPOINT_PATTERN = Pattern.compile(
            "(?is)new\\s+(WebSocket|EventSource)\\s*\\(\\s*['\"]([^'\"]{2,200})['\"]"
    );

    private JavaScriptAnalyzer() {}

    public static boolean looksLikeJavaScriptForAnalysis(String url, String body) {
        if (body == null || body.isBlank()) return false;
        String u = url == null ? "" : url.toLowerCase(Locale.ROOT);
        if (u.matches(".*\\.(js|mjs)(\\?.*)?$")) return true;
        String trimmed = body.trim();
        return trimmed.contains("function")
                || trimmed.contains("=>")
                || trimmed.contains("const ")
                || trimmed.contains("let ")
                || trimmed.contains("var ")
                || trimmed.contains("document.")
                || trimmed.contains("window.")
                || trimmed.contains("fetch(")
                || trimmed.contains("eval(")
                || trimmed.contains("axios.")
                || trimmed.contains(".then(")
                || trimmed.contains("addEventListener(")
                || trimmed.contains("setTimeout(")
                || trimmed.contains("setInterval(")
                || trimmed.contains("postMessage(")
                || trimmed.contains("require(")
                || trimmed.contains("import ")
                || trimmed.contains("XMLHttpRequest");
    }

    public static List<Finding> analyzeJavaScript(String url, String script) {
        if (!looksLikeJavaScriptForAnalysis(url, script)) return List.of();
        return analyzeJavaScriptContent(url, script);
    }

    /**
     * Analyzes content that the caller already knows to be JavaScript (e.g. extracted
     * {@code <script>} bodies or source-map {@code sourcesContent} entries), bypassing the
     * heuristic sniffing in {@link #looksLikeJavaScriptForAnalysis(String, String)}. That
     * heuristic exists only to decide whether an *ambiguous* HTTP response body is worth
     * treating as JavaScript, and must not be used to gate content whose type is already known.
     */
    public static List<Finding> analyzeJavaScriptContent(String url, String script) {
        if (script == null || script.isBlank()) return List.of();

        List<Finding> out = new ArrayList<>();
        String host = hostFromUrl(url);
        addEndpointFindings(out, url, host, script);
        addSinkFindings(out, url, host, script);
        addPostMessageFindings(out, url, host, script);
        addPrototypePollutionFindings(out, url, host, script);
        addRealtimeEndpointFindings(out, url, host, script);
        return out;
    }

    private static void addEndpointFindings(List<Finding> out, String url, String host, String script) {
        Set<String> seen = new HashSet<>();

        Matcher endpointMatcher = ENDPOINT_PATTERN.matcher(script);
        while (endpointMatcher.find()) {
            String endpoint = endpointMatcher.group(1);
            if (!isInterestingPath(endpoint) || !seen.add("ep:" + endpoint)) continue;
            out.add(new Finding(
                    FindingType.JAVASCRIPT_ENDPOINT_REFERENCE.name(),
                    severityForEndpoint(endpoint),
                    confidenceForEndpoint(endpoint),
                    url,
                    host,
                    "Endpoint reference found in JavaScript",
                    "JavaScript contains a likely client-side endpoint or route reference that may expose additional functionality or attack surface.",
                    shrink(endpointMatcher.group(0), 220),
                    "Review the referenced endpoint for authorization, method handling, and unintended exposure. Correlate with runtime requests and hidden UI flows.",
                    "endpoint:" + endpoint
            ));
        }

        Matcher routeMatcher = ROUTE_PATTERN.matcher(script);
        while (routeMatcher.find()) {
            String route = routeMatcher.group(1);
            if (!isInterestingPath(route) || !seen.add("route:" + route)) continue;

            int confidence = route.contains("/api/") || route.contains("/graphql") ? 72 : 55;
            String summary = "JavaScript contains a hard-coded route or resource reference that may indicate hidden functionality, navigation paths, or backend endpoints.";
            if (GRAPHQL_PATTERN.matcher(route).find()) {
                confidence = 78;
                summary = "JavaScript references a likely GraphQL endpoint or operation path.";
            }

            out.add(new Finding(
                    FindingType.JAVASCRIPT_ENDPOINT_REFERENCE.name(),
                    confidence >= 70 ? Severity.MEDIUM : Severity.INFO,
                    confidence,
                    url,
                    host,
                    "Route or API reference found in JavaScript",
                    summary,
                    shrink(routeMatcher.group(0), 220),
                    "Review the referenced route or endpoint for hidden functionality, authorization gaps, and client-side assumptions about server behavior.",
                    "route:" + route
            ));
        }
    }

    private static void addSinkFindings(List<Finding> out, String url, String host, String script) {
        Set<String> seen = new HashSet<>();
        Matcher matcher = SINK_PATTERN.matcher(script);
        while (matcher.find()) {
            String sink = matcher.group(1);
            if (!seen.add(sink)) continue;
            String sinkLower = sink.toLowerCase(Locale.ROOT);
            boolean highRisk = sinkLower.contains("eval") || sinkLower.contains("function") || sinkLower.contains("bypasssecuritytrust");
            out.add(new Finding(
                    FindingType.DOM_XSS_SINK.name(),
                    highRisk ? Severity.MEDIUM : Severity.LOW,
                    highRisk ? 72 : 58,
                    url,
                    host,
                    "Potential DOM XSS sink found in JavaScript",
                    "JavaScript contains a dangerous DOM or code-execution sink. This is not a vulnerability by itself, but it is a strong indicator for manual DOM XSS review.",
                    shrink(matcher.group(0), 220),
                    "Trace attacker-controlled sources reaching this sink. Review URL parameters, postMessage handlers, storage values, and server-rendered data that may flow into it.",
                    "sink:" + sink
            ));
        }
    }

    private static void addPostMessageFindings(List<Finding> out, String url, String host, String script) {
        Matcher matcher = POSTMESSAGE_PATTERN.matcher(script);
        if (!matcher.find()) return;

        String matched = matcher.group(1);
        boolean checksOrigin = script.toLowerCase(Locale.ROOT).contains("event.origin")
                || script.toLowerCase(Locale.ROOT).contains(".origin")
                || script.toLowerCase(Locale.ROOT).contains("targetorigin");
        out.add(new Finding(
                FindingType.POSTMESSAGE_HANDLER.name(),
                checksOrigin ? Severity.INFO : Severity.MEDIUM,
                checksOrigin ? 55 : 75,
                url,
                host,
                "postMessage usage found in JavaScript",
                checksOrigin
                        ? "JavaScript uses postMessage or message event handlers and appears to reference origin checks. Manual review is still recommended."
                        : "JavaScript uses postMessage or message event handlers without obvious origin validation nearby. Review for cross-origin message handling issues.",
                shrink(matched, 220),
                "Review message listeners and senders for strict origin validation, message schema validation, and avoidance of dangerous sink usage.",
                "postmessage:" + matched
        ));
    }

    private static void addPrototypePollutionFindings(List<Finding> out, String url, String host, String script) {
        Set<String> seen = new HashSet<>();
        Matcher matcher = PROTOTYPE_POLLUTION_PATTERN.matcher(script);
        while (matcher.find()) {
            String matched = matcher.group(1);
            if (!seen.add(matched)) continue;
            out.add(new Finding(
                    FindingType.PROTOTYPE_POLLUTION_HINT.name(),
                    Severity.LOW,
                    45,
                    url,
                    host,
                    "Possible prototype pollution pattern in JavaScript",
                    "JavaScript contains a pattern commonly associated with client-side prototype pollution.",
                    shrink(matcher.group(0), 220),
                    "Trace whether attacker-controlled data reaches this merge/assignment without key sanitization (reject __proto__/constructor/prototype keys).",
                    "protopollution:" + matched
            ));
        }
    }

    private static void addRealtimeEndpointFindings(List<Finding> out, String url, String host, String script) {
        Set<String> seen = new HashSet<>();
        Matcher matcher = REALTIME_ENDPOINT_PATTERN.matcher(script);
        while (matcher.find()) {
            String api = matcher.group(1);
            String endpoint = matcher.group(2);
            if (!seen.add(api + ":" + endpoint)) continue;
            out.add(new Finding(
                    FindingType.RUNTIME_NETWORK_REFERENCE.name(),
                    Severity.INFO,
                    60,
                    url,
                    host,
                    api + " endpoint reference found in JavaScript",
                    "JavaScript establishes a " + api + " connection to a hard-coded endpoint. Review authentication, message validation, and origin checks, since " + api + " traffic does not always go through the same authorization path as regular HTTP requests.",
                    shrink(matcher.group(0), 220),
                    "Review the " + api + " endpoint's authentication/authorization model and message handling for injection or spoofing issues.",
                    "realtime:" + endpoint
            ));
        }
    }

    private static boolean isInterestingPath(String candidate) {
        if (candidate == null || candidate.isBlank()) return false;
        String lower = candidate.toLowerCase(Locale.ROOT);
        if (lower.startsWith("http://") || lower.startsWith("https://")) return true;
        return lower.startsWith("/")
                && !lower.matches("^/(?:[a-z0-9._-]+\\.(?:png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|css|map))(?:\\?.*)?$");
    }

    private static int confidenceForEndpoint(String endpoint) {
        String lower = endpoint.toLowerCase(Locale.ROOT);
        if (lower.contains("/api/") || lower.contains("/graphql")) return 80;
        if (lower.contains("/admin") || lower.contains("/internal")) return 75;
        return 65;
    }

    private static Severity severityForEndpoint(String endpoint) {
        String lower = endpoint.toLowerCase(Locale.ROOT);
        if (lower.contains("/admin") || lower.contains("/internal")) return Severity.MEDIUM;
        return Severity.INFO;
    }

    private static String hostFromUrl(String url) {
        try {
            URI u = URI.create(url);
            return u.getHost() == null ? "" : u.getHost();
        } catch (Exception e) {
            return "";
        }
    }

    private static String shrink(String s, int max) {
        if (s == null) return "";
        String normalized = s.replaceAll("\\s+", " ").trim();
        if (normalized.length() <= max) return normalized;
        return normalized.substring(0, max) + "...";
    }
}
