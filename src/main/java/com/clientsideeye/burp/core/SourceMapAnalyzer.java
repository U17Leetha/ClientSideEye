package com.clientsideeye.burp.core;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.clientsideeye.burp.core.Finding.Severity;

public final class SourceMapAnalyzer {

    private static final Pattern SOURCE_MAPPING_URL_PATTERN = Pattern.compile("(?im)//[#@]\\s*sourceMappingURL\\s*=\\s*([^\\s]+)");
    private static final Pattern SOURCES_ARRAY_PATTERN = Pattern.compile("(?is)\"sources\"\\s*:\\s*\\[(.*?)\\]");
    private static final Pattern SOURCE_ITEM_PATTERN = Pattern.compile("(?is)\"((?:\\\\.|[^\"])*)\"");
    private static final Pattern SOURCES_CONTENT_PATTERN = Pattern.compile("(?is)\"sourcesContent\"\\s*:\\s*\\[(.*?)\\]\\s*(?:,\\s*\"|\\}\\s*$)");

    private SourceMapAnalyzer() {}

    public static boolean looksLikeSourceMap(String url, String body) {
        if (body == null || body.isBlank()) return false;
        String u = url == null ? "" : url.toLowerCase(Locale.ROOT);
        if (u.matches(".*\\.map(\\?.*)?$")) return true;
        String trimmed = body.trim().toLowerCase(Locale.ROOT);
        return trimmed.startsWith("{")
                && trimmed.contains("\"version\"")
                && trimmed.contains("\"sources\"");
    }

    public static List<Finding> analyzeSourceMap(String url, String body) {
        if (!looksLikeSourceMap(url, body)) return List.of();

        List<Finding> out = new ArrayList<>();
        String host = hostFromUrl(url);
        addDisclosureFinding(out, url, host, body);
        addEmbeddedSourceFindings(out, url, host, body);
        return out;
    }

    public static List<Finding> analyzeSourceMappingReference(String url, String body) {
        if (body == null || body.isBlank()) return List.of();
        Matcher matcher = SOURCE_MAPPING_URL_PATTERN.matcher(body);
        if (!matcher.find()) return List.of();

        String mapRef = matcher.group(1).trim();
        String host = hostFromUrl(url);
        return List.of(new Finding(
                FindingType.SOURCE_MAP_DISCLOSURE.name(),
                Severity.INFO,
                70,
                url,
                host,
                "Source map reference found in JavaScript asset",
                "The JavaScript asset references a source map. Source maps often expose original source paths and unminified code that expand the client-side attack surface.",
                shrink(matcher.group(0), 220),
                "Review whether the source map is publicly accessible and whether it exposes sensitive routes, internal filenames, comments, or implementation details.",
                "sourcemap-ref:" + mapRef
        ));
    }

    private static void addDisclosureFinding(List<Finding> out, String url, String host, String body) {
        List<String> sources = parseSources(body);
        String evidence = sources.isEmpty()
                ? shrink(body, 240)
                : shrink(String.join(", ", sources.subList(0, Math.min(8, sources.size()))), 240);
        out.add(new Finding(
                FindingType.SOURCE_MAP_DISCLOSURE.name(),
                Severity.MEDIUM,
                82,
                url,
                host,
                "Source map exposed in response",
                "A source map response is accessible. Source maps can reveal original source paths, comments, endpoints, and unminified code that materially expand the client-side review surface.",
                evidence,
                "Restrict source map exposure in production unless explicitly required. Review whether the map leaks internal structure, routes, secrets, or dangerous client-side logic.",
                "sourcemap:" + Integer.toHexString(evidence.hashCode())
        ));
    }

    private static void addEmbeddedSourceFindings(List<Finding> out, String url, String host, String body) {
        for (String sourceBody : parseSourcesContent(body)) {
            if (sourceBody.isBlank()) continue;
            out.addAll(JavaScriptAnalyzer.analyzeJavaScriptContent(url, sourceBody));
        }
    }

    private static List<String> parseSources(String body) {
        Matcher matcher = SOURCES_ARRAY_PATTERN.matcher(body);
        if (!matcher.find()) return List.of();
        String content = matcher.group(1);
        Set<String> out = new LinkedHashSet<>();
        Matcher itemMatcher = SOURCE_ITEM_PATTERN.matcher(content);
        while (itemMatcher.find()) {
            out.add(unescapeJson(itemMatcher.group(1)));
        }
        return new ArrayList<>(out);
    }

    private static List<String> parseSourcesContent(String body) {
        Matcher matcher = SOURCES_CONTENT_PATTERN.matcher(body);
        if (!matcher.find()) return List.of();
        String content = matcher.group(1);
        List<String> out = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inString = false;
        boolean escaped = false;

        for (int i = 0; i < content.length(); i++) {
            char ch = content.charAt(i);
            if (!inString) {
                if (ch == '"') {
                    inString = true;
                    current.setLength(0);
                }
                continue;
            }

            if (escaped) {
                current.append(ch);
                escaped = false;
                continue;
            }

            if (ch == '\\') {
                escaped = true;
                current.append(ch);
                continue;
            }

            if (ch == '"') {
                inString = false;
                out.add(unescapeJson(current.toString()));
                continue;
            }

            current.append(ch);
        }

        return out;
    }

    private static String unescapeJson(String text) {
        return text
                .replace("\\\\", "\\")
                .replace("\\/", "/")
                .replace("\\\"", "\"")
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t");
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
