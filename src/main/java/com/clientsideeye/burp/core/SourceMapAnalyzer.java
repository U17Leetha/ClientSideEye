package com.clientsideeye.burp.core;

import java.net.URL;
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

        AnalysisLimits.checkBody(body);
        com.google.gson.stream.JsonReader reader = new com.google.gson.stream.JsonReader(new java.io.StringReader(body));
        reader.setStrictness(com.google.gson.Strictness.STRICT);
        reader.setNestingLimit(AnalysisLimits.MAX_DEPTH);
        try {
            com.google.gson.JsonElement parsed = com.google.gson.JsonParser.parseReader(reader);
            if (reader.peek() != com.google.gson.stream.JsonToken.END_DOCUMENT || !parsed.isJsonObject())
                throw new IllegalArgumentException("Source map must be one JSON object.");
            com.google.gson.JsonObject map = parsed.getAsJsonObject();
            if (!map.has("version") || !map.get("version").isJsonPrimitive() || !map.get("version").getAsString().equals("3"))
                throw new IllegalArgumentException("Only version 3 source maps are supported.");
            List<Finding> out = new ArrayList<>();
            String host = hostFromUrl(url);
            out.add(new Finding(FindingType.SOURCE_MAP_DISCLOSURE.name(), Severity.MEDIUM, 82,
                url, host, "Source map exposed in response", "A source map exposes client-side implementation details.",
                shrink(body, 240), "Review disclosed sources and restrict production exposure where appropriate.", "sourcemap"));
            if (map.has("sections"))
                throw new IllegalArgumentException("Indexed source maps are not supported; inspect their component maps individually.");
            if (!map.has("sources") || !map.get("sources").isJsonArray())
                throw new IllegalArgumentException("Source map sources must be an array.");
            var sources = map.getAsJsonArray("sources");
            if (sources.size() > AnalysisLimits.MAX_FINDINGS)
                throw new IllegalArgumentException("Source map exceeds the 1000-source budget.");
            if (!map.has("sourcesContent")) return out;
            if (!map.get("sourcesContent").isJsonArray())
                throw new IllegalArgumentException("Source map sourcesContent must be an array.");
            var contents = map.getAsJsonArray("sourcesContent");
            if (contents.size() != sources.size())
                throw new IllegalArgumentException("Source map source/content arrays must have matching lengths.");
            for (int i = 0; i < contents.size(); i++) {
                var source = sources.get(i);
                var content = contents.get(i);
                if (!source.isJsonPrimitive() || !source.getAsJsonPrimitive().isString())
                    throw new IllegalArgumentException("Source paths must be strings.");
                if (content.isJsonNull()) continue;
                if (!content.isJsonPrimitive() || !content.getAsJsonPrimitive().isString())
                    throw new IllegalArgumentException("Source content must be a string or null.");
                for (Finding finding : JavaScriptAnalyzer.analyzeJavaScriptContent(url, content.getAsString())) {
                    AnalysisLimits.checkFindings(out.size() + 1);
                    out.add(new Finding(finding.type(), finding.severity(), finding.confidence(), finding.url(),
                        finding.host(), finding.title(), finding.summary(), "[source: " + source.getAsString() + "] " + finding.evidence(),
                        finding.recommendation(), finding.identity() + "|source-index:" + i, finding.firstSeen()));
                }
            }
            return out;
        } catch (java.io.IOException | com.google.gson.JsonParseException | IllegalStateException error) {
            throw new IllegalArgumentException("Invalid or over-depth source map JSON.", error);
        }
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

    private static String hostFromUrl(String url) {
        try {
            URL u = new URL(url);
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
