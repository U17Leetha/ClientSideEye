package com.clientsideeye.burp.core;

import java.util.List;

public final class JsonExporter {

    private JsonExporter() {}

    public static String toJson(List<Finding> findings) {
        return toJson(findings, null);
    }

    public static String toJson(List<Finding> findings, java.util.Set<String> falsePositiveKeys) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"tool\":\"ClientSideEye\",\"findings\":[");
        boolean first = true;
        for (Finding f : findings) {
            if (!first) sb.append(",");
            first = false;
            boolean isFalsePositive = falsePositiveKeys != null && falsePositiveKeys.contains(f.stableKey());
            sb.append("{");
            kv(sb, "type", f.type()); sb.append(",");
            kv(sb, "severity", f.severity().name()); sb.append(",");
            sb.append("\"confidence\":").append(f.confidence()).append(",");
            sb.append("\"falsePositive\":").append(isFalsePositive).append(",");
            kv(sb, "url", f.url()); sb.append(",");
            kv(sb, "host", f.host()); sb.append(",");
            kv(sb, "title", f.title()); sb.append(",");
            kv(sb, "identity", f.identity()); sb.append(",");
            kv(sb, "firstSeen", f.firstSeen()); sb.append(",");
            kv(sb, "summary", f.summary()); sb.append(",");
            kv(sb, "evidence", f.evidence()); sb.append(",");
            kv(sb, "recommendation", f.recommendation());
            sb.append("}");
        }
        sb.append("]}");
        return sb.toString();
    }

    private static void kv(StringBuilder sb, String k, String v) {
        sb.append("\"").append(esc(k)).append("\":\"").append(esc(v)).append("\"");
    }

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> out.append("\\\\");
                case '"' -> out.append("\\\"");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int)c));
                    else out.append(c);
                }
            }
        }
        return out.toString();
    }
}
