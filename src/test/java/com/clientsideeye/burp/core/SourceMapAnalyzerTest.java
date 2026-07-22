package com.clientsideeye.burp.core;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SourceMapAnalyzerTest {

    @Test
    void detectsSourceMappingReferenceInJavaScript() {
        String js = "console.log('app');\n//# sourceMappingURL=app.js.map";
        List<Finding> findings = SourceMapAnalyzer.analyzeSourceMappingReference("https://example.test/app.js", js);
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.SOURCE_MAP_DISCLOSURE.name())));
    }

    @Test
    void detectsExposedSourceMapAndEmbeddedJavaScriptSignals() {
        String map = """
                {
                  "version":3,
                  "sources":["src/app.js"],
                  "sourcesContent":["fetch('/api/admin/users'); eval(location.hash);"]
                }
                """;
        List<Finding> findings = SourceMapAnalyzer.analyzeSourceMap("https://example.test/app.js.map", map);
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.SOURCE_MAP_DISCLOSURE.name())));
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.JAVASCRIPT_ENDPOINT_REFERENCE.name())));
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.DOM_XSS_SINK.name())));
    }
}
