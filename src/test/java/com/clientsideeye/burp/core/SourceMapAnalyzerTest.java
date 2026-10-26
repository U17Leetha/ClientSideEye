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
    @Test
    void preservesNullSlotsDuplicateSourcesAndUnicode() {
        String map = "{\"version\":3,\"sources\":[\"first.js\",\"second.js\",\"second.js\"],\"sourcesContent\":[null,\"eval(location.hash);\",\"fetch('/api/admin');\"]}";
        var findings = SourceMapAnalyzer.analyzeSourceMap("https://example.test/a.map?q=\"><tag>", map);
        assertTrue(findings.stream().filter(f -> f.type().equals("DOM_XSS_SINK")).allMatch(f -> f.evidence().startsWith("[source: second.js]")));
        org.junit.jupiter.api.Assertions.assertEquals(1, findings.stream().filter(f -> f.type().equals("DOM_XSS_SINK")).count());
        assertTrue(findings.stream().anyMatch(f -> f.identity().contains("source-index:2")));
        assertTrue(findings.stream().allMatch(f -> f.host().equals("example.test")));
    }

    @Test
    void rejectsMalformedAndDeepMapsWithoutPartialResults() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
            () -> SourceMapAnalyzer.analyzeSourceMap("https://example.test/a.map", "{bad-json}"));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
            () -> SourceMapAnalyzer.analyzeSourceMap("https://example.test/a.map", "[".repeat(100) + "0" + "]".repeat(100)));
    }

}
