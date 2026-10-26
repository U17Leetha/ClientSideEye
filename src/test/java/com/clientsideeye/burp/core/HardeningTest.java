package com.clientsideeye.burp.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HardeningTest {
    @Test
    void identityPreservesKnownHashCollisionsAndLongSuffixes() {
        assertNotEquals(finding("Aa").stableKey(), finding("BB").stableKey());
        assertNotEquals(finding("x".repeat(400) + "a").stableKey(), finding("x".repeat(400) + "b").stableKey());
        assertEquals("original", finding("Aa").withFirstSeen("original").firstSeen());
    }

    @Test
    void visibleAttributesAndEmptyPasswordsDoNotBecomeSecurityFindings() {
        var findings = HtmlAnalyzer.analyzeHtml("https://example.test/open?q=\"><tag>",
            "<button aria-hidden='false' style='opacity:0.5' onclick='save()'>Save</button><input type=password value=''>");
        assertTrue(findings.stream().noneMatch(f -> f.type().equals("HIDDEN_OR_DISABLED_CONTROL") || f.type().equals("PASSWORD_VALUE_IN_DOM")));
    }

    @Test
    void rejectsInputBudgetsBeforeCollectingUnboundedResults() {
        assertThrows(IllegalArgumentException.class, () -> ResponseAnalyzer.analyze("https://example.test/app.js", "a".repeat(AnalysisLimits.MAX_BODY_BYTES + 1)));
        assertThrows(IllegalArgumentException.class, () -> HtmlAnalyzer.analyzeHtml("https://example.test/", "<div>".repeat(100) + "<button hidden>Delete</button>" + "</div>".repeat(100)));
        assertThrows(IllegalArgumentException.class, () -> HtmlAnalyzer.analyzeHtml("https://example.test/", "<button hidden>Delete</button>".repeat(1100)));
    }

    @Test
    void sourceMapDecodesUnicodeAndBracketsInsideStrings() {
        String map = "{\"version\":3,\"sources\":[\"a]b.js\"],\"sourcesContent\":[\"\\u0065val(location.hash);\"]}";
        var findings = SourceMapAnalyzer.analyzeSourceMap("https://example.test/app.js.map", map);
        assertTrue(findings.stream().anyMatch(f -> f.type().equals("DOM_XSS_SINK") && f.evidence().startsWith("[source: a]b.js]")));
    }

    private static Finding finding(String identity) {
        return new Finding("DOM_XSS_SINK", Finding.Severity.LOW, 50, "https://example.test/", "example.test", "t", "s", "e", "r", identity);
    }
}
