package com.clientsideeye.burp.core;

import java.util.ArrayList;
import java.util.List;

/** Shared static-analysis dispatch for Site Map and request selections. */
public final class ResponseAnalyzer {
    private ResponseAnalyzer() {}
    public static List<Finding> analyze(String url, String body) {
        AnalysisLimits.checkBody(body);
        if (SourceMapAnalyzer.looksLikeSourceMap(url, body)) return SourceMapAnalyzer.analyzeSourceMap(url, body);
        List<Finding> out = new ArrayList<>();
        if (HtmlAnalyzer.looksLikeHtmlForAnalysis(url, body)) out.addAll(HtmlAnalyzer.analyzeHtml(url, body));
        if (JavaScriptAnalyzer.looksLikeJavaScriptForAnalysis(url, body)) {
            out.addAll(JavaScriptAnalyzer.analyzeJavaScript(url, body));
            out.addAll(SourceMapAnalyzer.analyzeSourceMappingReference(url, body));
        }
        AnalysisLimits.checkFindings(out.size());
        return out;
    }
}
