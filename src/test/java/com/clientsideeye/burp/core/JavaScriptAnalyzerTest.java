package com.clientsideeye.burp.core;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class JavaScriptAnalyzerTest {

    @Test
    void detectsEndpointReferences() {
        String js = "fetch('/api/admin/users'); axios.get('/graphql');";
        List<Finding> findings = JavaScriptAnalyzer.analyzeJavaScript("https://example.test/app.js", js);
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.JAVASCRIPT_ENDPOINT_REFERENCE.name())));
    }

    @Test
    void detectsEndpointAndSinkReferencesWithoutDeclarationKeywordsOrJsExtension() {
        String js = "fetch('/api/admin/users'); eval(location.hash);";
        List<Finding> findings = JavaScriptAnalyzer.analyzeJavaScript("https://example.test/app.js.map", js);
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.JAVASCRIPT_ENDPOINT_REFERENCE.name())));
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.DOM_XSS_SINK.name())));
    }

    @Test
    void analyzeJavaScriptContentBypassesHeuristicGateForKnownJavaScript() {
        String js = "fetch('/api/admin/users');";
        List<Finding> findings = JavaScriptAnalyzer.analyzeJavaScriptContent("https://example.test/x", js);
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.JAVASCRIPT_ENDPOINT_REFERENCE.name())));
    }

    @Test
    void detectsDomXssSinks() {
        String js = "element.innerHTML = location.hash; eval(payload);";
        List<Finding> findings = JavaScriptAnalyzer.analyzeJavaScript("https://example.test/app.js", js);
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.DOM_XSS_SINK.name())));
    }

    @Test
    void detectsPostMessageUsage() {
        String js = "window.addEventListener('message', function(event){ doThing(event.data); });";
        List<Finding> findings = JavaScriptAnalyzer.analyzeJavaScript("https://example.test/app.js", js);
        assertTrue(findings.stream().anyMatch(f ->
                f.type().equals(FindingType.POSTMESSAGE_HANDLER.name())));
    }

    @Test
    void detectsFrameworkHtmlSinks() {
        String react = "const el = <div dangerouslySetInnerHTML={{__html: userInput}} />;";
        List<Finding> reactFindings = JavaScriptAnalyzer.analyzeJavaScript("https://example.test/app.js", react);
        assertTrue(reactFindings.stream().anyMatch(f ->
                f.type().equals(FindingType.DOM_XSS_SINK.name())));

        String angular = "this.sanitizer.bypassSecurityTrustHtml(userInput);";
        List<Finding> angularFindings = JavaScriptAnalyzer.analyzeJavaScript("https://example.test/app.js", angular);
        assertTrue(angularFindings.stream().anyMatch(f ->
                f.type().equals(FindingType.DOM_XSS_SINK.name()) && f.confidence() >= 70));
    }

    @Test
    void detectsPrototypePollutionPatterns() {
        String directProto = "function set(o){ o.__proto__.isAdmin = true; }";
        List<Finding> directFindings = JavaScriptAnalyzer.analyzeJavaScript("https://example.test/app.js", directProto);
        assertTrue(directFindings.stream().anyMatch(f ->
                f.type().equals(FindingType.PROTOTYPE_POLLUTION_HINT.name())));

        String mergeCall = "function apply(target, input){ _.merge(target, JSON.parse(input)); }";
        List<Finding> mergeFindings = JavaScriptAnalyzer.analyzeJavaScript("https://example.test/app.js", mergeCall);
        assertTrue(mergeFindings.stream().anyMatch(f ->
                f.type().equals(FindingType.PROTOTYPE_POLLUTION_HINT.name())));
    }

    @Test
    void detectsWebSocketAndEventSourceEndpointReferences() {
        String ws = "function connect(){ const socket = new WebSocket('wss://example.test/ws'); }";
        List<Finding> wsFindings = JavaScriptAnalyzer.analyzeJavaScript("https://example.test/app.js", ws);
        assertTrue(wsFindings.stream().anyMatch(f ->
                f.type().equals(FindingType.RUNTIME_NETWORK_REFERENCE.name()) && f.evidence().contains("wss://example.test/ws")));

        String es = "function stream(){ const source = new EventSource('/api/events'); }";
        List<Finding> esFindings = JavaScriptAnalyzer.analyzeJavaScript("https://example.test/app.js", es);
        assertTrue(esFindings.stream().anyMatch(f ->
                f.type().equals(FindingType.RUNTIME_NETWORK_REFERENCE.name()) && f.evidence().contains("/api/events")));
    }
}
