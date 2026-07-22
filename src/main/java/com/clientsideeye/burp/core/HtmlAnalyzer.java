package com.clientsideeye.burp.core;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.nodes.TextNode;
import org.jsoup.select.Elements;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.clientsideeye.burp.core.Finding.Severity;

public final class HtmlAnalyzer {

    private HtmlAnalyzer() {}

    private static final String[] RISK_KEYWORDS = new String[]{
            "delete", "remove", "admin", "role", "permission", "privilege",
            "approve", "reject", "reset", "unlock", "disable", "enable",
            "export", "import", "service", "serviceaccount", "account",
            "sudo", "elevat", "impersonat", "grant", "revoke", "token", "key"
    };
    private static final String[] STATE_CHANGE_KEYWORDS = new String[]{
            "save", "submit", "update", "create", "add", "apply", "confirm"
    };

    // Matches any HTML/XML-like opening tag or DOCTYPE marker (e.g. "<div", "<script", "<!DOCTYPE").
    // Intentionally broad: callers are expected to have already excluded known non-HTML content
    // (by file extension or JSON/source-map sniffing) before relying on this as a positive signal.
    private static final Pattern HTML_TAG_HINT = Pattern.compile("<\\s*(?:[a-zA-Z][\\w-]*[\\s/>]|!DOCTYPE)");

    public static boolean looksLikeHtmlForAnalysis(String url, String body) {
        if (body == null || body.isBlank()) return false;
        String u = url == null ? "" : url.toLowerCase(Locale.ROOT);
        if (u.matches(".*\\.(map|js|mjs|css|json|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot)(\\?.*)?$")) return false;

        String t = body.trim();
        if (t.startsWith("{") || t.startsWith("[")) {
            String lower = t.toLowerCase(Locale.ROOT);
            if (lower.contains("\"version\"") && lower.contains("\"sources\"")) return false;
            if (lower.contains("\"openapi\"") || lower.contains("\"swagger\"")) return false;
        }

        return HTML_TAG_HINT.matcher(t).find();
    }

    private static String shrink(String s, int max) {
        if (s == null) return "";
        s = s.replaceAll("\\s+", " ").trim();
        if (s.length() <= max) return s;
        return s.substring(0, max) + "...";
    }

    private static String hostFromUrl(String url) {
        try {
            return URI.create(url).getHost() == null ? "" : URI.create(url).getHost();
        } catch (Exception e) {
            return "";
        }
    }

    public static List<Finding> analyzeHtml(String url, String html) {
        if (html == null || html.isBlank()) return List.of();
        if (!looksLikeHtmlForAnalysis(url, html)) return List.of();

        Document document = Jsoup.parse(html, url);
        List<Finding> out = new ArrayList<>();
        String host = hostFromUrl(url);

        addPasswordFindings(out, document, url, host);
        addHiddenDisabledFindings(out, document, url, host);
        addRoleHintFinding(out, document, url, host);
        addScriptFindings(out, document, html, url, host);
        return out;
    }

    private static void addPasswordFindings(List<Finding> out, Document document, String url, String host) {
        for (Element input : document.select("input[type=password]")) {
            if (!input.hasAttr("value")) continue;

            String value = input.attr("value").trim();
            int conf = 95;
            if (value.isEmpty()) conf = 70;
            if (value.equalsIgnoreCase("password") || value.equalsIgnoreCase("********")) conf = 75;

            String evidence = shrink(input.outerHtml(), 400);
            out.add(new Finding(
                    FindingType.PASSWORD_VALUE_IN_DOM.name(),
                    Severity.HIGH,
                    conf,
                    url,
                    host,
                    "Password value present in HTML",
                    "An <input type=\"password\"> includes a value attribute in the HTML. Users can reveal it via DevTools or intercepting proxies.",
                    evidence,
                    "Do not render secrets or passwords into client-side HTML. Populate credentials server-side only when needed, and never include password values in responses. Enforce server-side authorization and consider rotating exposed credentials.",
                    elementIdentity(input)
            ));
        }
    }

    private static void addHiddenDisabledFindings(List<Finding> out, Document document, String url, String host) {
        Elements controls = document.select("button,a,input,select,textarea,form,div,span,[role=button]");
        for (Element element : controls) {
            String tag = element.tagName().toLowerCase(Locale.ROOT);
            boolean hidden = hasHiddenSignal(element);
            boolean disabled = hasDisabledSignal(element);
            if (!hidden && !disabled) continue;

            if ("input".equals(tag)) {
                String type = element.attr("type").toLowerCase(Locale.ROOT);
                if (!(type.isBlank() || type.equals("submit") || type.equals("button") || type.equals("image") || type.equals("password") || type.equals("reset"))) {
                    continue;
                }
            }

            ControlSignals signals = scoreControlSignals(element);
            if (!signals.actionable && !hasDirectInteractivitySignal(element) && ("div".equals(tag) || "span".equals(tag))) {
                // Plain hidden/disabled divs and spans are extremely common for pure layout/CSS
                // purposes and are not interactive controls, so skip them entirely to reduce noise.
                // Only skip when there is also no direct evidence of click/keyboard interactivity -
                // otherwise a hidden "div role=button onclick=..." style control (a common real-world
                // pattern for privileged actions) would be silently dropped instead of at least being
                // reported informationally.
                continue;
            }

            String state = (hidden ? "hidden" : "") + (hidden && disabled ? " & " : "") + (disabled ? "disabled" : "");
            String why = signals.reasons.isEmpty() ? "" : ("Signals: " + String.join(", ", signals.reasons) + ".");
            String evidence = shrink(element.outerHtml(), 420);
            String identity = elementIdentity(element);

            if (signals.actionable) {
                out.add(new Finding(
                        FindingType.HIDDEN_OR_DISABLED_CONTROL.name(),
                        severityForActionableHiddenControl(signals.confidence),
                        signals.confidence,
                        url,
                        host,
                        "Client-side " + state + " control likely to perform an action",
                        "An interactive control is present in the HTML but is " + state + " on the client side and appears actionable. If server-side authorization is missing, users may be able to enable/trigger privileged actions. " + why,
                        evidence,
                        "Do not rely on client-side hiding/disabled states for authorization. Enforce authorization server-side for all actions. Prefer not rendering unauthorized controls at all (or render in a non-actionable form).",
                        identity
                ));
            } else {
                int infoConf = Math.min(45, Math.max(15, signals.confidence));
                out.add(new Finding(
                        FindingType.HIDDEN_OR_DISABLED_CONTROL.name(),
                        Severity.INFO,
                        infoConf,
                        url,
                        host,
                        "Hidden/disabled control detected (informational)",
                        "A control is present in the HTML but is " + state + " on the client side. It does not show clear signals of a state-changing action. " + why,
                        evidence,
                        "If this control maps to privileged actions, ensure authorization is enforced server-side. Otherwise, consider removing it from the DOM for unauthorized users.",
                        identity
                ));
            }
        }
    }

    private static void addRoleHintFinding(List<Finding> out, Document document, String url, String host) {
        String scanText = document.outerHtml();
        Pattern roleHint = Pattern.compile(
                "(?is)\\b(permission|authorize|isadmin|is_admin|acl|rbac|privilege)\\b|role\\s*[:=]\\s*['\"]?(admin|superuser|owner|manager|privileged|staff)\\b"
        );
        Matcher matcher = roleHint.matcher(scanText);
        if (!matcher.find()) return;

        String matched = matcher.group(1) != null ? matcher.group(1) : matcher.group(2);
        out.add(new Finding(
                FindingType.ROLE_PERMISSION_HINT.name(),
                Severity.INFO,
                35,
                url,
                host,
                "Role/permission hints found in HTML/JS",
                "The page contains role/permission-related keywords. This may help locate authorization logic or UI gating, but is not necessarily a vulnerability on its own.",
                "Matched keyword: " + matched,
                "Confirm all authorization decisions are enforced server-side. Avoid leaking internal role names or authorization flags to the client unless required.",
                "role-hint:" + matched.toLowerCase(Locale.ROOT)
        ));
    }

    private static void addScriptFindings(List<Finding> out, Document document, String html, String url, String host) {
        List<ScriptCandidate> secretishCandidates = new ArrayList<>();
        List<ScriptCandidate> devtoolsCandidates = new ArrayList<>();

        for (Element script : document.select("script")) {
            String body = script.data();
            if (body == null || body.isBlank()) {
                body = script.html();
            }
            if (body == null || body.isBlank()) continue;

            if (looksSecretish(body)) {
                secretishCandidates.add(new ScriptCandidate(30, body));
            }

            DevtoolsSignals signals = scoreDevtoolsSignals(body);
            if (signals.confidence >= 40) {
                devtoolsCandidates.add(new ScriptCandidate(signals.confidence, body));
            }
        }

        addSecretishFindings(out, secretishCandidates, url, host);
        addDevtoolsFindings(out, devtoolsCandidates, url, host);

        if (devtoolsCandidates.isEmpty() && looksDevtoolsHint(html)) {
            out.add(new Finding(
                    FindingType.DEVTOOLS_BLOCKING.name(),
                    Severity.INFO,
                    30,
                    url,
                    host,
                    "DevTools-related hint found in HTML",
                    "The page contains DevTools-related keywords. This may indicate client-side detection or blocking logic elsewhere (e.g., external scripts).",
                    shrink(html, 240),
                    "If DevTools access is blocked and testing is authorized, look for client-side detection in scripts and consider a controlled bypass snippet.",
                    "devtools-hint"
            ));
        }
    }

    private static boolean hasHiddenSignal(Element element) {
        Set<String> classes = loweredClassNames(element);
        String style = element.attr("style").toLowerCase(Locale.ROOT);

        boolean a11yOnlyHidden = classes.contains("sr-only")
                || classes.contains("visually-hidden")
                || classes.contains("visuallyhidden");
        boolean visuallyHidden = style.contains("display:none")
                || style.contains("display: none")
                || style.contains("visibility:hidden")
                || style.contains("visibility: hidden")
                || style.contains("opacity:0")
                || style.contains("opacity: 0");
        boolean hiddenAttribute = element.hasAttr("hidden") || element.hasAttr("aria-hidden");
        boolean hiddenClass = classes.contains("hidden") || classes.contains("d-none");

        if (a11yOnlyHidden && !visuallyHidden && !hiddenAttribute) return false;
        return visuallyHidden || hiddenAttribute || hiddenClass;
    }

    // Direct, unambiguous signals that a non-form element (div/span) is wired up as a clickable
    // control, independent of the broader weighted heuristic score used for confidence/severity.
    private static boolean hasDirectInteractivitySignal(Element element) {
        if (element.hasAttr("onclick") || element.hasAttr("onmousedown") || element.hasAttr("onmouseup")) {
            return true;
        }
        if ("button".equalsIgnoreCase(element.attr("role")) || "link".equalsIgnoreCase(element.attr("role"))) {
            return true;
        }
        return element.hasAttr("tabindex");
    }

    private static boolean hasDisabledSignal(Element element) {
        Set<String> classes = loweredClassNames(element);
        return element.hasAttr("disabled")
                || "true".equalsIgnoreCase(element.attr("aria-disabled"))
                || classes.contains("disabled")
                || classes.contains("pf-m-disabled")
                || classes.contains("is-disabled")
                || classes.contains("btn-disabled");
    }

    private static Set<String> loweredClassNames(Element element) {
        Set<String> out = new HashSet<>();
        for (String className : element.classNames()) {
            out.add(className.toLowerCase(Locale.ROOT));
        }
        return out;
    }

    private static class ControlSignals {
        int confidence;
        boolean actionable;
        List<String> reasons = new ArrayList<>();
    }

    private static ControlSignals scoreControlSignals(Element element) {
        ControlSignals signals = new ControlSignals();
        int conf = 10;
        int action = 0;

        String tag = element.tagName().toLowerCase(Locale.ROOT);
        String lowerHtml = element.outerHtml().toLowerCase(Locale.ROOT);
        String href = element.attr("href").toLowerCase(Locale.ROOT);

        if (element.hasAttr("onclick") || element.hasAttr("onmousedown") || element.hasAttr("onmouseup") || element.hasAttr("onchange")) {
            action += 30;
            signals.reasons.add("event handler");
        }
        if (element.hasAttr("formaction") || element.hasAttr("formmethod") || element.hasAttr("form")) {
            action += 30;
            signals.reasons.add("form action");
        }
        if ("submit".equalsIgnoreCase(element.attr("type"))) {
            action += 30;
            signals.reasons.add("submit");
        }
        if (hasDisabledSignal(element)) {
            action += 15;
            signals.reasons.add("client-side disabled gate");
        }

        if (!href.isBlank()) {
            if (href.startsWith("#") || href.startsWith("javascript:")) {
                action += 10;
                signals.reasons.add("href (weak)");
            } else {
                action += 25;
                signals.reasons.add("href");
            }
        }

        if (element.hasAttr("data-action") || element.hasAttr("data-url") || element.hasAttr("data-endpoint") || element.hasAttr("data-method")) {
            action += 20;
            signals.reasons.add("data-* action");
        }

        if ("button".equals(tag)) action += 10;
        if ("input".equals(tag)) {
            String type = element.attr("type").toLowerCase(Locale.ROOT);
            if (type.equals("button") || type.equals("submit") || type.equals("image") || type.equals("reset")) {
                action += 15;
            }
        }
        if ("button".equalsIgnoreCase(element.attr("role"))) {
            action += 10;
            signals.reasons.add("role=button");
        }
        if (element.hasAttr("tabindex")) {
            action += 5;
            signals.reasons.add("tabindex");
        }

        String idNameBlob = String.join(" ",
                element.id().toLowerCase(Locale.ROOT),
                element.attr("name").toLowerCase(Locale.ROOT),
                element.attr("value").toLowerCase(Locale.ROOT),
                element.attr("aria-label").toLowerCase(Locale.ROOT),
                element.attr("title").toLowerCase(Locale.ROOT),
                href,
                element.attr("data-action").toLowerCase(Locale.ROOT),
                element.attr("data-url").toLowerCase(Locale.ROOT),
                element.attr("data-endpoint").toLowerCase(Locale.ROOT),
                element.attr("data-testid").toLowerCase(Locale.ROOT),
                ownText(element).toLowerCase(Locale.ROOT),
                lowerHtml
        );

        int keywordHits = 0;
        for (String keyword : RISK_KEYWORDS) {
            if (idNameBlob.contains(keyword)) keywordHits++;
        }
        if (keywordHits > 0) {
            conf += Math.min(30, keywordHits * 8);
            signals.reasons.add("risky keyword(s)");
        }

        if (idNameBlob.contains("btn") || idNameBlob.contains("ctl00") || idNameBlob.contains("cphmain")) {
            conf += 5;
            signals.reasons.add("webforms-ish id/name");
        }
        for (String keyword : STATE_CHANGE_KEYWORDS) {
            if (idNameBlob.contains(keyword)) {
                action += 10;
                signals.reasons.add("state-change label");
                break;
            }
        }

        int combined = conf + action;
        signals.confidence = Math.max(0, Math.min(100, combined));
        signals.actionable = action >= 60;
        return signals;
    }

    private static String ownText(Element element) {
        StringBuilder sb = new StringBuilder();
        for (Node node : element.childNodes()) {
            if (node instanceof TextNode textNode) {
                sb.append(textNode.text()).append(' ');
            }
        }
        String text = sb.toString().replaceAll("\\s+", " ").trim();
        if (!text.isBlank()) return text;
        return element.text().replaceAll("\\s+", " ").trim();
    }

    private static String elementIdentity(Element element) {
        String text = ownText(element);
        if (text.length() > 80) text = text.substring(0, 80);
        return String.join("|",
                element.tagName().toLowerCase(Locale.ROOT),
                element.id(),
                element.attr("data-testid"),
                element.attr("name"),
                element.attr("href"),
                element.attr("action"),
                element.attr("aria-label"),
                text
        );
    }

    private static Severity severityForActionableHiddenControl(int confidence) {
        if (confidence >= 85) return Severity.HIGH;
        if (confidence >= 60) return Severity.MEDIUM;
        return Severity.LOW;
    }

    private static boolean looksSecretish(String scriptBody) {
        String s = scriptBody;
        if (s == null) return false;

        Pattern secretAssign = Pattern.compile("(?i)(api[_-]?key|secret|bearer|token)\\b\\s*[:=]\\s*['\\\"][^'\\\"]{20,}['\\\"]");
        if (secretAssign.matcher(s).find()) return true;

        if (s.contains("eyJ") && s.contains(".")) return true;
        Pattern tokenNearKeyword = Pattern.compile("(?is)(api[_-]?key|secret|bearer|token|authorization)\\b.{0,80}?([a-z0-9+/]{30,}={0,2}|[a-f0-9]{32,})");
        return tokenNearKeyword.matcher(s).find();
    }

    private static class ScriptCandidate {
        final int confidence;
        final String body;

        ScriptCandidate(int confidence, String body) {
            this.confidence = confidence;
            this.body = body == null ? "" : body;
        }
    }

    private static void addSecretishFindings(List<Finding> out, List<ScriptCandidate> candidates, String url, String host) {
        if (candidates == null || candidates.isEmpty()) return;
        Set<String> seen = new HashSet<>();
        for (ScriptCandidate candidate : candidates) {
            String snippet = shrink(candidate.body, 420);
            if (!seen.add(snippet)) continue;
            out.add(new Finding(
                    FindingType.INLINE_SCRIPT_SECRETISH.name(),
                    Severity.LOW,
                    30,
                    url,
                    host,
                    "Potential secret-like value in inline script",
                    "The page contains inline script content that looks like it may include credentials/tokens/keys. This is heuristic and can generate false positives.",
                    snippet,
                    "Avoid embedding secrets in client-side code. Use server-side sessions or retrieve short-lived tokens from protected endpoints with proper authorization.",
                    "script-secret:" + Integer.toHexString(snippet.hashCode())
            ));
        }
    }

    private static void addDevtoolsFindings(List<Finding> out, List<ScriptCandidate> candidates, String url, String host) {
        if (candidates == null || candidates.isEmpty()) return;
        candidates.sort((a, b) -> Integer.compare(b.confidence, a.confidence));
        Set<String> seen = new HashSet<>();
        for (ScriptCandidate candidate : candidates) {
            String snippet = shrink(candidate.body, 420);
            if (!seen.add(snippet)) continue;
            Severity severity = candidate.confidence >= 65 ? Severity.MEDIUM : Severity.LOW;
            out.add(new Finding(
                    FindingType.DEVTOOLS_BLOCKING.name(),
                    severity,
                    candidate.confidence,
                    url,
                    host,
                    "Possible DevTools blocking or detection logic in client-side script",
                    "The page includes script patterns commonly used to detect or disrupt DevTools usage (e.g., debugger statements, window size checks, or devtools keywords). This can interfere with client-side enumeration and validation.",
                    snippet,
                    "If this behavior is authorized to bypass, use a controlled DevTools bypass snippet to neutralize common detection hooks. Ensure testing remains in-scope and approved.",
                    "script-devtools:" + Integer.toHexString(snippet.hashCode())
            ));
        }
    }

    private static class DevtoolsSignals {
        int confidence;
    }

    private static DevtoolsSignals scoreDevtoolsSignals(String scriptBody) {
        DevtoolsSignals signals = new DevtoolsSignals();
        int score = 0;
        String lower = scriptBody == null ? "" : scriptBody.toLowerCase(Locale.ROOT);

        if (lower.contains("devtools") || lower.contains("dev tool") || lower.contains("developer tools")) score += 30;
        if (lower.contains("devtools-opened") || lower.contains("devtoolsopened")) score += 30;
        if (lower.contains("isdevtoolsopen") || lower.contains("devtoolsopen")) score += 20;
        if (lower.contains("disabletransformwhendevtoolsopen")) score += 25;
        if (lower.contains("outerwidth") && lower.contains("innerwidth")) score += 25;
        if (lower.contains("outerheight") && lower.contains("innerheight")) score += 20;
        if (lower.contains("outerwidth-innerwidth") || lower.contains("outerwidth - innerwidth")) score += 15;
        if (lower.contains("outerheight-innerheight") || lower.contains("outerheight - innerheight")) score += 15;
        if (lower.contains("outerwidth") && lower.contains("innerwidth") && lower.contains("math.abs")) score += 10;
        if ((lower.contains("outerwidth") && lower.contains("innerwidth") && lower.contains("160"))
                || (lower.contains("outerheight") && lower.contains("innerheight") && lower.contains("160"))) {
            score += 10;
        }
        if (lower.contains("debugger")) score += 20;
        if (lower.contains("setinterval") || lower.contains("settimeout")) score += 12;
        if (lower.contains("requestanimationframe")) score += 8;
        if (lower.contains("resize") && lower.contains("addeventlistener")) score += 10;
        if (lower.contains("console.clear") || lower.contains("console.log") || lower.contains("console.profile")) score += 10;
        if (lower.contains("tostring") && lower.contains("function")) score += 10;
        if (lower.contains("performance.now") || lower.contains("date.now")) score += 8;
        if (lower.contains("chrome") && lower.contains("devtools")) score += 10;

        signals.confidence = Math.max(0, Math.min(100, score));
        return signals;
    }

    private static boolean looksDevtoolsHint(String html) {
        if (html == null) return false;
        String lower = html.toLowerCase(Locale.ROOT);
        return lower.contains("devtools") || lower.contains("dev tool") || lower.contains("developer tools");
    }
}
