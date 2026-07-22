package com.clientsideeye.burp.ui;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class FindHintBuilder {

    private FindHintBuilder() {}

    record HintEntry(String label, String value) {
        HintEntry {
            label = label == null ? "" : label;
            value = value == null ? "" : value;
        }

        String displayText() {
            if (value.isBlank() || value.indexOf('\n') >= 0) return label;
            String preview = value.length() > 80 ? value.substring(0, 80) + "..." : value;
            return label + ": " + preview;
        }

        @Override
        public String toString() {
            return displayText();
        }
    }

    static final class Result {
        final String bestSelector;
        final List<HintEntry> hints;
        final String highlightSnippet;
        final String revealSnippet;

        Result(String bestSelector, List<HintEntry> hints, String highlightSnippet, String revealSnippet) {
            this.bestSelector = bestSelector == null ? "" : bestSelector;
            this.hints = hints == null ? List.of() : hints;
            this.highlightSnippet = highlightSnippet == null ? "" : highlightSnippet;
            this.revealSnippet = revealSnippet == null ? "" : revealSnippet;
        }
    }

    static Result build(String evidence) {
        String id = extractAttr(evidence, "id");
        String dataTestId = extractAttr(evidence, "data-testid");
        String name = extractAttr(evidence, "name");
        String ariaLabel = extractAttr(evidence, "aria-label");
        String role = extractAttr(evidence, "role");
        String type = extractAttr(evidence, "type");
        String value = extractAttr(evidence, "value");
        String href = extractAttr(evidence, "href");
        String src = extractAttr(evidence, "src");
        String action = extractAttr(evidence, "action");
        String text = extractInnerText(evidence);

        List<SelectorCandidate> selectors = rankedSelectors(id, dataTestId, name, ariaLabel, role, type, value, href, src, action, text);
        String bestSelector = selectors.isEmpty() ? "" : selectors.get(0).selector;
        List<HintEntry> hints = new ArrayList<>();

        for (SelectorCandidate candidate : selectors) {
            hints.add(new HintEntry(candidate.label, locateSnippet(candidate.selector)));
        }

        if (!text.isBlank()) {
            hints.add(new HintEntry("Locate by text (exact)", locateByTextSnippet(text, role, type)));
        }

        if (!text.isBlank() || !bestSelector.isBlank()) {
            hints.add(new HintEntry("Locate across iframes/shadow roots", deepLocateSnippet(bestSelector, text, role, type)));
        }

        if (!bestSelector.isBlank()) {
            hints.add(new HintEntry("Elements search (CSS)", bestSelector));
        }

        if (!id.isBlank()) {
            hints.add(new HintEntry("Inspector search text", "id=\"" + id + "\""));
        }
        if (!dataTestId.isBlank()) {
            hints.add(new HintEntry("Inspector search text", "data-testid=\"" + dataTestId + "\""));
        }
        if (!name.isBlank()) {
            hints.add(new HintEntry("Inspector search text", "name=\"" + name + "\""));
        }
        if (!ariaLabel.isBlank()) {
            hints.add(new HintEntry("Inspector search text", "aria-label=\"" + ariaLabel + "\""));
        }
        if (!href.isBlank()) {
            hints.add(new HintEntry("Inspector search text", "href=\"" + href + "\""));
        }
        if (!text.isBlank()) {
            hints.add(new HintEntry("Inspector search text", text));
        }

        String findTerm = bestEvidenceSearchTerm(evidence);
        if (!findTerm.isBlank()) {
            hints.add(new HintEntry("Markup search term", findTerm));
        }
        if (hints.isEmpty()) {
            hints.add(new HintEntry("Markup search term", evidence == null ? "" : evidence.replaceAll("\\s+", " ").trim()));
        }

        String highlightSnippet = highlightSnippet(bestSelector, text, role, type);
        String revealSnippet = revealSnippet(bestSelector, dataTestId, text, role, type);
        return new Result(bestSelector, hints, highlightSnippet, revealSnippet);
    }

    private static List<SelectorCandidate> rankedSelectors(
            String id,
            String dataTestId,
            String name,
            String ariaLabel,
            String role,
            String type,
            String value,
            String href,
            String src,
            String action,
            String text
    ) {
        Set<String> seen = new LinkedHashSet<>();
        List<SelectorCandidate> out = new ArrayList<>();
        addCandidate(out, seen, "Locate (high confidence: data-testid)", attrSelector("data-testid", dataTestId));
        addCandidate(out, seen, "Locate (high confidence: id)", attrSelector("id", id));
        addCandidate(out, seen, "Locate (high confidence: name)", attrSelector("name", name));
        addCandidate(out, seen, "Locate (fallback: aria-label)", attrSelector("aria-label", ariaLabel));
        if (!href.isBlank()) addCandidate(out, seen, "Locate (fallback: href)", "a[href=\"" + cssEscape(href) + "\"]");
        if (!action.isBlank()) addCandidate(out, seen, "Locate (fallback: form action)", "form[action=\"" + cssEscape(action) + "\"]");
        if (!src.isBlank()) addCandidate(out, seen, "Locate (fallback: src)", "[src=\"" + cssEscape(src) + "\"]");
        if (!type.isBlank()) {
            if (!value.isBlank()) {
                addCandidate(out, seen, "Locate (fallback: type + value)", "input[type=\"" + cssEscape(type) + "\"][value=\"" + cssEscape(value) + "\"]");
            }
            addCandidate(out, seen, "Locate (fallback: type)", "button[type=\"" + cssEscape(type) + "\"],input[type=\"" + cssEscape(type) + "\"],select[type=\"" + cssEscape(type) + "\"]");
        }
        if (!role.isBlank() && !text.isBlank()) {
            addCandidate(out, seen, "Locate (fallback: role + text)", "[role=\"" + cssEscape(role) + "\"]");
        }
        if (!text.isBlank()) {
            String normalized = text.length() > 40 ? text.substring(0, 40) : text;
            addCandidate(out, seen, "Locate (fallback: button-ish text)", "button,a,[role=\"button\"],input[type=\"button\"],input[type=\"submit\"]");
            addCandidate(out, seen, "Locate (fallback: text anchor)", "*");
            if (!normalized.isBlank()) {
                // keep text available for later snippets
            }
        }
        return out;
    }

    private static void addCandidate(List<SelectorCandidate> out, Set<String> seen, String label, String selector) {
        if (selector == null || selector.isBlank()) return;
        if (!seen.add(selector)) return;
        out.add(new SelectorCandidate(label, selector));
    }

    private record SelectorCandidate(String label, String selector) {}

    static String extractAttr(String text, String attr) {
        if (text == null) return "";
        Pattern p = Pattern.compile("(?i)\\b" + Pattern.quote(attr) + "\\s*=\\s*(?:([\"'])(.*?)\\1|([^\\s>]+))");
        Matcher m = p.matcher(text);
        if (m.find()) {
            String quoted = m.group(2);
            if (quoted != null) return quoted;
            String unquoted = m.group(3);
            return unquoted == null ? "" : unquoted;
        }
        return "";
    }

    static String bestEvidenceSearchTerm(String evidence) {
        if (evidence == null) return "";
        String dataTestId = extractAttr(evidence, "data-testid");
        if (!dataTestId.isBlank()) return "data-testid=\"" + dataTestId + "\"";

        String href = extractAttr(evidence, "href");
        if (!href.isBlank()) return "href=\"" + href + "\"";

        String src = extractAttr(evidence, "src");
        if (!src.isBlank()) return "src=\"" + src + "\"";

        String action = extractAttr(evidence, "action");
        if (!action.isBlank()) return "action=\"" + action + "\"";

        String s = evidence.replaceAll("\\s+", " ").trim();
        if (s.length() > 80) s = s.substring(0, 80);
        return s;
    }

    private static String attrSelector(String attr, String value) {
        if (value == null || value.isBlank()) return "";
        return "[" + attr + "=\"" + cssEscape(value) + "\"]";
    }

    private static String locateSnippet(String selector) {
        String jsSelector = jsSingleQuoteEscape(selector);
        return ""
                + "(() => {\n"
                + "  const matches = [...document.querySelectorAll('" + jsSelector + "')];\n"
                + "  if (!matches.length) return console.log('[ClientSideEye] no matches for selector:', '" + jsSelector + "');\n"
                + "  matches.forEach((el, i) => {\n"
                + "    el.scrollIntoView({block:'center'});\n"
                + "    console.log('[ClientSideEye] match', i, el);\n"
                + "  });\n"
                + "  if (matches[0] && typeof inspect === 'function') inspect(matches[0]);\n"
                + "  return matches;\n"
                + "})()";
    }

    private static String locateByTextSnippet(String text, String role, String type) {
        String jsText = jsSingleQuoteEscape(text);
        String jsRole = jsSingleQuoteEscape(role);
        String jsType = jsSingleQuoteEscape(type);
        return ""
                + "(() => {\n"
                + "  const want = '" + jsText + "'.trim().toLowerCase();\n"
                + "  const nodes = [...document.querySelectorAll('button,a,input,select,textarea,[role=\"button\"],[role]')];\n"
                + "  const matches = nodes.filter(el => {\n"
                + "    const textValue = (el.innerText || el.textContent || el.value || '').replace(/\\s+/g, ' ').trim().toLowerCase();\n"
                + "    if (want && textValue !== want) return false;\n"
                + "    if ('" + jsRole + "' && el.getAttribute('role') !== '" + jsRole + "') return false;\n"
                + "    if ('" + jsType + "' && (el.getAttribute('type') || '').toLowerCase() !== '" + jsType + "') return false;\n"
                + "    return true;\n"
                + "  });\n"
                + "  matches.forEach((el, i) => console.log('[ClientSideEye] text match', i, el));\n"
                + "  if (matches[0]) { matches[0].scrollIntoView({block:'center'}); if (typeof inspect === 'function') inspect(matches[0]); }\n"
                + "  return matches;\n"
                + "})()";
    }

    private static String deepLocateSnippet(String selector, String text, String role, String type) {
        String jsSelector = jsSingleQuoteEscape(selector == null ? "" : selector);
        String jsText = jsSingleQuoteEscape(text == null ? "" : text);
        String jsRole = jsSingleQuoteEscape(role == null ? "" : role);
        String jsType = jsSingleQuoteEscape(type == null ? "" : type);
        return ""
                + "(() => {\n"
                + "  const selector = '" + jsSelector + "';\n"
                + "  const wantText = '" + jsText + "'.trim().toLowerCase();\n"
                + "  const seen = new Set();\n"
                + "  const roots = [document];\n"
                + "  [...document.querySelectorAll('*')].forEach(el => { if (el.shadowRoot) roots.push(el.shadowRoot); });\n"
                + "  [...document.querySelectorAll('iframe')].forEach(frame => { try { if (frame.contentDocument) roots.push(frame.contentDocument); } catch (e) {} });\n"
                + "  const matches = [];\n"
                + "  const add = el => { if (el && !seen.has(el)) { seen.add(el); matches.push(el); } };\n"
                + "  roots.forEach(root => {\n"
                + "    try {\n"
                + "      if (selector) root.querySelectorAll(selector).forEach(add);\n"
                + "      if (!matches.length && wantText) {\n"
                + "        root.querySelectorAll('button,a,input,select,textarea,[role],[role=\"button\"]').forEach(el => {\n"
                + "          const textValue = (el.innerText || el.textContent || el.value || '').replace(/\\s+/g, ' ').trim().toLowerCase();\n"
                + "          if (textValue !== wantText) return;\n"
                + "          if ('" + jsRole + "' && el.getAttribute('role') !== '" + jsRole + "') return;\n"
                + "          if ('" + jsType + "' && (el.getAttribute('type') || '').toLowerCase() !== '" + jsType + "') return;\n"
                + "          add(el);\n"
                + "        });\n"
                + "      }\n"
                + "    } catch (e) {}\n"
                + "  });\n"
                + "  matches.forEach((el, i) => console.log('[ClientSideEye] deep match', i, el));\n"
                + "  if (matches[0]) { matches[0].scrollIntoView({block:'center'}); if (typeof inspect === 'function') inspect(matches[0]); }\n"
                + "  return matches;\n"
                + "})()";
    }

    private static String highlightSnippet(String selector, String text, String role, String type) {
        String baseLocate = !selector.isBlank()
                ? "root.querySelectorAll('" + jsSingleQuoteEscape(selector) + "').forEach(add);"
                : "";
        String jsText = jsSingleQuoteEscape(text == null ? "" : text);
        String jsRole = jsSingleQuoteEscape(role == null ? "" : role);
        String jsType = jsSingleQuoteEscape(type == null ? "" : type);
        return ""
                + "(() => {\n"
                + "  const matches = [];\n"
                + "  const seen = new Set();\n"
                + "  const add = el => { if (el && !seen.has(el)) { seen.add(el); matches.push(el); } };\n"
                + "  const roots = [document];\n"
                + "  [...document.querySelectorAll('*')].forEach(el => { if (el.shadowRoot) roots.push(el.shadowRoot); });\n"
                + "  [...document.querySelectorAll('iframe')].forEach(frame => { try { if (frame.contentDocument) roots.push(frame.contentDocument); } catch (e) {} });\n"
                + "  roots.forEach(root => {\n"
                + "    try {\n"
                + "      " + baseLocate + "\n"
                + "      if (!matches.length && '" + jsText + "') {\n"
                + "        root.querySelectorAll('button,a,input,select,textarea,[role],[role=\"button\"]').forEach(el => {\n"
                + "          const textValue = (el.innerText || el.textContent || el.value || '').replace(/\\s+/g, ' ').trim().toLowerCase();\n"
                + "          if (textValue !== '" + jsText + "'.trim().toLowerCase()) return;\n"
                + "          if ('" + jsRole + "' && el.getAttribute('role') !== '" + jsRole + "') return;\n"
                + "          if ('" + jsType + "' && (el.getAttribute('type') || '').toLowerCase() !== '" + jsType + "') return;\n"
                + "          add(el);\n"
                + "        });\n"
                + "      }\n"
                + "    } catch (e) {}\n"
                + "  });\n"
                + "  const revealed = [];\n"
                + "  const revealAncestors = (el) => {\n"
                + "    let node = el.parentElement;\n"
                + "    while (node && node.nodeType === 1) {\n"
                + "      const hadHidden = node.hasAttribute('hidden');\n"
                + "      const hadAriaHidden = node.getAttribute('aria-hidden') === 'true';\n"
                + "      const prevDisplay = node.style.display;\n"
                + "      const prevVisibility = node.style.visibility;\n"
                + "      const prevOpacity = node.style.opacity;\n"
                + "      let changed = false;\n"
                + "      if (hadHidden) { node.removeAttribute('hidden'); changed = true; }\n"
                + "      if (hadAriaHidden) { node.removeAttribute('aria-hidden'); changed = true; }\n"
                + "      const cs = getComputedStyle(node);\n"
                + "      if (cs.display === 'none') { node.style.setProperty('display', 'revert', 'important'); changed = true; }\n"
                + "      if (cs.visibility === 'hidden') { node.style.setProperty('visibility', 'visible', 'important'); changed = true; }\n"
                + "      if (cs.opacity === '0') { node.style.setProperty('opacity', '1', 'important'); changed = true; }\n"
                + "      if (changed) revealed.push({ node, hadHidden, hadAriaHidden, prevDisplay, prevVisibility, prevOpacity });\n"
                + "      node = node.parentElement;\n"
                + "    }\n"
                + "  };\n"
                + "  matches.forEach(revealAncestors);\n"
                + "  if (revealed.length) console.log('[ClientSideEye] temporarily revealed', revealed.length, 'hidden ancestor container(s) so the highlighted match is actually visible (use Reveal Snippet to unlock the control itself).');\n"
                + "  matches.forEach((el, i) => {\n"
                + "    el.dataset.clientsideeyeOutline = el.style.outline || '';\n"
                + "    el.dataset.clientsideeyeOutlineOffset = el.style.outlineOffset || '';\n"
                + "    el.style.outline = '3px solid #ff4d4f';\n"
                + "    el.style.outlineOffset = '2px';\n"
                + "    console.log('[ClientSideEye] highlighted match', i, el);\n"
                + "  });\n"
                + "  setTimeout(() => {\n"
                + "    matches.forEach(el => {\n"
                + "      el.style.outline = el.dataset.clientsideeyeOutline || '';\n"
                + "      el.style.outlineOffset = el.dataset.clientsideeyeOutlineOffset || '';\n"
                + "    });\n"
                + "    revealed.forEach(r => {\n"
                + "      if (r.hadHidden) r.node.setAttribute('hidden', '');\n"
                + "      if (r.hadAriaHidden) r.node.setAttribute('aria-hidden', 'true');\n"
                + "      r.node.style.display = r.prevDisplay;\n"
                + "      r.node.style.visibility = r.prevVisibility;\n"
                + "      r.node.style.opacity = r.prevOpacity;\n"
                + "    });\n"
                + "  }, 4000);\n"
                + "  if (matches[0]) matches[0].scrollIntoView({block:'center'});\n"
                + "  return matches;\n"
                + "})()";
    }

    private static String revealSnippet(String selector, String dataTestId, String text, String role, String type) {
        String jsSelector = jsSingleQuoteEscape(selector == null ? "" : selector);
        String jsTestId = jsSingleQuoteEscape(dataTestId == null ? "" : dataTestId);
        String jsText = jsSingleQuoteEscape(text == null ? "" : text);
        String jsRole = jsSingleQuoteEscape(role == null ? "" : role);
        String jsType = jsSingleQuoteEscape(type == null ? "" : type);
        return ""
                + "(() => {\n"
                + "  const matches = [];\n"
                + "  const seen = new Set();\n"
                + "  const add = el => { if (el && !seen.has(el)) { seen.add(el); matches.push(el); } };\n"
                + "  const roots = [document];\n"
                + "  [...document.querySelectorAll('*')].forEach(el => { if (el.shadowRoot) roots.push(el.shadowRoot); });\n"
                + "  [...document.querySelectorAll('iframe')].forEach(frame => { try { if (frame.contentDocument) roots.push(frame.contentDocument); } catch (e) {} });\n"
                + "  roots.forEach(root => {\n"
                + "    try {\n"
                + "      if ('" + jsSelector + "') root.querySelectorAll('" + jsSelector + "').forEach(add);\n"
                + "      if (!matches.length && '" + jsTestId + "') root.querySelectorAll('[data-testid=\"" + jsDoubleQuoteEscape(dataTestId == null ? "" : dataTestId) + "\"]').forEach(add);\n"
                + "      if (!matches.length && '" + jsText + "') {\n"
                + "        root.querySelectorAll('button,a,input,select,textarea,[role],[role=\"button\"]').forEach(el => {\n"
                + "          const textValue = (el.innerText || el.textContent || el.value || '').replace(/\\s+/g, ' ').trim().toLowerCase();\n"
                + "          if (textValue !== '" + jsText + "'.trim().toLowerCase()) return;\n"
                + "          if ('" + jsRole + "' && el.getAttribute('role') !== '" + jsRole + "') return;\n"
                + "          if ('" + jsType + "' && (el.getAttribute('type') || '').toLowerCase() !== '" + jsType + "') return;\n"
                + "          add(el);\n"
                + "        });\n"
                + "      }\n"
                + "    } catch (e) {}\n"
                + "  });\n"
                + "  const revealOne = (el) => {\n"
                + "    let node = el;\n"
                + "    while (node && node.nodeType === 1) {\n"
                + "      node.hidden = false;\n"
                + "      node.removeAttribute && node.removeAttribute('hidden');\n"
                + "      node.removeAttribute && node.removeAttribute('aria-hidden');\n"
                + "      if (node.tagName === 'INPUT' && node.type === 'password') {\n"
                + "        node.type = 'text';\n"
                + "        console.log('[ClientSideEye] unmasked password input', node);\n"
                + "      }\n"
                + "      if (node.style) {\n"
                + "        const cs = getComputedStyle(node);\n"
                + "        if (cs.display === 'none') node.style.setProperty('display', 'revert', 'important');\n"
                + "        if (cs.visibility === 'hidden') node.style.setProperty('visibility', 'visible', 'important');\n"
                + "        if (cs.opacity === '0') node.style.setProperty('opacity', '1', 'important');\n"
                + "        if (cs.pointerEvents === 'none') node.style.setProperty('pointer-events', 'auto', 'important');\n"
                + "        node.style.filter = '';\n"
                + "        node.style.maxHeight = '';\n"
                + "        node.style.overflow = 'visible';\n"
                + "      }\n"
                + "      if ('disabled' in node) node.disabled = false;\n"
                + "      node.removeAttribute && node.removeAttribute('disabled');\n"
                + "      node.removeAttribute && node.removeAttribute('aria-disabled');\n"
                + "      if (node.classList) {\n"
                + "        // Match disabled/hidden *state* classes by pattern rather than a curated list of exact\n"
                + "        // names, so this works across CSS frameworks (PatternFly, Bootstrap, Ant Design,\n"
                + "        // Material UI, Bulma, Foundation, Tailwind, hand-rolled conventions, etc.) instead of\n"
                + "        // only the handful of class names seen in any one app.\n"
                + "        [...node.classList].forEach(cls => {\n"
                + "          if (/(^|[-_])(disabled|hidden|hide|invisible)([-_]|$)/i.test(cls) || /^d-none$/i.test(cls)) node.classList.remove(cls);\n"
                + "        });\n"
                + "      }\n"
                + "      node = node.parentElement;\n"
                + "    }\n"
                + "    el.scrollIntoView({block:'center'});\n"
                + "    el.focus && el.focus({preventScroll:true});\n"
                + "    el.style.outline = '3px solid #fa8c16';\n"
                + "  };\n"
                + "  matches.forEach(revealOne);\n"
                + "  matches.forEach((el, i) => console.log('[ClientSideEye] revealed match', i, el));\n"
                + "  if (!matches.length) return console.log('[ClientSideEye] reveal target not found. Try the deep-locate hint first.');\n"
                + "  if (matches[0] && typeof inspect === 'function') inspect(matches[0]);\n"
                + "  return matches;\n"
                + "})()";
    }

    static String extractInnerText(String evidence) {
        if (evidence == null || evidence.isBlank()) return "";
        String s = evidence.replaceAll("(?is)<[^>]+>", " ").replaceAll("\\s+", " ").trim();
        if (s.length() > 80) s = s.substring(0, 80);
        return s;
    }

    static String jsSingleQuoteEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("'", "\\'");
    }

    static String jsDoubleQuoteEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    static String cssEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
