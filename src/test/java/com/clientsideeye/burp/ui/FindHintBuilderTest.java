package com.clientsideeye.burp.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FindHintBuilderTest {

    @Test
    void buildsSelectorHintsForId() {
        String evidence = "<button id=\"save\" disabled>Save</button>";
        FindHintBuilder.Result result = FindHintBuilder.build(evidence);

        assertEquals("[id=\"save\"]", result.bestSelector);
        assertTrue(result.hints.stream().anyMatch(h ->
                h.label().equals("Locate (high confidence: id)")));
        assertTrue(result.hints.stream().anyMatch(h ->
                h.value().contains("document.querySelectorAll('[id=\"save\"]')")));
        assertTrue(result.highlightSnippet.contains("querySelectorAll('[id=\\\"save\\\"]')")
                || result.highlightSnippet.contains("querySelectorAll('[id=\"save\"]')"));
        assertTrue(result.revealSnippet.contains("inspect(matches[0])"));
    }

    @Test
    void parsesUnquotedHrefForSelector() {
        String evidence = "<a href=/admin/delete>Delete</a>";
        FindHintBuilder.Result result = FindHintBuilder.build(evidence);

        assertEquals("a[href=\"/admin/delete\"]", result.bestSelector);
        assertTrue(result.hints.stream().anyMatch(h ->
                h.label().equals("Elements search (CSS)") && h.value().equals("a[href=\"/admin/delete\"]")));
    }

    @Test
    void buildsSelectorFromDataTestIdAndRevealCanDropDisabledState() {
        String evidence = "<button data-testid=\"localization-tab-save\" aria-disabled=\"true\" class=\"pf-v5-c-button pf-m-primary pf-m-disabled\" disabled=\"\" type=\"submit\">Save</button>";
        FindHintBuilder.Result result = FindHintBuilder.build(evidence);

        assertEquals("[data-testid=\"localization-tab-save\"]", result.bestSelector);
        assertTrue(result.hints.stream().anyMatch(h ->
                h.label().equals("Locate (high confidence: data-testid)")));
        assertTrue(result.hints.stream().anyMatch(h ->
                h.label().equals("Locate across iframes/shadow roots")));
        assertTrue(result.highlightSnippet.contains("highlighted match"));
        assertTrue(result.revealSnippet.contains("removeAttribute('aria-disabled')"));
        assertTrue(result.revealSnippet.contains("removeAttribute('disabled')"));
        assertTrue(result.revealSnippet.contains("node.classList.remove(cls)"));
    }

    @Test
    void addsTextFallbackLocatorWhenNoStableAttributesExist() {
        String evidence = "<button class=\"btn btn-danger\" disabled>Delete User</button>";
        FindHintBuilder.Result result = FindHintBuilder.build(evidence);

        assertTrue(result.hints.stream().anyMatch(h ->
                h.label().equals("Locate by text (exact)")));
        assertTrue(result.revealSnippet.contains("Delete User"));
    }

    @Test
    void hintValueForMultiLineSnippetIsNotCorruptedByLabelsContainingColonSpace() {
        // Regression test: labels like "Locate (high confidence: data-testid)" contain their own
        // ": " sequence. Copying a hint must use the structured value field directly rather than
        // string-splitting the display text on the first ": ", which previously picked the wrong
        // split point and corrupted the copied JS snippet (producing a paste-time SyntaxError).
        String evidence = "<button id=\"delete-owner\" data-testid=\"delete-owner\" disabled>Delete Owner Account</button>";
        FindHintBuilder.Result result = FindHintBuilder.build(evidence);

        FindHintBuilder.HintEntry dataTestIdHint = result.hints.stream()
                .filter(h -> h.label().equals("Locate (high confidence: data-testid)"))
                .findFirst()
                .orElseThrow();

        // The value must be the actual runnable snippet, not leftover label fragments.
        assertTrue(dataTestIdHint.value().startsWith("(() => {"));
        assertFalse(dataTestIdHint.value().contains("data-testid):"));
    }

    @Test
    void displayTextNeverInlinesMultiLineSnippets() {
        String evidence = "<button id=\"save\" disabled>Save</button>";
        FindHintBuilder.Result result = FindHintBuilder.build(evidence);

        FindHintBuilder.HintEntry idHint = result.hints.stream()
                .filter(h -> h.label().equals("Locate (high confidence: id)"))
                .findFirst()
                .orElseThrow();

        assertTrue(idHint.value().contains("\n"));
        assertEquals("Locate (high confidence: id)", idHint.displayText());
        assertFalse(idHint.displayText().contains("\n"));
    }

    @Test
    void displayTextInlinesShortSingleLineValues() {
        String evidence = "<a href=\"/admin/delete\">Delete</a>";
        FindHintBuilder.Result result = FindHintBuilder.build(evidence);

        FindHintBuilder.HintEntry cssHint = result.hints.stream()
                .filter(h -> h.label().equals("Elements search (CSS)"))
                .findFirst()
                .orElseThrow();

        assertEquals("Elements search (CSS): a[href=\"/admin/delete\"]", cssHint.displayText());
    }

    @Test
    void highlightSnippetRevealsHiddenAncestorsSoTheOutlineIsActuallyVisible() {
        // Regression test: a matched element can be invisible purely because an *ancestor*
        // container has the `hidden` attribute (or display:none/visibility:hidden) - exactly the
        // "hidden admin panel" pattern this tool exists to flag. Applying an outline directly to
        // the target element achieves nothing visible if its ancestor subtree isn't rendered at
        // all, so the highlight snippet must also temporarily unhide ancestors and revert that
        // afterwards - unlike Reveal, it must never touch the target's own disabled/hidden state.
        String evidence = "<button id=\"delete-owner\" data-testid=\"delete-owner\" disabled>Delete Owner Account</button>";
        FindHintBuilder.Result result = FindHintBuilder.build(evidence);

        assertTrue(result.highlightSnippet.contains("revealAncestors"));
        assertTrue(result.highlightSnippet.contains("hasAttribute('hidden')"));
        assertTrue(result.highlightSnippet.contains("removeAttribute('hidden')"));
        // Must restore the ancestor's original hidden state after the outline is cleared.
        assertTrue(result.highlightSnippet.contains("r.node.setAttribute('hidden', '')"));
    }

    @Test
    void revealSnippetUnmasksPasswordInputsSoPlaintextValueIsVisible() {
        // Regression test: "Reveal" previously only cleared hidden/disabled state on the target
        // and its ancestors, which does nothing for a <input type="password"> whose value is
        // masked purely by the input's `type`. Reveal must flip password inputs to type="text"
        // (in addition to unhiding/enabling them) so the plaintext value becomes visible for
        // client-side-trust testing.
        String evidence = "<input id=\"admin-password\" type=\"password\" value=\"s3cr3t\" hidden>";
        FindHintBuilder.Result result = FindHintBuilder.build(evidence);

        assertTrue(result.revealSnippet.contains("node.type === 'password'"));
        assertTrue(result.revealSnippet.contains("node.type = 'text'"));
    }

    @Test
    void revealSnippetStripsDisabledOrHiddenStateClassesFromAnyCssFrameworkNotJustACuratedList() {
        // Regression test: Reveal previously only removed a small curated list of exact class
        // names ('pf-m-disabled', 'is-disabled', 'btn-disabled', 'disabled', 'hidden', 'd-none')
        // that happened to match the tool's own test lab app, so it would silently do nothing for
        // other frameworks/naming conventions in the wild (e.g. Ant Design's 'ant-btn-disabled',
        // Material UI's 'Mui-disabled', Bulma's 'is-hidden'). To work across the *majority* of
        // real-world apps rather than one specific app, class removal must be pattern-based
        // rather than an exact-name list.
        String evidence = "<button id=\"save\" disabled>Save</button>";
        FindHintBuilder.Result result = FindHintBuilder.build(evidence);

        assertTrue(result.revealSnippet.contains("[...node.classList].forEach(cls =>"));
        assertTrue(result.revealSnippet.contains("disabled|hidden|hide|invisible"));
        assertTrue(result.revealSnippet.contains("d-none"));
        assertFalse(result.revealSnippet.contains("'pf-m-disabled'"),
                "must not hardcode class names from any single tested application");
    }

    @Test
    void revealAndHighlightSnippetsOverrideStylesWithImportantSoTheyBeatImportantUtilityClasses() {
        // Regression test: many real-world CSS frameworks hide/disable elements using
        // `!important` utility classes (e.g. Bootstrap's `.d-none { display: none !important; }`
        // and `.invisible { visibility: hidden !important; }`). A plain, non-important inline
        // style assignment (`el.style.display = 'revert'`) loses to an `!important` author rule
        // in the CSS cascade, so the override silently does nothing on any site using them. Both
        // snippets must apply overrides with '!important' priority via setProperty(...) so they
        // actually win regardless of which framework produced the hiding/disabling CSS.
        String evidence = "<button id=\"save\" disabled>Save</button>";
        FindHintBuilder.Result result = FindHintBuilder.build(evidence);

        assertTrue(result.revealSnippet.contains("setProperty('display', 'revert', 'important')"));
        assertTrue(result.revealSnippet.contains("setProperty('visibility', 'visible', 'important')"));
        assertTrue(result.revealSnippet.contains("setProperty('opacity', '1', 'important')"));
        assertTrue(result.revealSnippet.contains("setProperty('pointer-events', 'auto', 'important')"));

        assertTrue(result.highlightSnippet.contains("setProperty('display', 'revert', 'important')"));
        assertTrue(result.highlightSnippet.contains("setProperty('visibility', 'visible', 'important')"));
        assertTrue(result.highlightSnippet.contains("setProperty('opacity', '1', 'important')"));
        // Opacity hiding must be detected via computed style (covers class-driven opacity:0 too),
        // not just whatever happens to already be set inline.
        assertTrue(result.highlightSnippet.contains("cs.opacity === '0'"));
    }
}
