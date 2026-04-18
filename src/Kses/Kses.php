<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Kses;

use Piplup\Sanitize\Core\Encoding;
use Piplup\Sanitize\Sanitize\UrlSanitizer;
use Piplup\Sanitize\Sanitize\CssSanitizer;

/**
 * KSES — "KSES Strips Evil Scripts"
 *
 * Filters an HTML string, keeping only the tags and attributes that appear
 * in a caller-supplied allow-list.  Everything else is stripped.
 *
 * WHEN TO USE KSES vs WHEN TO USE TextSanitizer
 * ───────────────────────────────────────────────
 * TextSanitizer::sanitizeTextField()  → produces PLAIN TEXT (all tags removed)
 * Kses::filter()                      → produces SAFE HTML (allowed tags kept)
 *
 * Use Kses when the stored value must remain HTML — blog posts, comments,
 * rich-text editor output, etc.  Use TextSanitizer when you want plain text.
 *
 * WHAT MAKES THIS SAFE
 * ─────────────────────
 * 1. PARSING: uses DOMDocument (via HtmlParser), NOT regex.
 *    Regex-based HTML filtering is famously unreliable; malformed or
 *    adversarial markup can bypass it in dozens of documented ways.
 *    DOMDocument parses HTML the way browsers do, making bypass much harder.
 *
 * 2. TAG WHITELIST: disallowed tags are replaced with their text content.
 *    <script>alert(1)</script> → "alert(1)" (text, not code)
 *    The text is preserved so user-written content is not silently deleted.
 *
 * 3. ATTRIBUTE WHITELIST: every attribute on every allowed tag is checked.
 *    Only attributes in the allow-list survive; everything else is removed.
 *
 * 4. EVENT HANDLER BLOCK: on* attributes are ALWAYS stripped regardless of
 *    the allow-list.  Even if a caller accidentally allows onclick="…", this
 *    class removes it.
 *
 * 5. URL SANITIZATION: attributes that hold URLs (href, src, action, …) are
 *    run through UrlSanitizer::escUrlRaw(), which rejects javascript:, data:,
 *    vbscript:, and any other non-whitelisted protocol.
 *
 * Equivalent to WordPress wp_kses().
 */
final class Kses
{
    /**
     * Attributes whose values are URLs and must pass URL sanitization.
     *
     * WHY THESE SPECIFIC ATTRIBUTES?
     * ────────────────────────────────
     * Each of these attributes can cause the browser to load or navigate to
     * a URL.  If the URL is javascript: or data:text/html, the browser executes
     * arbitrary code.  UrlSanitizer::escUrlRaw() rejects those protocols.
     *
     * 'xlink:href' is included for SVG elements (e.g. <use xlink:href="…">).
     * Although we do not include SVG tags in our presets, a custom allow-list
     * might include them.
     */
    private const URL_ATTRIBUTES = [
        'action',      // <form action="…">
        'cite',        // <blockquote cite="…">, <del cite="…">
        'formaction',  // <button formaction="…"> — overrides form's action
        'href',        // <a href="…">, <area href="…">
        'poster',      // <video poster="…">  (not in presets but may be in custom lists)
        'src',         // <img src="…">, <audio src="…">, <video src="…">
        'xlink:href',  // SVG <use xlink:href="…">
        'srcset', 'data', 'ping', 'lowsrc', 'background',
    ];

    /**
     * Event-handler attributes that execute JavaScript in the browser.
     *
     * WHY BLOCK THESE UNCONDITIONALLY (OUTSIDE THE ALLOW-LIST MECHANISM)?
     * ──────────────────────────────────────────────────────────────────────
     * There is no legitimate use case for allowing user-supplied event handlers
     * in an HTML filter.  Allowing onclick="…" is equivalent to allowing
     * arbitrary JavaScript execution — it's a complete XSS bypass.
     *
     * This constant serves as a named explicit block-list and documents WHICH
     * handlers are known dangerous.  The code also has a catch-all check for
     * any attribute that starts with "on" (str_starts_with($attrLower, 'on'))
     * which covers handlers not listed here (e.g. onpointerdown, onauxclick).
     */
    private const BLOCKED_ATTRIBUTES = [
        'onabort', 'onblur', 'onchange', 'onclick', 'ondblclick', 'onerror',
        'onfocus', 'onkeydown', 'onkeypress', 'onkeyup', 'onload', 'onmousedown',
        'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onreset',
        'onresize', 'onscroll', 'onselect', 'onsubmit', 'onunload',
    ];

    /**
     * Filter an HTML string, retaining only allowed tags and attributes.
     *
     * ALGORITHM OVERVIEW:
     *   1. Return '' immediately for empty input.
     *   2. Ensure valid UTF-8.
     *   3. Normalize the allow-list keys to lowercase for case-insensitive comparison.
     *   4. Parse the HTML into a DOM tree.
     *   5. Walk every element node (deepest first — see HtmlParser::walk() docs):
     *      a. If the tag is NOT in the allow-list → replace with its children (unwrap).
     *      b. If the tag IS in the allow-list → iterate its attributes:
     *         i.  Always remove on* event handlers.
     *         ii. Remove attributes not in the allow-list for this tag.
     *         iii.For URL-bearing attributes: run through UrlSanitizer; remove if empty.
     *   6. Serialize the DOM back to an HTML string.
     *
     * @param string                            $html    Potentially unsafe HTML.
     * @param array<string, array<string,bool>> $allowed Tag → attributes allow-list.
     *                                                   See AllowedHtml for format.
     * @return string                                    Sanitized HTML fragment.
     */
    public static function filter(string $html, array $allowed): string
    {
        // Short-circuit: nothing to do for empty input.
        if ($html === '') {
            return '';
        }

        $html = Encoding::toUtf8($html);

        // Normalize all tag/attribute names in the allow-list to lowercase.
        // HTML tag and attribute names are case-insensitive, but array key
        // lookups are case-sensitive in PHP.  This step ensures that a user
        // submitting <SCRIPT> matches the same path as <script>.
        $allowed = self::normalizeAllowedList($allowed);

        // Parse the HTML fragment into a DOM tree.  libxml handles malformed
        // markup by recovering gracefully (same strategy as browsers).
        $doc = HtmlParser::parse($html);

        // Walk every element node in the tree (deepest first) and apply the
        // allow-list policy.  The closure captures $allowed and $doc by reference
        // so it can modify the tree (remove attributes, unwrap nodes).
        HtmlParser::walk($doc, function (\DOMElement $node) use ($allowed, $doc): void {
            $tagName = strtolower($node->tagName);

            // ── Step 5a: disallowed tag → unwrap (replace with its children) ─
            if (!isset($allowed[$tagName])) {
                // Some tags must have their entire content removed (scripts,
                // styles, iframes, embeds, etc.).  Removing children for
                // those tags would leave executable payloads as text.
                $stripContent = ['script', 'style', 'iframe', 'object', 'embed', 'meta', 'noscript'];

                if (in_array($tagName, $stripContent, true)) {
                    $parent = $node->parentNode;
                    if ($parent !== null) {
                        $parent->removeChild($node);
                    }
                    return;
                }

                // For ordinary tags we "unwrap" the element and keep children.
                self::replaceWithChildren($node, $doc);
                return;  // No further processing for this (now-removed) node.
            }

            // ── Step 5b: allowed tag → check each attribute ───────────────────
            $allowedAttrs = $allowed[$tagName];

            // DOMNamedNodeMap is LIVE — removing an attribute while iterating
            // over it causes the map to shift and we'd skip or double-visit
            // items.  We snapshot the attribute names into a plain PHP array first.
            $attrNames = [];
            foreach ($node->attributes as $attr) {
                $attrNames[] = $attr->name;
            }

            foreach ($attrNames as $attrName) {
                $attrLower = strtolower($attrName);

                // ── Step 5b-i: unconditionally block known event handlers ─────
                // Check both the explicit block-list AND the general "on" prefix.
                // The general prefix check catches newer event types not in our list
                // (e.g. onpointerdown, onanimationend, onvisibilitychange).
                if (in_array($attrLower, self::BLOCKED_ATTRIBUTES, true)
                    || str_starts_with($attrLower, 'on')
                ) {
                    $node->removeAttribute($attrName);
                    continue;
                }

                // ── Step 5b-ii: remove attributes not on the allow-list ───────
                // $allowedAttrs['*'] would allow all attributes on this tag —
                // useful for custom elements, but none of our presets use it.
                if (!isset($allowedAttrs[$attrLower]) && !isset($allowedAttrs['*'])) {
                    $node->removeAttribute($attrName);
                    continue;
                }

                // ── Step 5b-iii-a: sanitize `style` attribute values via CssSanitizer ─
                // Delegate complex CSS validation to a dedicated sanitizer that
                // parses declarations and validates url(...) tokens.
                if ($attrLower === 'style') {
                    $raw = $node->getAttribute($attrName);
                    $cleanCss = CssSanitizer::sanitize($raw);

                    if ($cleanCss === '') {
                        $node->removeAttribute($attrName);
                    } else {
                        $node->setAttribute($attrName, $cleanCss);
                    }

                    continue;
                }

                // ── Step 5b-iii: sanitize URL-bearing attributes ──────────────
                // Even allowed URL attributes can carry javascript: or data: URIs.
                // Pass them through UrlSanitizer; remove the attribute entirely
                // if the URL is rejected (returns '').
                // Special-case `srcset`: it's a comma-separated list of URL [descriptor]
                // tokens (e.g. "a.jpg 1x, b.jpg 2x").  Sanitize each URL and drop
                // any token whose URL is rejected.
                if ($attrLower === 'srcset') {
                    $parts = array_filter(array_map('trim', explode(',', (string) $node->getAttribute($attrName))));
                    $clean = array_filter(array_map(function(string $part) {
                        [$url, $descriptor] = array_pad(preg_split('/\s+/', $part, 2), 2, '');
                        $safeUrl = UrlSanitizer::escUrlRaw(trim($url));
                        return $safeUrl !== '' ? trim($safeUrl . ($descriptor !== '' ? ' ' . $descriptor : '')) : '';
                    }, $parts));

                    if (empty($clean)) {
                        $node->removeAttribute($attrName);
                    } else {
                        $node->setAttribute($attrName, implode(', ', $clean));
                    }

                    continue;
                }

                if (in_array($attrLower, self::URL_ATTRIBUTES, true)) {
                    $raw   = $node->getAttribute($attrName);
                    $clean = UrlSanitizer::escUrlRaw($raw);

                    if ($clean === '') {
                        // The URL was rejected (bad protocol, etc.) — remove attr.
                        $node->removeAttribute($attrName);
                    } else {
                        // Store the cleaned URL back on the attribute.
                        $node->setAttribute($attrName, $clean);
                    }
                }
                // Non-URL attributes that passed the allow-list check are left
                // unchanged.  The values will be HTML-encoded by DOMDocument
                // during serialization (e.g. " in an attribute becomes &quot;).
            }
        });

        // Serialize the sanitized DOM back to an HTML string.
        return HtmlParser::serialize($doc);
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /**
     * Replace a DOM element with its child nodes ("unwrap" the tag).
     *
     * VISUAL EXAMPLE:
     *   Before: <div>Hello <b>World</b></div>  (and <div> is disallowed)
     *   After:  Hello <b>World</b>             (div removed, children kept)
     *
     * HOW IT WORKS:
     * DOMDocument's insertBefore() moves a node from its current parent to
     * a new position.  We iterate the children and move each one to just
     * before the original node in the parent.  When all children have been
     * moved, the original node is a childless shell that we then delete.
     *
     * WHY NOT clone THE CHILDREN?
     * ────────────────────────────
     * Moving (not cloning) is correct here — we want to relocate the existing
     * nodes, not duplicate them.  Cloning would double the content.
     *
     * @param \DOMElement  $node The element being unwrapped.
     * @param \DOMDocument $doc  The owning document (used for context, not modified directly).
     */
    private static function replaceWithChildren(\DOMElement $node, \DOMDocument $doc): void
    {
        $parent = $node->parentNode;

        // Guard: if there is no parent (orphaned node), nothing to do.
        if ($parent === null) {
            return;
        }

        // Move each child node to just before $node in the parent.
        // We always access firstChild rather than iterating, because the
        // child list shrinks as we move nodes out of it.
        while ($node->firstChild !== null) {
            $parent->insertBefore($node->firstChild, $node);
        }

        // All children have been moved out.  Remove the now-empty element.
        $parent->removeChild($node);
    }

    /**
     * Normalize all tag and attribute names in the allow-list to lowercase.
     *
     * WHY: HTML tag/attribute names are case-insensitive per the spec, but
     * PHP array lookups are case-sensitive.  A user might submit "<SCRIPT>"
     * or "<Script>" — without normalization, neither would match the "script"
     * key in the allow-list.
     *
     * We normalize the ALLOW-LIST rather than the input tags because:
     *   a) This is a one-time cost at the start of filter(), not per-node.
     *   b) The per-node code already calls strtolower() on each tag name.
     *
     * @param array<string, array<string, bool>> $allowed Raw allow-list.
     * @return array<string, array<string, bool>> Allow-list with lowercase keys.
     */
    private static function normalizeAllowedList(array $allowed): array
    {
        $normalized = [];

        foreach ($allowed as $tag => $attrs) {
            $normalizedAttrs = [];
            foreach ($attrs as $attr => $permitted) {
                // Cast $attr to string defensively — callers might pass int keys.
                $normalizedAttrs[strtolower((string) $attr)] = $permitted;
            }
            $normalized[strtolower($tag)] = $normalizedAttrs;
        }

        return $normalized;
    }
}
