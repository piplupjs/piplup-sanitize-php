<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Escape;

use Piplup\Sanitize\Core\Encoding;

/**
 * HTML output escaping.
 *
 * THE CORE SECURITY RULE THIS CLASS ENFORCES
 * ────────────────────────────────────────────
 * "Escape on output, sanitize on input."
 *
 * Sanitization (TextSanitizer, etc.) transforms data into a clean form for
 * STORAGE.  Escaping transforms already-stored data into a form that is safe
 * for a specific OUTPUT CONTEXT — in this case, HTML.
 *
 * You must do BOTH.  Sanitizing without escaping leaves stored data that can
 * still break HTML when rendered.  Escaping without sanitizing may pass
 * invisible garbage (null bytes, control chars) into storage.
 *
 * WHY ALL THREE METHODS (escHtml, escAttr, escTextarea) HAVE THE SAME BODY
 * ──────────────────────────────────────────────────────────────────────────
 * Technically, escaping for HTML body text, attributes, and textarea content
 * uses identical encoding rules — htmlspecialchars() with ENT_QUOTES covers
 * all three contexts safely.  The three separate methods exist for:
 *
 *   1. READABILITY: code reviewers can immediately tell what context a value
 *      is being escaped for without reading the surrounding HTML template.
 *   2. FUTURE-PROOFING: if the escaping rules for a specific context need to
 *      change (e.g. stricter attribute escaping), each method can be updated
 *      independently without touching the others.
 *   3. CONSISTENCY WITH WORDPRESS: developers migrating from WordPress code
 *      can use the same method names they already know.
 *
 * WHAT htmlspecialchars() ACTUALLY ENCODES
 * ─────────────────────────────────────────
 * With ENT_QUOTES | ENT_HTML5:
 *   &  → &amp;    prevents entity injection
 *   "  → &quot;   prevents breaking out of double-quoted attributes
 *   '  → &#039;   prevents breaking out of single-quoted attributes
 *   <  → &lt;     prevents opening new HTML tags
 *   >  → &gt;     prevents closing current tags or opening </script>
 *
 * These five characters cover 100% of HTML injection vectors in normal
 * attribute and body contexts.
 */
final class HtmlEscaper
{
    /**
     * Escape a string for safe output inside HTML body text.
     *
     * USE THIS FOR: any dynamic text placed between HTML tags:
     *   <p><?= HtmlEscaper::escHtml($userBio) ?></p>
     *   <h1><?= HtmlEscaper::escHtml($pageTitle) ?></h1>
     *   <td><?= HtmlEscaper::escHtml($tableCell) ?></td>
     *
     * DO NOT USE THIS FOR: URLs in href/src attributes — use UrlSanitizer::escUrl().
     * DO NOT USE THIS FOR: values inside <script> tags — use JsEscaper::escJs().
     *
     * WHY WE CALL toUtf8() FIRST
     * ────────────────────────────
     * htmlspecialchars() with ENT_SUBSTITUTE replaces invalid UTF-8 sequences
     * with the Unicode replacement character U+FFFD, but it does so silently.
     * Calling toUtf8() explicitly makes the repair step visible in the call
     * stack during debugging and ensures consistent behaviour across PHP versions.
     *
     * Equivalent to WordPress esc_html().
     *
     * @param string $value Unescaped plain-text string.
     * @return string       String safe for embedding in HTML body content.
     */
    public static function escHtml(string $value): string
    {
        // Ensure valid UTF-8 before passing to htmlspecialchars().
        $value = Encoding::toUtf8($value);

        // ENT_QUOTES:    encode both " → &quot; and ' → &#039;
        // ENT_SUBSTITUTE: replace invalid UTF-8 bytes with U+FFFD (not empty string)
        // 'UTF-8':       lock the character set explicitly
        //
        // NOTE: ENT_HTML5 is intentionally NOT used here.  In HTML5 mode, PHP
        // encodes single-quote as &apos; instead of &#039;.  While &apos; is
        // valid HTML5, it is not recognized by HTML4 parsers and breaks
        // test expectations that match the long-established &#039; form.
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * Escape a string for safe output inside an HTML attribute value.
     *
     * USE THIS FOR: any dynamic value placed inside an HTML attribute:
     *   <input type="text" value="<?= HtmlEscaper::escAttr($formValue) ?>">
     *   <div class="<?= HtmlEscaper::escAttr($cssClass) ?>">
     *   <button title="<?= HtmlEscaper::escAttr($tooltip) ?>">
     *
     * WHY A SEPARATE METHOD FROM escHtml()?
     * ─────────────────────────────────────
     * The encoding is identical, but the method name communicates intent to
     * the developer reading the template.  It also makes it easy to grep for
     * all attribute escaping in a codebase during a security review.
     *
     * ALWAYS wrap attribute values in quotes in your HTML templates.
     * Unquoted attributes (e.g. <div class=<?= $class ?>) are not safe even
     * with escaping, because characters like spaces would break the attribute.
     *
     * Equivalent to WordPress esc_attr().
     *
     * @param string $value Unescaped string destined for an HTML attribute.
     * @return string       String safe for embedding inside a quoted HTML attribute.
     */
    public static function escAttr(string $value): string
    {
        $value = Encoding::toUtf8($value);
        // Same flags as escHtml() — ENT_HTML5 intentionally omitted so that
        // single-quote encodes as &#039; (not &apos;) for broad compatibility.
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * Escape a string for safe output inside a <textarea> element.
     * Preserves newlines and encodes HTML-special characters.
     *
     * @param string $value Unescaped textarea content.
     * @return string Escaped string safe for textarea content.
     */
    public static function escTextarea(string $value): string
    {
        $value = Encoding::toUtf8($value);
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * Decode HTML entities into their corresponding characters.
     *
     * @param string $value Escaped string containing HTML entities.
     * @return string Decoded string.
     */
    public static function decodeEntities(string $value): string
    {
        // ENT_QUOTES: also decode &quot; and &#039;.
        // ENT_HTML5: recognize HTML5 named entities (e.g. &nbsp;, &copy;).
        return html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
}
