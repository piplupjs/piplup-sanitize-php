<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Sanitize;

use Piplup\Sanitize\Core\Encoding;
use Piplup\Sanitize\Core\Normalization;

/**
 * Text field sanitization — mirrors the WordPress sanitize_text_field() family.
 *
 * SANITIZE vs ESCAPE — WHEN TO USE WHICH
 * ─────────────────────────────────────────
 * • SANITIZE (this class) — clean data on the way *in* (form submission,
 *   API payload, database read).  Makes the data safe to store.
 * • ESCAPE (HtmlEscaper, JsEscaper) — encode data on the way *out* just
 *   before rendering.  Makes already-stored data safe to display.
 *
 * Do both: sanitize on input AND escape on output.  They serve different
 * threat models and doing only one leaves you partially exposed.
 *
 * DESIGN RULES
 * ─────────────
 * • All methods are pure (stateless, no side-effects).
 * • Input may be any byte string; output is always valid UTF-8.
 * • Nothing is HTML-encoded here — encoding is the escaper's job.
 */
final class TextSanitizer
{
    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Sanitize a single-line text input field.
     *
     * This is the most commonly needed sanitizer.  Use it for any text input
     * that should produce a single clean line of plain text: names, titles,
     * search queries, usernames, etc.
     *
     * WHAT THIS METHOD DOES (in order):
     *   1. Ensures valid UTF-8                  — see Encoding::toUtf8()
     *   2. Strips null bytes                    — prevents path-traversal tricks
     *   3. Strips ASCII control characters      — removes invisible garbage
     *   4. Strips all HTML and PHP tags         — <b>Hello</b> → Hello
     *   5. Collapses whitespace to single space — "foo   bar" → "foo bar"
     *   6. Trims leading/trailing whitespace
     *
     * WHAT THIS METHOD DOES NOT DO:
     *   • Does NOT HTML-encode special characters — use HtmlEscaper for output
     *   • Does NOT validate format (email, URL, etc.) — use dedicated sanitizers
     *   • Does NOT truncate length — enforce length limits separately
     *
     * WHY strip_tags() IS SUFFICIENT HERE
     * ─────────────────────────────────────
     * We are not trying to produce safe HTML output — we are trying to produce
     * plain text with all markup removed.  strip_tags() is perfect for this
     * purpose.  (For HTML-in → safe-HTML-out filtering, see Kses::filter().)
     *
    * Equivalent to WordPress sanitize_text_field().
    *
    * @param string $value Input string to sanitize.
    * @return string Sanitized single-line UTF-8 string.
    */
    public static function sanitizeTextField(string $value): string
    {
        // Step 1: ensure valid UTF-8 so all subsequent regex calls are safe.
        $value = Encoding::toUtf8($value);

        // Step 2: remove null bytes (\x00) — they can bypass C-level string
        // functions and hide malicious path components.
        $value = Encoding::stripNullBytes($value);

        // Step 3: remove non-printable control characters (but preserve \t, \n, \r).
        $value = Encoding::stripControlCharacters($value);

        // Step 4: strip all HTML and PHP tags.
        // strip_tags() removes everything between < and > including attributes.
        // Any remaining angle brackets are literal characters, not tags.
        $value = strip_tags($value);

        // Step 5 & 6: collapse multiple spaces/tabs into one, then trim ends.
        // Uses Unicode-aware \h pattern so non-breaking spaces are also collapsed.
        $value = Normalization::collapseWhitespace($value);

        return $value;
    }

    /**
     * Sanitize a multi-line textarea field.
     *
     * Like sanitizeTextField() but preserves intentional newlines.
     * Handles the CRLF vs LF vs CR difference so stored data is always
     * consistent regardless of the client operating system.
     *
     * WHAT THIS METHOD DOES (in addition to sanitizeTextField logic):
     *   • Normalizes \r\n and \r line endings to \n
     *   • Collapses whitespace on each line independently
     *     (so "foo   bar\n  baz  " → "foo bar\nbaz")
     *   • Preserves blank lines between paragraphs
     *
     * USE CASE: blog post body, comment text, bio, address, multi-line notes.
     *
    * Equivalent to WordPress sanitize_textarea_field().
    *
    * @param string $value Raw textarea input.
    * @return string Normalized UTF-8 textarea content with preserved newlines.
    */
    public static function sanitizeTextareaField(string $value): string
    {
        $value = Encoding::toUtf8($value);
        $value = Encoding::stripNullBytes($value);
        $value = Encoding::stripControlCharacters($value);

        // Strip tags before normalizing line endings.  strip_tags() itself
        // may produce runs of whitespace where tags used to be; normalizing
        // after ensures those remnants are cleaned up too.
        $value = strip_tags($value);

        // Normalize all line endings to \n so we can safely split on \n below.
        // Without this, Windows CRLF would create empty entries when splitting.
        $value = Normalization::normalizeLineEndings($value);

        // Split into individual lines and collapse whitespace on each one.
        // This gives us per-line normalization while preserving the newlines
        // themselves (i.e. we do NOT collapse multi-line content into one line).
        $lines = explode("\n", $value);
        $lines = array_map(
            static fn (string $line): string => Normalization::collapseWhitespace($line),
            $lines
        );

        // Re-join with LF.  We do NOT strip empty lines here — users may have
        // intentionally pressed Enter twice to create a paragraph break.
        return implode("\n", $lines);
    }

    /**
     * Sanitize a string for use as an array key, option name, or identifier.
     *
     * Output contains ONLY: lowercase a-z, digits 0-9, hyphens, underscores.
     * This makes the result safe as a PHP array key, a CSS class name, a
     * database column name, an HTML id attribute, or an option/setting key.
     *
     * EXAMPLES
     *   "My Setting!"  → "mysetting"
     *   "user-profile" → "user-profile"
     *   "Héllo"        → "hllo"  (non-ASCII stripped, not transliterated here)
     *
     * NOTE: This does NOT transliterate accents — it simply removes any
     * character outside [a-z0-9_-].  For slug generation with accent removal
     * use sanitizeSlug() instead.
     *
    * Equivalent to WordPress sanitize_key().
    *
    * @param string $value Raw input string.
    * @return string Identifier-safe string (lowercase, a-z0-9_-).
    */
    public static function sanitizeKey(string $value): string
    {
        // Convert to UTF-8 first, then lowercase before stripping.
        // Lowercasing before stripping means "MY-KEY" → "my-key" (kept),
        // not "MY-KEY" → "mykey" (hyphens gone if we stripped first).
        $value = Normalization::toLower(Encoding::toUtf8($value));

        // Keep only characters that are universally safe as identifiers.
        // Everything else — spaces, unicode, punctuation — is stripped entirely.
        return (string) preg_replace('/[^a-z0-9_\-]/', '', $value);
    }

    /**
     * Sanitize a string for use as a human-readable display title.
     *
     * Strips HTML tags and normalizes whitespace but preserves Unicode
     * characters such as accented letters, CJK characters, Arabic script, etc.
     * The result is suitable for display in a heading or page title.
     *
     * DIFFERENCE FROM sanitizeSlug()
     * ─────────────────────────────────
     * sanitizeTitle() → preserves Unicode, good for H1 tags and display names
     * sanitizeSlug()  → ASCII only, good for URL path segments
     *
     * Example:
     *   sanitizeTitle('<h1>Héllo & World</h1>') → "Héllo & World"
     *   sanitizeSlug('<h1>Héllo & World</h1>')  → "hello-world"
     *
    * Equivalent to WordPress sanitize_title() in display context.
    *
    * @param string $value Raw input string.
    * @return string Clean display title suitable for headings.
    */
    public static function sanitizeTitle(string $value): string
    {
        $value = Encoding::toUtf8($value);
        $value = Encoding::stripNullBytes($value);

        // Remove HTML/PHP tags.  We want plain text, not formatted content.
        $value = strip_tags($value);

        // Decode HTML entities so that "&amp;" becomes "&" in the stored title.
        // ENT_QUOTES decodes both &quot; and &#039; (single quote entity).
        // ENT_HTML5 enables HTML5 named entities (e.g. &nbsp;, &copy;).
        $value = html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Collapse whitespace created by stripped tags and trim the ends.
        $value = Normalization::collapseWhitespace($value);

        return $value;
    }

    /**
     * Sanitize a string into a URL-safe slug.
     *
     * A "slug" is the URL-path segment that identifies a resource:
     *   https://example.com/blog/{slug}
     *
     * Output contains ONLY: lowercase a-z, digits 0-9, hyphens.
     * Accented Latin characters are transliterated to ASCII equivalents.
     *
     * PIPELINE (in order):
     *   1. Ensure valid UTF-8
     *   2. Strip HTML tags
     *   3. Decode HTML entities
     *   4. Transliterate accents: é → e, ü → u, ß → ss, etc.
     *   5. Lowercase
     *   6. Replace whitespace and underscores with hyphens
     *   7. Strip any remaining non-slug characters
     *   8. Collapse consecutive hyphens: "foo---bar" → "foo-bar"
     *   9. Trim leading/trailing hyphens
     *
     * EXAMPLES
     *   "Hello World"     → "hello-world"
     *   "Héllo Wörld"     → "hello-world"
     *   "<b>My Post</b>"  → "my-post"
     *   "foo___bar"       → "foo-bar"
     *   "--my slug--"     → "my-slug"
     *
    * Equivalent to WordPress sanitize_title() in "save" / slug context.
    *
    * @param string $value Raw input string.
    * @return string URL-safe ASCII slug.
    */
    public static function sanitizeSlug(string $value): string
    {
        $value = Encoding::toUtf8($value);

        // Strip tags before decoding entities to avoid decoding tag attributes
        // into text that then needs stripping again.
        $value = strip_tags($value);

        // Decode HTML entities (&amp; → &, &eacute; → é) before transliteration.
        // Without this, "&eacute;" would become "eacute" in the slug, not "e".
        $value = html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Replace accented and special Latin characters with ASCII equivalents.
        // Uses a hand-rolled map (see below).  For broader Unicode coverage,
        // StringUtils::removeAccents() uses the intl extension if available.
        $value = self::removeAccentsBasic($value);

        // Lowercase after accent removal so we get "e" not "E" from "É".
        $value = Normalization::toLower($value);

        // Replace whitespace and underscores with hyphens.
        // Underscores are also converted because URL conventions prefer hyphens
        // and Google recommends hyphens over underscores as word separators.
        $value = (string) preg_replace('/[\s_]+/', '-', $value);

        // Strip any character that is not a-z, 0-9, or hyphen.
        // Anything non-ASCII that survived accent removal is dropped here.
        $value = (string) preg_replace('/[^a-z0-9\-]/', '', $value);

        // Collapse consecutive hyphens that resulted from stripped characters.
        // e.g. "foo & bar" → "foo--bar" after stripping "&" → "foo-bar"
        $value = (string) preg_replace('/-{2,}/', '-', $value);

        // Remove leading and trailing hyphens that look bad in URLs.
        return trim($value, '-');
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /**
     * Replace the most common accented Latin characters with ASCII equivalents.
     *
     * WHY A HAND-ROLLED MAP INSTEAD OF intl/iconv?
     * ──────────────────────────────────────────────
     * This method is intentionally minimal and has zero external dependencies.
     * It covers the Latin-1 Supplement block (the characters most likely to
     * appear in Western European text) without requiring ext-intl.
     *
     * For broader Unicode transliteration (CJK, Greek, Cyrillic, Arabic, …)
     * use StringUtils::removeAccents() which leverages the Transliterator
     * class from ext-intl when available.
     *
     * The map is applied with strtr() because strtr() handles multi-character
     * replacements correctly and is faster than preg_replace() for fixed
     * character substitution at this scale.
     *
     * @param string $value Input string (should be valid UTF-8).
     * @return string       Input with accented Latin chars replaced by ASCII.
     */
    private static function removeAccentsBasic(string $value): string
    {
        // Keys: accented characters (UTF-8 encoded in this source file).
        // Values: ASCII replacement strings.
        // Notable entries:
        //   ß → ss  (German sharp-s, correctly expands to two letters)
        //   Æ → AE  (ligature)
        //   Þ → TH  (Icelandic thorn)
        //   Ð → DH  (Icelandic eth)
        $map = [
            'À'=>'A','Á'=>'A','Â'=>'A','Ã'=>'A','Ä'=>'A','Å'=>'A','à'=>'a',
            'á'=>'a','â'=>'a','ã'=>'a','ä'=>'a','å'=>'a','È'=>'E','É'=>'E',
            'Ê'=>'E','Ë'=>'E','è'=>'e','é'=>'e','ê'=>'e','ë'=>'e','Ì'=>'I',
            'Í'=>'I','Î'=>'I','Ï'=>'I','ì'=>'i','í'=>'i','î'=>'i','ï'=>'i',
            'Ò'=>'O','Ó'=>'O','Ô'=>'O','Õ'=>'O','Ö'=>'O','Ø'=>'O','ò'=>'o',
            'ó'=>'o','ô'=>'o','õ'=>'o','ö'=>'o','ø'=>'o','Ù'=>'U','Ú'=>'U',
            'Û'=>'U','Ü'=>'U','ù'=>'u','ú'=>'u','û'=>'u','ü'=>'u','Ý'=>'Y',
            'ý'=>'y','ÿ'=>'y','Ñ'=>'N','ñ'=>'n','Ç'=>'C','ç'=>'c','ß'=>'ss',
            'Æ'=>'AE','æ'=>'ae','Þ'=>'TH','þ'=>'th','Ð'=>'DH','ð'=>'dh',
        ];

        return strtr($value, $map);
    }
}
