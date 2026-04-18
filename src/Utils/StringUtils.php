<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Utils;

use Piplup\Sanitize\Core\Encoding;

/**
 * General-purpose string utilities.
 *
 * These methods do not fit neatly into the sanitize/escape categories —
 * they are helpers that support common operations across both pipelines.
 */
final class StringUtils
{
    /**
     * Remove accent diacritics and replace them with ASCII base letters.
     *
     * WHY THIS IS NEEDED
     * ────────────────────
     * Many applications need to:
     *   • Generate URL slugs from titles: "Héllo Wörld" → "hello-world"
     *   • Build search indexes where "café" and "cafe" should match
     *   • Sort accented names alongside unaccented ones
     *   • Normalize user input for comparison
     *
     * EXAMPLES
     *   "café"    → "cafe"
     *   "über"    → "uber"
     *   "España"  → "Espana"
     *   "Straße"  → "Strasse"   (ß expands to two characters: ss)
     *   "Ærø"     → "AEro"      (Æ expands to AE)
     *
     * TWO STRATEGIES: intl (preferred) vs fallback map
     * ──────────────────────────────────────────────────
     * Strategy 1 — intl Transliterator (when ext-intl is installed):
     *   Uses the ICU library's "Any-Latin; Latin-ASCII" transliteration rule,
     *   which covers thousands of characters: Latin, Greek, Cyrillic, Arabic,
     *   CJK (to Latin phonetics), etc.  The rule chain means:
     *     "Any-Latin"   — convert any script to Latin characters
     *     "Latin-ASCII" — strip diacritics from Latin characters
     *     "[\u0080-\u7fff] remove" — strip anything non-ASCII that remains
     *
     *   The Transliterator object is cached in a static local variable because
     *   creating it involves parsing ICU rule strings, which is relatively expensive.
     *   The static cache persists for the lifetime of the PHP request.
     *
     * Strategy 2 — hand-rolled map (fallback):
     *   Covers only the Latin-1 Supplement and Latin Extended-A Unicode blocks.
     *   This is enough for all Western European languages (English, French,
     *   German, Spanish, Portuguese, Polish, Czech, etc.) but NOT for Greek,
     *   Cyrillic, Arabic, CJK, etc.
     *
     * Equivalent to WordPress remove_accents().
     *
     * @param string $value UTF-8 string possibly containing accented characters.
     * @return string       Same string with accented characters replaced by ASCII.
     */
    public static function removeAccents(string $value): string
    {
        // Fast path: if the string contains no bytes above 0x7F, it is pure ASCII
        // and cannot contain any multi-byte characters, let alone accented ones.
        // \x80-\xff covers all non-ASCII bytes in UTF-8.
        if (!preg_match('/[\x80-\xff]/', $value)) {
            return $value;
        }

        // Ensure valid UTF-8 before passing to the transliterator or strtr().
        $value = Encoding::toUtf8($value);

        if (self::intlAvailable()) {
            return self::transliterateWithIntl($value);
        }

        return self::transliterateFallback($value);
    }

    /**
     * Strip all HTML and PHP tags from a string, returning plain text.
     *
     * WHY THIS IS SAFER THAN PHP'S strip_tags() ALONE
     * ──────────────────────────────────────────────────
     * PHP's strip_tags():
     *   ✓ Removes <tag> and </tag> delimiters
     *   ✗ Does NOT remove the CONTENT of <script> and <style> blocks
     *     "<script>alert(1)</script>" → "alert(1)"  ← JS code left as text
     *
     * This method removes <script> and <style> content first (content + tags),
     * then calls strip_tags() on the remainder, then decodes HTML entities.
     *
     * PIPELINE:
     *   1. Ensure valid UTF-8
     *   2. Regex-remove <script>…</script> and <style>…</style> blocks entirely
     *      (both the tags and their content)
     *   3. strip_tags() to remove any remaining tags
     *   4. html_entity_decode() so "&amp;" becomes "&" in the output
     *   5. Optionally: trim each line and remove blank lines
     *   6. Trim the whole result
     *
     * Equivalent to WordPress wp_strip_all_tags().
     *
     * @param string $value    Input that may contain HTML/PHP markup.
     * @param bool   $trimLines Also trim each individual line? Default true.
     * @return string          Plain text with all markup and script content removed.
     */
    public static function stripAllTags(string $value, bool $trimLines = true): string
    {
        $value = Encoding::toUtf8($value);

        // Step 2: remove <script>…</script> and <style>…</style> entirely.
        // The regex breakdown:
        //   <(script|style)  — opening tag with captured tag name
        //   [^>]*>           — any attributes, then >
        //   .*?              — content (non-greedy so it stops at the FIRST </tag>)
        //   </\1>            — closing tag matching the captured name
        //   #si flags: s = dot matches newlines (content may span multiple lines)
        //              i = case-insensitive (<SCRIPT> = <script>)
        $value = (string) preg_replace(
            '#<(script|style)[^>]*>.*?</\1>#si',
            ' ',  // replace with a space rather than '' to prevent word-merging
            $value
        );

        // Step 3: remove any remaining HTML/PHP tags.
        $value = strip_tags($value);

        // Step 4: decode HTML entities so the text is natural to read/store.
        // "&amp;" → "&", "&lt;" → "<", "&nbsp;" → " ", etc.
        $value = html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        if ($trimLines) {
            // Step 5: trim and filter each line independently.
            // This cleans up whitespace artifacts left by removed tags.
            $lines = explode("\n", $value);
            $lines = array_map('trim', $lines);

            // Remove lines that became entirely empty after trimming.
            // We preserve blank lines between real content (handled by the
            // fact that explode produces them and we check $l !== '').
            $lines = array_filter($lines, static fn (string $l): bool => $l !== '');

            $value = implode("\n", $lines);
        }

        return trim($value);
    }

    /**
     * Truncate a UTF-8 string to at most $maxChars Unicode characters.
     *
     * WHY NOT USE substr() FOR THIS?
     * ────────────────────────────────
     * substr() operates on bytes, not characters.  Truncating a UTF-8 string
     * with substr() can cut a multi-byte character in half, producing an invalid
     * byte sequence at the end.  mb_substr() operates on Unicode code points
     * and always produces valid UTF-8.
     *
     * HOW THE SUFFIX IS HANDLED
     * ──────────────────────────
     * The suffix (default '…', the Unicode ellipsis character U+2026) counts
     * toward the $maxChars limit.  This means the total visible length of the
     * truncated string never exceeds $maxChars.
     *
     * Example with $maxChars = 10, $suffix = '…' (1 char):
     *   "Hello World" (11 chars) → "Hello Wor…" (9 content chars + 1 suffix = 10 total)
     *
     * @param string $value    Input UTF-8 string.
     * @param int    $maxChars Maximum number of Unicode characters in the output.
     * @param string $suffix   Appended when truncation occurs (counts toward limit).
     * @return string          Truncated string, or original if short enough.
     */
    public static function truncate(string $value, int $maxChars, string $suffix = '…'): string
    {
        // Edge case: a zero or negative limit means "return nothing".
        if ($maxChars <= 0) {
            return '';
        }

        $len = mb_strlen($value, 'UTF-8');

        // Fast path: string is already within the limit, nothing to do.
        if ($len <= $maxChars) {
            return $value;
        }

        // Calculate how many content characters we can keep after reserving
        // space for the suffix.  max(0, …) prevents a negative targetLen when
        // the suffix itself is longer than maxChars.
        $suffixLen = mb_strlen($suffix, 'UTF-8');
        $targetLen = max(0, $maxChars - $suffixLen);

        return mb_substr($value, 0, $targetLen, 'UTF-8') . $suffix;
    }

    /**
     * Return true if $haystack starts with $needle.
     *
     * This is a thin wrapper around PHP 8.0's str_starts_with() that exists
     * for API completeness alongside endsWith() and the other string helpers.
     * It is safe for ASCII and UTF-8 strings because it compares bytes, and
     * for prefix matching that is exactly what we want.
     *
     * @param string $haystack The string to search in.
     * @param string $needle   The prefix to look for.
     * @return bool            True if $haystack begins with $needle.
     */
    public static function startsWith(string $haystack, string $needle): bool
    {
        return str_starts_with($haystack, $needle);
    }

    /**
     * Return true if $haystack ends with $needle.
     *
     * Same rationale as startsWith() — a clean named wrapper.
     *
     * @param string $haystack The string to search in.
     * @param string $needle   The suffix to look for.
     * @return bool            True if $haystack ends with $needle.
     */
    public static function endsWith(string $haystack, string $needle): bool
    {
        return str_ends_with($haystack, $needle);
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /**
     * Check whether the intl extension's Transliterator class is available.
     *
     * We check both extension_loaded() AND class_exists() because some builds
     * package intl without compiling in the full ICU data (in which case
     * Transliterator::create() might still fail at runtime).  The class_exists()
     * check is a fast proxy for "the extension is fully functional".
     */
    private static function intlAvailable(): bool
    {
        return extension_loaded('intl') && class_exists(\Transliterator::class);
    }

    /**
     * Transliterate accented characters to ASCII using ICU rules via ext-intl.
     *
     * The Transliterator is cached as a static local variable.  The first call
     * pays the cost of parsing the ICU rule string ("Any-Latin; Latin-ASCII; …").
     * Subsequent calls within the same PHP request reuse the compiled object.
     *
     * ICU RULE CHAIN EXPLAINED:
     *   "Any-Latin"             — convert any Unicode script to Latin characters
     *                             (e.g. Greek α → a, Cyrillic А → A)
     *   "Latin-ASCII"           — strip diacritics from Latin chars
     *                             (e.g. é → e, ü → u, ñ → n)
     *   "[\u0080-\u7fff] remove" — remove anything outside ASCII that remains
     *                             (catch-all for characters not handled above)
     *
     * @param string $value Valid UTF-8 string.
     * @return string       String with accented chars replaced by ASCII equivalents.
     */
    private static function transliterateWithIntl(string $value): string
    {
        /** @var \Transliterator|null $transliterator */
        static $transliterator = null;  // Cached for the lifetime of this request.

        if ($transliterator === null) {
            $transliterator = \Transliterator::create(
                'Any-Latin; Latin-ASCII; [\u0080-\u7fff] remove'
            );
        }

        // Transliterator::create() returns null on failure (bad ICU data, etc.).
        // Fall back to the map-based approach in that case.
        if ($transliterator === null) {
            return self::transliterateFallback($value);
        }

        // transliterate() returns false on failure; the ?: returns the original.
        return $transliterator->transliterate($value) ?: $value;
    }

    /**
     * Accent-removal fallback using a hand-rolled character substitution map.
     *
     * WHY A MAP INSTEAD OF iconv('UTF-8', 'ASCII//TRANSLIT')?
     * ─────────────────────────────────────────────────────────
     * iconv() behaviour for //TRANSLIT is locale-dependent — the output can
     * differ between servers depending on the system locale setting.  It also
     * falls back to '?' for unmapped characters, which is destructive and
     * would corrupt stored data.  A explicit map is predictable and portable.
     *
     * COVERAGE: Latin-1 Supplement (U+00C0–U+00FF) and Latin Extended-A
     * (U+0100–U+017F).  This covers all Western and Central European languages
     * that use Latin-script letters with diacritics.
     *
     * strtr() is used for application because it performs all substitutions
     * in a single, efficient pass — it does not re-scan already-replaced output,
     * so there is no risk of cascading substitutions.
     *
     * @param string $value Valid UTF-8 string.
     * @return string       String with covered accented chars replaced by ASCII.
     */
    private static function transliterateFallback(string $value): string
    {
        $map = [
            // ── Latin-1 Supplement ─────────────────────────────────────────────
            'À'=>'A','Á'=>'A','Â'=>'A','Ã'=>'A','Ä'=>'A','Å'=>'A',
            'à'=>'a','á'=>'a','â'=>'a','ã'=>'a','ä'=>'a','å'=>'a',
            'Æ'=>'AE','æ'=>'ae',           // AE ligature
            'Ç'=>'C','ç'=>'c',
            'È'=>'E','É'=>'E','Ê'=>'E','Ë'=>'E',
            'è'=>'e','é'=>'e','ê'=>'e','ë'=>'e',
            'Ì'=>'I','Í'=>'I','Î'=>'I','Ï'=>'I',
            'ì'=>'i','í'=>'i','î'=>'i','ï'=>'i',
            'Ð'=>'D','ð'=>'d',             // Icelandic eth
            'Ñ'=>'N','ñ'=>'n',
            'Ò'=>'O','Ó'=>'O','Ô'=>'O','Õ'=>'O','Ö'=>'O','Ø'=>'O',
            'ò'=>'o','ó'=>'o','ô'=>'o','õ'=>'o','ö'=>'o','ø'=>'o',
            'Ù'=>'U','Ú'=>'U','Û'=>'U','Ü'=>'U',
            'ù'=>'u','ú'=>'u','û'=>'u','ü'=>'u',
            'Ý'=>'Y','ý'=>'y','ÿ'=>'y',
            'Þ'=>'TH','þ'=>'th',           // Icelandic thorn
            'ß'=>'ss',                     // German sharp-s (correctly expands to two letters)

            // ── Latin Extended-A ────────────────────────────────────────────────
            'Ā'=>'A','ā'=>'a','Ă'=>'A','ă'=>'a','Ą'=>'A','ą'=>'a',
            'Ć'=>'C','ć'=>'c','Ĉ'=>'C','ĉ'=>'c','Ċ'=>'C','ċ'=>'c','Č'=>'C','č'=>'c',
            'Ď'=>'D','ď'=>'d','Đ'=>'D','đ'=>'d',
            'Ē'=>'E','ē'=>'e','Ĕ'=>'E','ĕ'=>'e','Ė'=>'E','ė'=>'e','Ę'=>'E','ę'=>'e','Ě'=>'E','ě'=>'e',
            'Ĝ'=>'G','ĝ'=>'g','Ğ'=>'G','ğ'=>'g','Ġ'=>'G','ġ'=>'g','Ģ'=>'G','ģ'=>'g',
            'Ĥ'=>'H','ĥ'=>'h','Ħ'=>'H','ħ'=>'h',
            'Ĩ'=>'I','ĩ'=>'i','Ī'=>'I','ī'=>'i','Ĭ'=>'I','ĭ'=>'i','Į'=>'I','į'=>'i','İ'=>'I','ı'=>'i',
            'IJ'=>'IJ','ij'=>'ij',         // Dutch IJ ligature
            'Ĵ'=>'J','ĵ'=>'j',
            'Ķ'=>'K','ķ'=>'k','ĸ'=>'k',
            'Ĺ'=>'L','ĺ'=>'l','Ļ'=>'L','ļ'=>'l','Ľ'=>'L','ľ'=>'l','Ŀ'=>'L','ŀ'=>'l','Ł'=>'L','ł'=>'l',
            'Ń'=>'N','ń'=>'n','Ņ'=>'N','ņ'=>'n','Ň'=>'N','ň'=>'n','ŉ'=>'n','Ŋ'=>'N','ŋ'=>'n',
            'Ō'=>'O','ō'=>'o','Ŏ'=>'O','ŏ'=>'o','Ő'=>'O','ő'=>'o','Œ'=>'OE','œ'=>'oe',
            'Ŕ'=>'R','ŕ'=>'r','Ŗ'=>'R','ŗ'=>'r','Ř'=>'R','ř'=>'r',
            'Ś'=>'S','ś'=>'s','Ŝ'=>'S','ŝ'=>'s','Ş'=>'S','ş'=>'s','Š'=>'S','š'=>'s',
            'Ţ'=>'T','ţ'=>'t','Ť'=>'T','ť'=>'t','Ŧ'=>'T','ŧ'=>'t',
            'Ũ'=>'U','ũ'=>'u','Ū'=>'U','ū'=>'u','Ŭ'=>'U','ŭ'=>'u','Ů'=>'U','ů'=>'u','Ű'=>'U','ű'=>'u','Ų'=>'U','ų'=>'u',
            'Ŵ'=>'W','ŵ'=>'w',
            'Ŷ'=>'Y','ŷ'=>'y','Ÿ'=>'Y',
            'Ź'=>'Z','ź'=>'z','Ż'=>'Z','ż'=>'z','Ž'=>'Z','ž'=>'z',
        ];

        return strtr($value, $map);
    }
}
