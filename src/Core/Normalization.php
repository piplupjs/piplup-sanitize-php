<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Core;

/**
 * String normalization routines.
 *
 * WHY THIS CLASS EXISTS
 * ─────────────────────
 * "Normalization" means transforming equivalent representations of the same
 * logical string into a single canonical form.  Without it, two strings that
 * look identical to a user may compare as unequal in code:
 *
 *   "Hello World"  (single space, LF line endings)
 *   "Hello  World" (double space, CRLF line endings)
 *
 * Normalizing before storage or comparison prevents duplicate records,
 * broken search, and inconsistent display.
 *
 * RELATIONSHIP TO Encoding.php
 * ─────────────────────────────
 * Encoding handles *byte-level* concerns (is the UTF-8 valid?).
 * Normalization handles *logical* concerns (is the whitespace consistent?).
 *
 * Always call Encoding::toUtf8() on untrusted input BEFORE calling any
 * method in this class, because the regex patterns here use the /u flag
 * which requires valid UTF-8.
 *
 * DESIGN RULES
 * ─────────────
 * • Stateless — no properties, no shared state.
 * • Pure functions — same input → same output, no side-effects.
 */
final class Normalization
{
    /**
     * Normalize line endings to Unix-style LF (\n).
     *
     * WHY NORMALIZE LINE ENDINGS?
     * ────────────────────────────
     * Three line-ending conventions exist in the wild:
     *   \r\n  — Windows (CRLF), also used in HTTP bodies and email
     *   \r    — Classic Mac OS (pre-OS X), still seen in some CSV exports
     *   \n    — Unix / Linux / macOS (LF) — our canonical form
     *
     * Storing mixed line endings causes:
     *   • Broken diffs and version control output
     *   • Double-spacing when rendered on Unix systems (\r\n renders as two lines)
     *   • Inconsistent line counts and substr_count() results
     *   • Potential filter bypass (some WAFs match on \n but not \r\n)
     *
     * ORDER MATTERS: we replace \r\n before lone \r.
     * If we replaced lone \r first, a \r\n sequence would become \n\n
     * (double newline) instead of a single \n.
     *
     * @param string $value String with potentially mixed line endings.
     * @return string       String with all line endings normalized to \n.
     */
    public static function normalizeLineEndings(string $value): string
    {
        // Step 1: \r\n (Windows) → \n.  Must come before step 2.
        // Step 2: remaining lone \r (old Mac) → \n.
        return str_replace(["\r\n", "\r"], "\n", $value);
    }

    /**
     * Collapse consecutive horizontal-whitespace characters into a single space
     * and trim leading/trailing whitespace.
     *
     * WHAT "HORIZONTAL WHITESPACE" MEANS
     * ─────────────────────────────────────
     * The \h PCRE shorthand matches any Unicode horizontal whitespace character:
     *   U+0009  HT   — ASCII tab
     *   U+0020  SP   — ASCII space
     *   U+00A0  NBSP — non-breaking space (common in copy-pasted text)
     *   U+1680  OGHAM space mark
     *   U+2000–U+200A — various typographic spaces (en space, em space, etc.)
     *   U+202F  narrow no-break space
     *   U+205F  medium mathematical space
     *   U+3000  ideographic space
     * Using \h instead of just [\t ] catches all of these in a single pass.
     *
     * WHY NOT ALSO COLLAPSE NEWLINES?
     * ─────────────────────────────────
     * This method is used by sanitizeTextField() where we want to produce a
     * single-line result without being destructive to what was intentionally
     * multi-line.  The textarea sanitizer calls normalizeLineEndings() first
     * and then collapseWhitespace() on each line individually.
     *
     * @param string $value Input string (should be valid UTF-8).
     * @return string       String with runs of horizontal whitespace collapsed
     *                      to a single space, trimmed at both ends.
     */
    public static function collapseWhitespace(string $value): string
    {
        // \h+ matches one-or-more horizontal whitespace characters (Unicode-aware).
        // The /u flag is required for \h to match non-ASCII whitespace.
        // trim() removes any leading/trailing space left after the replacement.
        return trim((string) preg_replace('/\h+/u', ' ', $value));
    }

    /**
     * Remove ALL whitespace from a string (spaces, tabs, newlines, etc.).
     *
     * USE CASES
     * ──────────
     * • Normalizing API keys, tokens, and hash values before comparison
     *   (users sometimes paste with accidental spaces)
     * • Generating compact identifiers where any whitespace is invalid
     * • Pre-processing before regex matching on tokens
     *
     * WARNING: this removes newlines too, unlike collapseWhitespace().
     * Use collapseWhitespace() when you want to preserve line structure.
     *
     * @param string $value Input string.
     * @return string       String with every whitespace character removed.
     */
    public static function removeAllWhitespace(string $value): string
    {
        // \s matches any Unicode whitespace: spaces, tabs, newlines (\n \r),
        // vertical tab, form feed, and Unicode separators.
        // The /u flag makes \s Unicode-aware (e.g. catches U+00A0 NBSP).
        return (string) preg_replace('/\s+/u', '', $value);
    }

    /**
     * Trim Unicode-aware whitespace from both ends of a string.
     *
     * WHY NOT USE PHP'S BUILT-IN trim()?
     * ─────────────────────────────────────
     * PHP's trim() only removes ASCII whitespace:
     *   space (0x20), tab (0x09), LF (0x0A), CR (0x0D), VT (0x0B), FF (0x0C)
     *
     * It does NOT remove:
     *   U+00A0 — non-breaking space (very common in copy-pasted web text)
     *   U+200B — zero-width space   (often injected by rich-text editors)
     *   U+FEFF — BOM / zero-width no-break space (common in UTF-8 BOM files)
     *   U+2000–U+200A — typographic spaces
     *
     * This method uses the PCRE \s shorthand with the /u flag, which covers
     * all Unicode separator characters.
     *
     * @param string $value Input string (should be valid UTF-8).
     * @return string       String with Unicode whitespace trimmed from both ends.
     */
    public static function trimUnicode(string $value): string
    {
        // ^\s+ matches whitespace at the start of the string.
        // \s+$ matches whitespace at the end of the string.
        // The /u flag enables Unicode-aware \s matching (covers U+00A0 NBSP, etc.)
        // We also explicitly match U+200B (zero-width space) and U+FEFF (BOM /
        // zero-width no-break space) because PCRE's \s does NOT include them
        // even in Unicode mode — they are "format" characters, not "separator"
        // characters in the Unicode category system.
        return (string) preg_replace('/^[\s\x{200B}\x{FEFF}]+|[\s\x{200B}\x{FEFF}]+$/u', '', $value);
    }

    /**
     * Convert a string to lowercase using multibyte-aware Unicode rules.
     *
     * WHY NOT USE strtolower()?
     * ──────────────────────────
     * PHP's strtolower() only handles the ASCII range A–Z → a–z.
     * It leaves accented or non-Latin uppercase characters unchanged:
     *   strtolower('ÜBER')  → 'ÜBER'   (Ü not lowercased)
     *   mb_strtolower('ÜBER') → 'über' (correct)
     *
     * Use this method any time the input might contain non-ASCII letters.
     *
     * @param string $value Input string (should be valid UTF-8).
     * @return string       Lowercased string.
     */
    public static function toLower(string $value): string
    {
        // The second argument locks the encoding explicitly.
        return mb_strtolower($value, 'UTF-8');
    }

    /**
     * Convert a string to uppercase using multibyte-aware Unicode rules.
     *
     * Same reasoning as toLower() — mb_strtoupper() handles accented and
     * non-Latin characters correctly, while strtoupper() only handles ASCII.
     *
     * @param string $value Input string (should be valid UTF-8).
     * @return string       Uppercased string.
     */
    public static function toUpper(string $value): string
    {
        return mb_strtoupper($value, 'UTF-8');
    }

    /**
     * Apply the full "clean text" pipeline in a single call.
     *
     * This is a convenience method that chains the most commonly needed
     * operations together:
     *   1. Encoding::toUtf8()              — repair invalid byte sequences
     *   2. Encoding::stripNullBytes()      — remove \x00 (path-traversal risk)
     *   3. Encoding::stripControlCharacters() — remove invisible junk bytes
     *   4. collapseWhitespace()            — normalize whitespace, trim
     *
     * It does NOT strip HTML tags (use TextSanitizer for that) and does NOT
     * normalize line endings (intended for single-line input).
     *
     * @param string $value Untrusted input string.
     * @return string       Cleaned, UTF-8 valid, whitespace-normalized string.
     */
    public static function clean(string $value): string
    {
        // Order is important here:
        //   1. Fix encoding first, or later regex operations may behave wrongly.
        //   2. Strip null bytes before collapsing whitespace (null bytes are
        //      not whitespace, so collapseWhitespace() wouldn't remove them).
        //   3. Strip control chars before collapsing whitespace for the same reason.
        //   4. Collapse whitespace last, after all removals are done.
        $value = Encoding::toUtf8($value);
        $value = Encoding::stripNullBytes($value);
        $value = Encoding::stripControlCharacters($value);
        return self::collapseWhitespace($value);
    }
}
