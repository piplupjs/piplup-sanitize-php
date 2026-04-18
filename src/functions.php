<?php

declare(strict_types=1);

/**
 * Optional WordPress-compatible global helper functions.
 *
 * WHY THESE FUNCTIONS EXIST
 * ──────────────────────────
 * The class-based API (TextSanitizer::sanitizeTextField(), etc.) is the
 * recommended approach for new code.  These global functions exist for:
 *
 *   1. MIGRATION EASE: codebases currently using WordPress functions like
 *      sanitize_text_field() or esc_html() can adopt this library by adding
 *      it as a Composer dependency — no search-and-replace required.
 *
 *   2. ERGONOMICS: some developers prefer function syntax for simple one-liners
 *      in template files.
 *
 * HOW THEY ARE LOADED
 * ─────────────────────
 * Composer autoloads this file unconditionally via the "files" key in
 * composer.json.  Every function is guarded with function_exists() so that:
 *   a) Loading this library alongside WordPress does NOT conflict.
 *   b) Loading this file twice (edge case) does not cause "function already
 *      declared" fatal errors.
 *
 * HOW TO DISABLE GLOBAL FUNCTIONS
 * ─────────────────────────────────
 * If you prefer not to pollute the global namespace, remove the "files" entry
 * from the autoload section of composer.json:
 *
 *   "autoload": {
 *     "psr-4": { "Piplup\\Sanitize\\": "src/" }
 *     // remove: "files": ["src/functions.php"]
 *   }
 *
 * Then use the classes directly — the functionality is identical.
 *
 * IMPORTANT: These functions are THIN PROXIES only.
 * All logic lives in the corresponding class.  Do not add logic here.
 */

use Piplup\Sanitize\Escape\HtmlEscaper;
use Piplup\Sanitize\Escape\JsEscaper;
use Piplup\Sanitize\Kses\AllowedHtml;
use Piplup\Sanitize\Kses\Kses;
use Piplup\Sanitize\Sanitize\EmailSanitizer;
use Piplup\Sanitize\Sanitize\FileSanitizer;
use Piplup\Sanitize\Sanitize\TextSanitizer;
use Piplup\Sanitize\Sanitize\UrlSanitizer;
use Piplup\Sanitize\Utils\NumberUtils;
use Piplup\Sanitize\Utils\StringUtils;

// =============================================================================
// Sanitize functions
// Correspond to WordPress sanitize_*() family.
// Use on INPUT: when receiving data from forms, APIs, databases.
// =============================================================================

if (!function_exists('sanitize_text_field')) {
    /**
     * Sanitize a single-line text input field.
     * Strips tags, null bytes, control chars; collapses whitespace.
     *
     * @param string $value Raw input string.
     * @return string Cleaned single-line UTF-8 string.
     * @see TextSanitizer::sanitizeTextField()
     */
    function sanitize_text_field(string $value): string
    {
        return TextSanitizer::sanitizeTextField($value);
    }
}

if (!function_exists('sanitize_textarea_field')) {
    /**
     * Sanitize a multi-line textarea field.
     * Like sanitize_text_field() but preserves newlines (normalized to \n).
     *
     * @param string $value Raw textarea input.
     * @return string Normalized UTF-8 textarea content.
     * @see TextSanitizer::sanitizeTextareaField()
     */
    function sanitize_textarea_field(string $value): string
    {
        return TextSanitizer::sanitizeTextareaField($value);
    }
}

if (!function_exists('sanitize_key')) {
    /**
     * Sanitize a string for use as an array key, option name, or identifier.
     * Output: lowercase a-z, 0-9, hyphens, underscores only.
     *
     * @param string $value Raw input string.
     * @return string Safe identifier string.
     * @see TextSanitizer::sanitizeKey()
     */
    function sanitize_key(string $value): string
    {
        return TextSanitizer::sanitizeKey($value);
    }
}

if (!function_exists('sanitize_title')) {
    /**
     * Sanitize a string for use as a human-readable display title.
     * Strips tags; preserves Unicode (accents, CJK, etc.); normalizes whitespace.
     *
     * @param string $value Raw input string.
     * @return string Clean display title.
     * @see TextSanitizer::sanitizeTitle()
     */
    function sanitize_title(string $value): string
    {
        return TextSanitizer::sanitizeTitle($value);
    }
}

if (!function_exists('sanitize_title_with_dashes')) {
    /**
     * Sanitize a string into a URL-safe slug (ASCII, lowercase, hyphens).
     * Equivalent to WordPress sanitize_title() in "save" context.
     *
     * @param string $value Raw input string.
     * @return string URL-safe slug.
     * @see TextSanitizer::sanitizeSlug()
     */
    function sanitize_title_with_dashes(string $value): string
    {
        return TextSanitizer::sanitizeSlug($value);
    }
}

if (!function_exists('sanitize_email')) {
    /**
     * Sanitize an email address: lowercase, strip invalid chars, validate format.
     * Returns empty string if the result is not a structurally valid email.
     *
     * @param string $email Raw email address.
     * @return string Sanitized email or empty string if invalid.
     * @see EmailSanitizer::sanitizeEmail()
     */
    function sanitize_email(string $email): string
    {
        return EmailSanitizer::sanitizeEmail($email);
    }
}

if (!function_exists('sanitize_file_name')) {
    /**
     * Sanitize a file name for safe use on disk (NOT a full path).
     * Handles path traversal, null bytes, Windows reserved names, forbidden chars.
     *
     * @param string $filename Raw file name.
     * @return string Sanitized file name safe for storage.
     * @see FileSanitizer::sanitizeFileName()
     */
    function sanitize_file_name(string $filename): string
    {
        return FileSanitizer::sanitizeFileName($filename);
    }
}

// =============================================================================
// Escape functions
// Correspond to WordPress esc_*() family.
// Use on OUTPUT: immediately before echoing/printing into a specific context.
// =============================================================================

if (!function_exists('esc_html')) {
    /**
     * Escape a string for safe output in HTML body content.
     * Encodes & " ' < >
     *
     * @param string $value Unescaped plain-text string.
     * @return string Escaped string safe for HTML body.
     * @see HtmlEscaper::escHtml()
     */
    function esc_html(string $value): string
    {
        return HtmlEscaper::escHtml($value);
    }
}

if (!function_exists('esc_attr')) {
    /**
     * Escape a string for safe output inside an HTML attribute value.
     * Same encoding as esc_html() but signals attribute context to code readers.
     *
     * @param string $value Unescaped string destined for an attribute.
     * @return string Escaped string safe for attribute values.
     * @see HtmlEscaper::escAttr()
     */
    function esc_attr(string $value): string
    {
        return HtmlEscaper::escAttr($value);
    }
}

if (!function_exists('esc_textarea')) {
    /**
     * Escape a string for safe output inside a <textarea> element.
     * Preserves newlines; encodes & " ' < >
     *
     * @param string $value Unescaped textarea content.
     * @return string Escaped string safe for textarea content.
     * @see HtmlEscaper::escTextarea()
     */
    function esc_textarea(string $value): string
    {
        return HtmlEscaper::escTextarea($value);
    }
}

if (!function_exists('esc_js')) {
    /**
     * Escape a string for safe embedding inside a JavaScript string literal.
     * Output is safe in both single- and double-quoted JS strings.
     * Do NOT wrap the output in quotes yourself — escJs() handles the content only.
     *
     * @param string $value Unescaped string for JS context.
     * @return string Escaped JS-safe string.
     * @see JsEscaper::escJs()
     */
    function esc_js(string $value): string
    {
        return JsEscaper::escJs($value);
    }
}

if (!function_exists('esc_url')) {
    /**
     * Sanitize and HTML-encode a URL for use in an HTML attribute (href, src, …).
     *
     * Returns '' for disallowed protocols (javascript:, data:, etc.).
     * The output is already HTML-encoded — do NOT call esc_attr() on top of it.
     *
     * @param string $url The URL to sanitize.
     * @param string[] $allowedProtocols Optional override of the default whitelist.
     * @return string HTML-encoded safe URL or empty string when disallowed.
     * @see UrlSanitizer::escUrl()
     */
    function esc_url(string $url, array $allowedProtocols = []): string
    {
        return UrlSanitizer::escUrl($url, $allowedProtocols);
    }
}

if (!function_exists('esc_url_raw')) {
    /**
     * Sanitize a URL for use OUTSIDE of HTML (redirects, curl, storage).
     * Does NOT HTML-encode the output — use esc_url() for HTML attributes.
     *
     * @param string $url The URL to sanitize.
     * @param string[] $allowedProtocols Optional override of the default whitelist.
     * @return string Sanitized URL (not HTML-encoded) or empty if disallowed.
     * @see UrlSanitizer::escUrlRaw()
     */
    function esc_url_raw(string $url, array $allowedProtocols = []): string
    {
        return UrlSanitizer::escUrlRaw($url, $allowedProtocols);
    }
}

// =============================================================================
// KSES / HTML filter functions
// Correspond to WordPress wp_kses*() family.
// Use to allow a subset of HTML tags and attributes in user-generated content.
// =============================================================================

if (!function_exists('wp_kses')) {
    /**
     * Filter HTML through a custom tag/attribute allow-list.
     *
     * @param string $html UTF-8 HTML fragment to filter.
     * @param array<string, array<string, bool>> $allowedHtml
     *        Format: ['tagname' => ['attr' => true, …], …]
     * @return string Sanitized HTML fragment.
     * @see Kses::filter()
     * @see AllowedHtml for pre-built presets
     */
    function wp_kses(string $html, array $allowedHtml): string
    {
        return Kses::filter($html, $allowedHtml);
    }
}

if (!function_exists('wp_kses_post')) {
    /**
     * Filter HTML using the "post content" preset (headings, links, images, tables, …).
     * Use for blog post bodies, article content, rich comment text.
     *
     * @param string $html HTML fragment to filter.
     * @return string Sanitized HTML (post preset).
     * @see AllowedHtml::post()
     */
    function wp_kses_post(string $html): string
    {
        return Kses::filter($html, AllowedHtml::post());
    }
}

if (!function_exists('wp_kses_data')) {
    /**
     * Filter HTML using the minimal "data" preset (inline emphasis only: <a>, <b>, …).
     * Use for short descriptions, bios, tooltip text.
     *
     * @param string $html HTML fragment to filter.
     * @return string Sanitized HTML (data preset).
     * @see AllowedHtml::data()
     */
    function wp_kses_data(string $html): string
    {
        return Kses::filter($html, AllowedHtml::data());
    }
}

// =============================================================================
// Utility functions
// Correspond to miscellaneous WordPress helper functions.
// =============================================================================

if (!function_exists('absint')) {
    /**
     * Convert any value to a non-negative integer (absolute value).
     * Equivalent to WordPress absint().
     *
     * @param mixed $value Value to convert (int|float|string|bool|null|array).
     * @return int Non-negative integer.
     * @see NumberUtils::absint()
     */
    function absint(mixed $value): int
    {
        return NumberUtils::absint($value);
    }
}

if (!function_exists('remove_accents')) {
    /**
     * Remove accent diacritics and replace them with ASCII base letters.
     * Uses ext-intl Transliterator when available; falls back to a Latin map.
     *
     * @param string $value Input string.
     * @return string ASCII-fied string with accents removed.
     * @see StringUtils::removeAccents()
     */
    function remove_accents(string $value): string
    {
        return StringUtils::removeAccents($value);
    }
}

if (!function_exists('wp_strip_all_tags')) {
    /**
     * Strip all HTML and PHP tags from a string, returning plain text.
     *
     * @param string $value Input string containing HTML.
     * @param bool $removeBreaks WordPress uses this param with inverted logic:
     *                           true  = also strip line breaks (not just tags)
     *                           false = preserve line breaks (default)
     *                           We invert it to match WordPress's behavior when
     *                           passing to stripAllTags($trimLines).
     * @return string Plain-text string with tags removed.
     * @see StringUtils::stripAllTags()
     */
    function wp_strip_all_tags(string $value, bool $removeBreaks = false): string
    {
        // WordPress: $removeBreaks=true removes line breaks → $trimLines=false
        // WordPress: $removeBreaks=false keeps line breaks  → $trimLines=true
        return StringUtils::stripAllTags($value, !$removeBreaks);
    }
}
