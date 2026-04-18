<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Core;

/**
 * Low-level UTF-8 encoding helpers.
 *
 * WHY THIS CLASS EXISTS
 * ─────────────────────
 * Every sanitizer in this library assumes its input is valid UTF-8.  But PHP
 * strings are just byte arrays — there is no built-in encoding guarantee.
 * Passing a malformed byte sequence to mb_strlen(), preg_replace('/…/u', …),
 * or htmlspecialchars() can cause silent truncation, wrong lengths, or (in
 * older PHP) even crashes.
 *
 * This class is therefore called first on untrusted input.  All other
 * classes depend on it; none of them duplicate its logic.
 *
 * DESIGN RULES
 * ─────────────
 * • Stateless — no properties, no shared state between calls.
 * • Pure functions — same input always produces the same output.
 * • Never throws — returns a safe value on any input, including empty string.
 */
final class Encoding
{
    /**
     * Ensure a string is valid UTF-8, repairing it when necessary.
     *
     * WHY WE NEED THIS
     * ─────────────────
     * User input arriving over HTTP, from databases, or read from files can
     * contain arbitrary bytes.  Functions like preg_replace('/…/u', …) return
     * null silently on invalid UTF-8, and htmlspecialchars() can produce
     * corrupt output.  Running this method first makes every downstream
     * operation predictable and safe.
     *
     * THE TWO-PASS REPAIR STRATEGY
     * ─────────────────────────────
     * Pass 1 — mb_convert_encoding('UTF-8', 'UTF-8')
     *   Telling mbstring to convert from UTF-8 *to* UTF-8 causes it to scan
     *   for invalid byte sequences and substitute the replacement character
     *   U+FFFD.  This handles the vast majority of real-world corruption.
     *
     * Pass 2 — regex strip (fallback only)
     *   In rare cases (certain mbstring builds or very malformed input) Pass 1
     *   may still leave invalid bytes.  The regex removes the byte patterns
     *   that are structurally illegal in UTF-8 per RFC 3629:
     *     [\x00-\x08\x10\x0B\x0C\x0E-\x19\x7F]  — raw C0 control chars / DEL
     *     [\x00-\x7F][\x80-\xBF]+                — ASCII byte followed by continuation bytes
     *     [\xC0\xC1]                              — overlong 2-byte sequence leaders (always invalid)
     *     [\xC2-\xDF](?![\x80-\xBF])             — incomplete 2-byte sequence
     *     [\xE0-\xEF](?![\x80-\xBF]{2})          — incomplete 3-byte sequence
     *     [\xF0-\xF7](?![\x80-\xBF]{3})          — incomplete 4-byte sequence
     *     (?<=…)[\x80-\xBF]+                      — orphaned continuation bytes
     *
     * @param string $value Raw input that may contain invalid bytes.
     * @return string       Guaranteed valid UTF-8 string.
     */
    public static function toUtf8(string $value): string
    {
        // Fast path: already valid — skip the expensive conversion entirely.
        // mb_check_encoding is faster than attempting a no-op conversion.
        if (self::isValidUtf8($value)) {
            return $value;
        }

        // Pass 1: let mbstring repair invalid sequences by re-encoding from
        // UTF-8 to UTF-8.  Invalid bytes become U+FFFD replacement characters.
        $converted = mb_convert_encoding($value, 'UTF-8', 'UTF-8');

        // Pass 2 (safety net): if Pass 1 still left invalid bytes, strip them
        // with the structural UTF-8 regex.  We apply to the *original* $value
        // rather than $converted to avoid processing artefacts from Pass 1.
        if (!self::isValidUtf8($converted)) {
            $converted = preg_replace(
                '/[\x00-\x08\x10\x0B\x0C\x0E-\x19\x7F]'   // C0 control chars and DEL
                . '|[\x00-\x7F][\x80-\xBF]+'               // ASCII byte + continuation(s)
                . '|[\xC0\xC1]'                             // overlong 2-byte sequence leaders
                . '|[\xC2-\xDF](?![\x80-\xBF])'            // truncated 2-byte sequence
                . '|[\xE0-\xEF](?![\x80-\xBF]{2})'         // truncated 3-byte sequence
                . '|[\xF0-\xF7](?![\x80-\xBF]{3})'         // truncated 4-byte sequence
                . '|(?<=[\x00-\x7F\xF8-\xFF])[\x80-\xBF]+/S', // orphaned continuation bytes
                '',
                $value
            ) ?? '';
        }

        return $converted;
    }

    /**
     * Check whether a string contains only valid UTF-8 bytes.
     *
     * WHY mb_check_encoding AND NOT preg_match('/./u')?
     * ──────────────────────────────────────────────────
     * The /u regex trick works but is slower and has edge-case differences
     * across PHP versions.  mb_check_encoding() is the purpose-built function
     * for this exact job and is consistently faster on strings longer than a
     * few dozen bytes.
     *
     * @param string $value String to inspect.
     * @return bool         True if every byte forms a valid UTF-8 sequence.
     */
    public static function isValidUtf8(string $value): bool
    {
        return mb_check_encoding($value, 'UTF-8');
    }

    /**
     * Strip null bytes (\x00) from a string.
     *
     * WHY NULL BYTES ARE A SECURITY RISK
     * ─────────────────────────────────────
     * PHP strings are binary-safe and can hold null bytes, but many underlying
     * C functions treat the first null byte as the end of the string.
     * Attackers exploit this discrepancy to bypass path checks:
     *
     *   Input:  "../../etc/passwd\x00.jpg"
     *   PHP sees the full string (passes a ".jpg extension" validation check)
     *   C filesystem call sees "../../etc/passwd" (reads the sensitive file)
     *
     * Removing null bytes early prevents this class of path-traversal attack.
     * This is also why null bytes can break MySQL queries, LDAP filters, and
     * some PCRE patterns.
     *
     * @param string $value String that may contain \x00 bytes.
     * @return string       String with every null byte removed.
     */
    public static function stripNullBytes(string $value): string
    {
        // str_replace is binary-safe and is the fastest single-char removal
        // for strings of arbitrary size.
        return str_replace("\x00", '', $value);
    }

    /**
     * Remove ASCII control characters that have no meaning in user-facing text.
     *
     * WHICH BYTES ARE REMOVED?
     * ─────────────────────────
     * The ASCII control range is 0x00–0x1F plus DEL (0x7F).  We preserve
     * three that appear legitimately in text content:
     *   0x09  HT  — horizontal tab      → kept (used in code / tables)
     *   0x0A  LF  — line feed / \n      → kept (newlines in textarea)
     *   0x0D  CR  — carriage return     → kept (normalised later to \n)
     *
     * Everything else is invisible garbage that can confuse parsers, sneak
     * through filters, or produce unexpected effects:
     *   BEL (0x07) — triggers a terminal beep in some environments
     *   ESC (0x1B) — starts ANSI/VT100 terminal control sequences
     *   BS  (0x08) — backspace, can corrupt log viewers
     *
     * NOTE: Newline normalisation (\r\n → \n) is handled separately in
     * Normalization::normalizeLineEndings() to keep responsibilities clear.
     *
     * @param string $value Input string.
     * @return string       Input with non-printable control characters removed.
     */
    public static function stripControlCharacters(string $value): string
    {
        // Pattern explanation:
        //   [\x00-\x08]  — NUL through BS   (codepoints 0–8)
        //   \x0B         — VT vertical tab  (codepoint 11)
        //   \x0C         — FF form feed     (codepoint 12)
        //   [\x0E-\x1F]  — SO through US    (codepoints 14–31)
        //   \x7F         — DEL              (codepoint 127)
        // The /S modifier asks PCRE to "study" the pattern, speeding up
        // repeated calls with the same compiled pattern.
        return (string) preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $value);
    }

    /**
     * Return the raw byte-length of a string.
     *
     * USE THIS WHEN: you care about storage size (database column limits,
     * network payload sizes, file sizes).  A MySQL VARCHAR(255) stores 255
     * bytes, not 255 characters.
     *
     * DO NOT USE THIS WHEN: you want the number of characters a user sees.
     * For that, use charLength() instead.
     *
     * Example: "café" → byteLength = 5 (é is encoded as 2 bytes in UTF-8)
     *          "café" → charLength = 4 (4 visible characters)
     *
     * @param string $value Any string (does not need to be valid UTF-8).
     * @return int          Number of bytes.
     */
    public static function byteLength(string $value): int
    {
        // strlen() counts bytes, not characters.  This is exactly what we
        // want here.  Note: in PHP 8.1+, mbstring.func_overload is gone, so
        // strlen() always counts bytes regardless of mbstring configuration.
        return strlen($value);
    }

    /**
     * Return the number of Unicode characters (code points) in a UTF-8 string.
     *
     * USE THIS WHEN: enforcing user-visible length limits, e.g. a 100-char
     * username field.  Users perceive "100 characters" in terms of what they
     * see on screen, not how many bytes their input takes.
     *
     * DO NOT USE THIS FOR: database column size checks.  Use byteLength() for
     * those (see example in byteLength() docs above).
     *
     * @param string $value Valid UTF-8 string.
     * @return int          Number of Unicode code points.
     */
    public static function charLength(string $value): int
    {
        // The second argument locks the encoding so the result is correct even
        // if the mbstring internal_encoding setting differs from UTF-8.
        return mb_strlen($value, 'UTF-8');
    }
}
