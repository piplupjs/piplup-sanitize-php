<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Sanitize;

use Piplup\Sanitize\Core\Encoding;

/**
 * URL sanitization and escaping.
 *
 * THE KEY DISTINCTION: escUrl() vs escUrlRaw()
 * ─────────────────────────────────────────────
 * Both methods validate and clean the URL identically.  They differ only in
 * what they do to the output:
 *
 *   escUrl()    → HTML-encodes the result (& → &amp;, " → &quot;, etc.)
 *                 Use this when embedding the URL in an HTML attribute:
 *                   <a href="<?= UrlSanitizer::escUrl($url) ?>">
 *
 *   escUrlRaw() → Returns the cleaned URL without HTML-encoding.
 *                 Use this when the URL is NOT going into HTML:
 *                   header('Location: ' . UrlSanitizer::escUrlRaw($url));
 *                   $curl->setOption(CURLOPT_URL, UrlSanitizer::escUrlRaw($url));
 *
 * USING THE WRONG ONE IS A SECURITY BUG:
 *   • Using escUrlRaw() in an HTML attribute leaves "&" unencoded, breaking
 *     the attribute value and potentially exposing XSS vectors.
 *   • Using escUrl() in a header() call double-encodes the URL, breaking it.
 *
 * THE SANITIZE vs ESCAPE DISTINCTION FOR URLS
 * ─────────────────────────────────────────────
 * Unlike text fields, URLs are both sanitized (protocol whitelist, null byte
 * removal) AND escaped (HTML encoding) in a single step, because the two
 * concerns are always applied together for URLs.  There is no useful
 * intermediate "cleaned but not encoded URL" that you would store — you either
 * store the raw URL (use escUrlRaw for redirects) or output it (use escUrl).
 */
final class UrlSanitizer
{
    /**
     * Protocols that are permitted in URLs by default.
     *
     * WHY A WHITELIST INSTEAD OF A BLACKLIST?
     * ─────────────────────────────────────────
     * Blacklists fail when new dangerous protocols are invented or when
     * attackers find obfuscation tricks (e.g. "jAvAsCrIpT:", "java\tscript:").
     * A whitelist is robust: if the protocol is not explicitly permitted,
     * the URL is rejected outright.
     *
     * Callers can override this list per-call for specialized use cases
     * (e.g. a mailto-only context, or an app with a custom deep-link scheme).
     */
    private const DEFAULT_ALLOWED_PROTOCOLS = [
        'http', 'https', 'ftp', 'ftps', 'mailto', 'news',
        'irc', 'gopher', 'nntp', 'feed', 'telnet', 'mms',
        'rtsp', 'sms', 'svn', 'tel', 'fax', 'xmpp', 'webcal',
    ];

    /**
     * Sanitize and HTML-encode a URL for safe use in an HTML attribute.
     *
     * OUTPUT IS HTML-SAFE: the result can be placed directly inside a
     * double-quoted HTML attribute without breaking the document or enabling XSS:
     *   <a href="<?= UrlSanitizer::escUrl($url) ?>">
     *   <img src="<?= UrlSanitizer::escUrl($src) ?>">
     *
     * Returns an empty string if the URL cannot be made safe (e.g. it uses
     * the javascript: protocol).  Always check for empty string and decide
     * how to handle it in your template.
     *
     * Equivalent to WordPress esc_url().
     *
     * @param string   $url              Raw URL (may be user-supplied).
     * @param string[] $allowedProtocols Override the default protocol whitelist.
     * @return string  HTML-encoded, safe URL — or empty string.
     */
    public static function escUrl(string $url, array $allowedProtocols = []): string
    {
        // First clean the URL (strip dangerous bits, check protocol).
        $clean = self::cleanUrl($url, $allowedProtocols);

        // Then HTML-encode for safe attribute embedding.
        // ENT_QUOTES encodes both " and ' to prevent attribute breakout.
        // ENT_SUBSTITUTE replaces any remaining invalid UTF-8 with U+FFFD.
        // ENT_HTML5 encodes to HTML5 named entities where applicable.
        return htmlspecialchars($clean, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }

    /**
     * Sanitize a URL for use OUTSIDE of HTML (redirects, HTTP clients, storage).
     *
     * OUTPUT IS NOT HTML-ENCODED: the '&' in query strings is kept as '&',
     * not converted to '&amp;'.  This is correct for:
     *   • HTTP Location headers: header('Location: ' . escUrlRaw($url))
     *   • curl / Guzzle requests
     *   • Storing URLs in a database for later retrieval
     *   • Comparing URLs programmatically
     *
     * ⚠ DO NOT use this in HTML attributes — use escUrl() instead.
     *
     * Equivalent to WordPress esc_url_raw().
     */
    public static function escUrlRaw(string $url, array $allowedProtocols = []): string
    {
        // Same cleaning as escUrl, just without the final HTML encoding step.
        return self::cleanUrl($url, $allowedProtocols);
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /**
     * Core URL cleaning logic shared by escUrl() and escUrlRaw().
     *
     * CLEANING STEPS (in order):
     *   1. Ensure valid UTF-8
     *   2. Strip null bytes and ASCII control characters
     *      Control chars can confuse URL parsers and bypass protocol detection.
     *   3. Decode HTML entities
     *      An attacker might submit "javascript&#58;alert(1)" — decoding it
     *      reveals "javascript:alert(1)" so the protocol check catches it.
     *   4. Trim whitespace
     *   5. Return '' immediately if now empty
     *   6. Extract and whitelist-check the protocol/scheme
     *      If the URL has a scheme and it is not on the whitelist → reject ('').
     *      If the URL has NO scheme (relative URL like "/path/to/page") → allow.
     *   7. Percent-encode characters that are not valid unencoded in a URI
     *      This handles Unicode characters in URLs without double-encoding
     *      existing %-escapes.
     *
     * @param string   $url              Raw URL.
     * @param string[] $allowedProtocols Caller-supplied override or [].
     * @return string                    Cleaned URL (not HTML-encoded).
     */
    private static function cleanUrl(string $url, array $allowedProtocols): string
    {
        // Use the caller's list if provided; otherwise fall back to the defaults.
        $allowed = $allowedProtocols !== [] ? $allowedProtocols : self::DEFAULT_ALLOWED_PROTOCOLS;

        // Step 1: validate UTF-8 before any multi-byte or regex operations.
        $url = Encoding::toUtf8($url);

        // Step 2: decode HTML entities BEFORE stripping whitespace and
        // control characters.  Attackers may encode dangerous characters
        // (e.g. "javascript&#58;" or "javascript&#10;") — decoding first
        // ensures those obfuscations are revealed and removed by the
        // subsequent whitespace/control stripping.
        $url = html_entity_decode($url, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Step 3: Some pages leave numeric character references (e.g. "&#13;",
        // "&#x0D;") intact instead of decoding them.  To be robust against
        // obfuscation we remove numeric entities that map to ASCII control
        // characters (0x00–0x1F and 0x7F) so they cannot hide dangerous
        // separators in the URL.
        $url = (string) preg_replace_callback(
            '/&#(?:x([0-9A-Fa-f]+)|([0-9]+));/',
            static function (array $m): string {
                $val = $m[1] !== '' ? hexdec($m[1]) : intval($m[2]);
                if (($val >= 0 && $val <= 0x1F) || $val === 0x7F) {
                    return '';
                }
                return $m[0];
            },
            $url
        );

        // Now strip null bytes, control characters, AND all whitespace.
        // Control characters and whitespace are used to split protocol names
        // and bypass naive filters (e.g. "java script:").  Remove them
        // before protocol extraction.
        $url = str_replace("\x00", '', $url);
        $url = (string) preg_replace('/[\x00-\x1F\x7F]/', '', $url);  // control chars
        $url = (string) preg_replace('/\s+/u', '', $url);              // all whitespace

        // Step 4: trim surrounding whitespace.
        $url = trim($url);

        // Step 5: early exit for empty URLs.
        if ($url === '') {
            return '';
        }

        // Step 6: extract the protocol and check it against the whitelist.
        $protocol = self::extractProtocol($url);

        if ($protocol !== null) {
            // The URL has an explicit scheme (e.g. "https", "javascript").
            // Compare case-insensitively because "HTTPS:" is the same as "https:".
            if (!in_array(strtolower($protocol), $allowed, true)) {
                // Protocol not whitelisted — reject the entire URL.
                // We return '' rather than stripping the protocol, because a
                // URL with an unknown protocol is dangerous in unknown ways.
                return '';
            }
        }
        // If $protocol is null, the URL is protocol-relative (//example.com/path)
        // or path-relative (/page, ../page, page).  These are allowed.

        // Step 7: encode any characters that are not valid unencoded in a URI.
        // We leave already-encoded sequences (like %20) alone to avoid
        // double-encoding them to %2520.
        $url = self::encodeUrl($url);

        return $url;
    }

    /**
     * Extract the scheme (protocol) from a URL, or return null.
     *
     * HOW URL SCHEMES WORK (RFC 3986 §3.1)
     * ─────────────────────────────────────
     * A scheme starts at the beginning of the URL and consists of:
     *   [a-zA-Z] followed by zero or more [a-zA-Z0-9+\-.]
     * followed by a colon (:).
     *
     * Examples:
     *   "https://example.com"      → scheme = "https"
     *   "mailto:user@example.com"  → scheme = "mailto"
     *   "javascript:alert(1)"      → scheme = "javascript"  ← dangerous
     *   "//example.com/path"       → null  (protocol-relative, no scheme)
     *   "/path/to/page"            → null  (path-relative, no scheme)
     *   "page.html"                → null  (relative, no scheme)
     *
     * @param string $url URL string (already cleaned of null bytes and entities).
     * @return string|null  The scheme without the colon, or null if none found.
     */
    private static function extractProtocol(string $url): ?string
    {
        // Detect the scheme (protocol) robustly, including some common
        // obfuscation tricks attackers use to hide dangerous protocols.
        //
        // Strategy:
        // 1. Remove leading percent-encoded bytes (e.g. "%60") which
        //    some payloads use to prefix a scheme ("%60javascript:").
        // 2. Trim leading whitespace and quotation/backtick characters.
        // 3. Apply the strict RFC 3986 scheme regex against the cleaned
        //    probe string.
        $probe = $url;

        // Strip leading percent-encoded octets (e.g. %60%3A...)
        $probe = (string) preg_replace('/^(?:%[0-9A-Fa-f]{2})+/', '', $probe);

        // Strip leading whitespace and common quoting characters used
        // to obfuscate attribute delimiters.
        $probe = (string) preg_replace('/^[\s\'"`]+/', '', $probe);

        if (preg_match('#^([a-zA-Z][a-zA-Z0-9+\-.]*):#', $probe, $m)) {
            return $m[1];
        }

        return null;
    }

    /**
     * Percent-encode characters in a URL that are not valid as-is per RFC 3986.
     *
     * WHY NOT JUST USE urlencode() OR rawurlencode()?
     * ─────────────────────────────────────────────────
     * urlencode() and rawurlencode() encode the ENTIRE string, including
     * characters like ':', '/', '?', '#', '&', '=' that are structurally
     * significant in URLs.  Applying them to a full URL would destroy it.
     *
     * This method instead uses a regex callback to encode ONLY the characters
     * that must be percent-encoded:
     *   • Bytes outside the printable ASCII range (< 0x21 or > 0x7E)
     *   • Specific ASCII characters that are not valid unencoded in any URI
     *     component: space " < > [ \ ] ^ ` { | }
     *
     * This preserves:
     *   ://  ?  =  &  #  /  +  and other structural URI characters
     *
     * It also avoids double-encoding: if the URL already contains "%20", the
     * % is in the printable ASCII range (0x25) and is not re-encoded to "%2520".
     *
     * @param string $url URL with scheme and structure intact.
     * @return string     URL with unsafe characters percent-encoded.
     */
    private static function encodeUrl(string $url): string
    {
        // Match bytes outside printable ASCII, OR specific unsafe printable chars.
        // The callback applies rawurlencode() to each matched character.
        return (string) preg_replace_callback(
            '/[^\x21-\x7E]|[\s"<>\[\\\\\]^`{|}]/',
            static fn (array $m): string => rawurlencode($m[0]),
            $url
        );
    }
}
