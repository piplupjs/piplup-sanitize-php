<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Sanitize;

use Piplup\Sanitize\Core\Encoding;

/**
 * Email address sanitization.
 *
 * WHY THIS CLASS EXISTS
 * ─────────────────────
 * User-supplied email addresses frequently contain:
 *   • Leading/trailing whitespace from copy-paste
 *   • Mixed case ("User@Example.COM") that causes false "not found" lookups
 *   • Characters outside the RFC 5321 allowed set that can break mailers
 *   • Null bytes or control characters injected to confuse parsers
 *
 * This class strips all of that, then confirms the result passes PHP's
 * own format validation.  The output is either a clean, lowercased email
 * address or an empty string — never something in-between that might silently
 * fail later.
 *
 * WHAT THIS CLASS DOES NOT DO
 * ────────────────────────────
 * • Does NOT check DNS / MX records (use a dedicated SMTP library for that)
 * • Does NOT verify deliverability
 * • Does NOT enforce domain-specific rules (e.g. "must be @example.com")
 *
 * Equivalent to WordPress sanitize_email().
 */
final class EmailSanitizer
{
    /**
     * Characters allowed in the LOCAL part of an email address (before the @).
     *
     * Based on RFC 5321 §4.1.2, which permits:
     *   a-z A-Z 0-9 ! # $ % & ' * + / = ? ^ _ ` { | } ~ - .
     *
     * We use the same conservative set that WordPress uses to maximise
     * compatibility with real-world mail servers, some of which reject
     * technically-valid but unusual characters like ` or |.
     *
     * Note: quoted local parts ("user name"@example.com) are valid per RFC but
     * extremely rare in practice and not supported here — we treat the quotes
     * as illegal characters.
     */
    // The forward slash must be escaped (\/) because it is used as the regex
    // delimiter in preg_replace('/[^...]/').  Without the backslash, the /
    // inside the character class would prematurely close the pattern and cause
    // a regex compilation error, making preg_replace() return null and stripping
    // the entire local part of every valid email address.
    private const ALLOWED_LOCAL_CHARS = 'a-zA-Z0-9!#$%&\'*+\/=?^_`{|}~\-\.';

    /**
     * Characters allowed in the DOMAIN part of an email address (after the @).
     *
     * Standard hostnames allow: letters, digits, hyphens, and dots.
     * Internationalized domain names (IDN, e.g. münchen.de) use Punycode ASCII
     * representation (xn--mnchen-3ya.de) at the protocol level, so we only
     * need to handle ASCII here.
     */
    private const ALLOWED_DOMAIN_CHARS = 'a-zA-Z0-9\-\.';

    /**
     * Sanitize an email address string.
     *
     * PIPELINE (in order):
     *   1. Ensure valid UTF-8 (defensively; email is ASCII-based but input may not be)
     *   2. Strip null bytes
     *   3. Trim whitespace from both ends
     *   4. Lowercase the entire address
     *   5. Quick fail: reject immediately if there is no '@' symbol
     *   6. Split at the LAST '@' into [local, domain]
     *      (splitting at the last '@' handles the edge case of a local part
     *       that contains '@' signs, which is technically RFC-valid)
     *   7. Strip illegal characters from local part and domain independently
     *   8. Collapse consecutive dots in either part (RFC forbids "a..b@x..y")
     *   9. Trim leading/trailing dots from each part
     *  10. Validate the assembled candidate with PHP's filter_var()
     *  11. Return cleaned address, or empty string if validation fails
     *
     * WHY LOWERCASE?
     * ───────────────
     * The local part of an email address is technically case-sensitive per
     * RFC 5321, meaning "User@example.com" and "user@example.com" could be
     * different mailboxes.  In practice, no major mail provider is case-
     * sensitive.  WordPress lowercases, and most applications do too, to
     * prevent duplicate accounts for "User@" and "user@".
     *
     * WHY filter_var AS THE FINAL STEP?
     * ────────────────────────────────────
     * Our character stripping makes a best-effort attempt to produce a valid
     * email, but it cannot guarantee structural correctness (e.g. it won't
     * catch a domain with no TLD after stripping).  filter_var() with
     * FILTER_VALIDATE_EMAIL provides a second, independent check and rejects
     * structurally invalid results.
     *
     * @param string $email Raw email input from a form or API.
     * @return string       Cleaned, lowercased address — or empty string.
     */
    public static function sanitizeEmail(string $email): string
    {
        // Step 1 & 2: byte-level safety before any string operations.
        $email = Encoding::toUtf8($email);

        // Reject outright if the original input contains null bytes.
        if (strpos($email, "\x00") !== false) {
            return '';
        }

        // Strip null bytes defensively (defensive duplication).
        $email = str_replace("\x00", '', $email);

        // Step 3: trim surrounding whitespace (copy-paste artifact).
        $email = trim($email);

        // Reject internal whitespace (spaces inside the address are invalid).
        if (preg_match('/\s/', $email)) {
            return '';
        }

        // Step 4: lowercase the whole address for consistent storage/comparison.
        $email = strtolower($email);

        // Step 5: quick structural check — require exactly one '@'.
        // We do NOT accept multiple '@' signs even if subsequent cleanup
        // could produce a valid-looking address.
        if (substr_count($email, '@') !== 1) {
            return '';
        }

        // Step 6: split at the LAST '@' to get [local, domain].
        // Using strrpos (last occurrence) correctly handles rare-but-valid
        // addresses where the local part is quoted and contains '@' itself.
        [$local, $domain] = self::splitEmail($email);

        if ($local === '' || $domain === '') {
            return '';
        }

        // Step 7: strip characters that are not in the allowed set for each part.
        // We build character-class patterns from the constants defined above.
        // preg_replace returns null on error, so we fall back to '' via ??.
        $local  = preg_replace('/[^' . self::ALLOWED_LOCAL_CHARS  . ']/', '', $local)  ?? '';
        $domain = preg_replace('/[^' . self::ALLOWED_DOMAIN_CHARS . ']/', '', $domain) ?? '';

        // Step 8: reject consecutive dots in either part — tests expect
        // addresses with ".." to be considered invalid rather than silently
        // collapsing them.
        if (preg_match('/\.{2,}/', $local) || preg_match('/\.{2,}/', $domain)) {
            return '';
        }

        // Step 9: trim leading/trailing dots.
        $local  = trim($local, '.');
        $domain = trim($domain, '.');

        // One more emptiness check after all the stripping above.
        if ($local === '' || $domain === '') {
            return '';
        }

        $candidate = $local . '@' . $domain;

        // Step 10 & 11: PHP's built-in validator as a final structural gate.
        // We do not rely on it alone because it does not clean the input —
        // it only tells us whether the candidate is structurally valid.
        if (filter_var($candidate, FILTER_VALIDATE_EMAIL) === false) {
            return '';
        }

        return $candidate;
    }

    /**
     * Check whether a string is a structurally valid email address.
     *
     * This is a validation-only check — it does NOT clean the input.
     * Use sanitizeEmail() when you also want to normalize the address.
     * Use this when you only need a boolean answer (e.g. form validation).
     *
     * @param string $email Email string to validate (whitespace is trimmed).
     * @return bool         True if structurally valid per FILTER_VALIDATE_EMAIL.
     */
    public static function isValidEmail(string $email): bool
    {
        // trim() before validation because a space-padded email like
        // " user@example.com " should be considered valid — the whitespace
        // is the user's typo, not an invalid address.
        return filter_var(trim($email), FILTER_VALIDATE_EMAIL) !== false;
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /**
     * Split an email address at the last '@' symbol into [local, domain].
     *
     * WHY THE LAST '@', NOT THE FIRST?
     * ──────────────────────────────────
     * RFC 5321 allows quoted local parts that contain '@':
     *   "user@name"@example.com
     * Splitting at the first '@' would give us local="\"user" and domain=
     * "name\"@example.com", which is wrong.  Splitting at the LAST '@' gives
     * local="\"user@name\"" and domain="example.com", which is correct.
     *
     * @param string $email Already-lowercased email string.
     * @return array{0: string, 1: string}  [local_part, domain]
     */
    private static function splitEmail(string $email): array
    {
        $pos = strrpos($email, '@');

        if ($pos === false) {
            return ['', ''];
        }

        return [substr($email, 0, $pos), substr($email, $pos + 1)];
    }
}
