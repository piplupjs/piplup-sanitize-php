<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Escape;

use Piplup\Sanitize\Core\Encoding;

/**
 * JavaScript output escaping.
 *
 * WHEN TO USE THIS CLASS
 * ───────────────────────
 * Use these methods when you need to embed PHP values inside JavaScript code
 * that is written directly into an HTML page (inline scripts).
 *
 * NEVER embed raw user input in JavaScript — always escape it first.
 *
 * CHOOSING THE RIGHT METHOD
 * ──────────────────────────
 * escJs()      → escapes a PHP string for use INSIDE a JS string literal
 *                <script>var name = '<?= JsEscaper::escJs($name) ?>';</script>
 *
 * jsonEncode() → serializes any PHP value (string, array, object) as JSON
 *                that is safe to assign to a JS variable directly
 *                <script>var data = <?= JsEscaper::jsonEncode($data) ?>;</script>
 *
 * THE JAVASCRIPT ESCAPING PROBLEM
 * ─────────────────────────────────
 * JavaScript strings and HTML interact in a tricky way inside <script> tags.
 * The HTML parser runs BEFORE the JS parser, so the string "</script>" inside
 * a JS string literal causes the HTML parser to think the script block ended:
 *
 *   <script>
 *     var x = 'Hello </script><script>alert(1)//';
 *   </script>
 *
 * The HTML parser splits this into two script blocks and the second one
 * executes alert(1).  Both escJs() and jsonEncode() prevent this by encoding
 * '<' and '>' so that "</script>" can never appear literally.
 *
 * ⚠️  Do NOT use HtmlEscaper::escHtml() for JavaScript contexts.
 *    HTML-encoding turns ' into &#039;, which is valid HTML but is NOT valid
 *    JavaScript — the JS engine would see the literal string "&#039;", not
 *    a single quote character.
 */
final class JsEscaper
{
    /**
     * Escape a PHP string for safe embedding inside a JavaScript string literal.
     *
     * The output is safe inside BOTH single-quoted and double-quoted JS strings:
     *   var a = '<?= JsEscaper::escJs($val) ?>';   // single-quoted
     *   var b = "<?= JsEscaper::escJs($val) ?>";   // double-quoted
     *
     * CHARACTERS ESCAPED AND WHY:
     *   \  → \\       Backslash is the JS escape character itself; must be doubled.
     *   '  → \'       Closes single-quoted string literals.
     *   "  → \"       Closes double-quoted string literals.
     *   \n → \n       Unescaped newlines break JS string literals (syntax error).
     *   \r → \r       Same as \n.
     *   \t → \t       Tabs are safe in string literals but we encode for consistency.
     *   <  → \u003C   Prevents </script> tag injection (see class docblock).
     *   >  → \u003E   Same reason — needed to prevent both </ and > appearing.
     *   &  → \u0026   Prevents HTML entity sequences inside JS strings in HTML context.
     *   U+2028 → \u2028  Unicode Line Separator — treated as a literal line break
     *                    in JavaScript, causing a syntax error in a string literal.
     *   U+2029 → \u2029  Unicode Paragraph Separator — same issue as U+2028.
     *
     * HOW json_encode() IS USED AS THE HEAVY LIFTER
     * ──────────────────────────────────────────────
     * Rather than maintaining our own character-by-character escaping logic,
     * we leverage json_encode() which already handles all the tricky cases
     * correctly.  json_encode() wraps the result in double quotes; we strip
     * those outer quotes so callers can embed the result in either quote style.
     *
     * The fallbackEscapeJs() method is used if json_encode() somehow fails
     * (e.g. on a string with a very specific malformed encoding edge case).
     *
     * Equivalent to WordPress esc_js().
     *
     * @param string $value Unescaped PHP string.
     * @return string       String safe for embedding inside a JS string literal
     *                      (without surrounding quotes).
     */
    public static function escJs(string $value): string
    {
        // Validate UTF-8 first — json_encode() may behave unexpectedly on
        // malformed byte sequences, depending on the JSON_THROW_ON_ERROR flag.
        $value = Encoding::toUtf8($value);

        // JSON_HEX_TAG:  encode < and > as \u003C and \u003E
        //                Prevents </script> injection (see class docblock).
        // JSON_HEX_AMP:  encode & as \u0026
        //                Prevents &lt; sequences from being interpreted as HTML.
        // JSON_UNESCAPED_UNICODE: keep non-ASCII chars as-is (readability).
        //                         U+2028 / U+2029 ARE still escaped because
        //                         json_encode() always escapes those two.
        // JSON_HEX_TAG: encode < → \u003C and > → \u003E (prevents </script> injection)
        // JSON_HEX_AMP: encode & → \u0026 (prevents &lt; entity sequences in HTML)
        // JSON_UNESCAPED_UNICODE: keep non-ASCII chars readable
        //   Note: json_encode() always escapes U+2028 and U+2029 regardless of flags.
        $encoded = json_encode($value, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE);

        if ($encoded === false) {
            // json_encode() failed — fall back to our own manual escaping.
            return self::fallbackEscapeJs($value);
        }

        // Strip the surrounding double-quotes that json_encode() always adds.
        $result = substr($encoded, 1, -1);

        // json_encode() does NOT escape single quotes — JSON string delimiters
        // are double-quotes, so single quotes are not special in JSON.
        // But since we strip the double-quotes so callers can embed this in
        // single-quoted JS strings (var x = '...'), we must escape ' ourselves.
        return str_replace("'", "\\'", $result);
    }

    /**
     * Serialize any PHP value as HTML-safe JSON for inline <script> blocks.
     *
     * USE THIS FOR: passing PHP data (arrays, objects, numbers, booleans)
     * to JavaScript as structured data:
     *
     *   <script>
     *     var config = <?= JsEscaper::jsonEncode($phpConfig) ?>;
     *     var labels = <?= JsEscaper::jsonEncode($labelsArray) ?>;
     *   </script>
     *
     * WHY NOT JUST USE json_encode() DIRECTLY?
     * ─────────────────────────────────────────
     * Plain json_encode() does NOT escape HTML-special characters like < > & ' "
     * This means the string "foo</script>bar" would appear literally in the
     * output, causing the HTML parser to break the script block (XSS).
     *
     * This method uses JSON_HEX_* flags to Unicode-escape all four HTML-
     * special characters, making the output safe inside a <script> block
     * without any additional escaping by the template layer.
     *
     * JSON FLAGS USED AND WHY:
     *   JSON_HEX_TAG   — < → \u003C, > → \u003E  (closes </script> risk)
     *   JSON_HEX_AMP   — & → \u0026               (prevents &lt; entity in HTML)
     *   JSON_HEX_APOS  — ' → \u0027               (prevents attribute breakout)
     *   JSON_HEX_QUOT  — " → \u0022               (prevents attribute breakout)
     *   JSON_UNESCAPED_UNICODE — keep non-ASCII readable (optional but nice)
     *   JSON_THROW_ON_ERROR    — throw instead of returning false on failure
     *
     * @param mixed $value Any JSON-serialisable PHP value (string, int, float,
     *                     bool, null, array, or object with public properties).
     * @return string      HTML-safe JSON string, or the literal string 'null'
     *                     if serialization fails.
     */
    public static function jsonEncode(mixed $value): string
    {
        $flags = JSON_HEX_TAG              // < and > → Unicode escapes
               | JSON_HEX_AMP             // & → \u0026
               | JSON_HEX_APOS            // ' → \u0027
               | JSON_HEX_QUOT            // " → \u0022
               | JSON_UNESCAPED_UNICODE   // keep multibyte chars as-is
               | JSON_THROW_ON_ERROR;     // throw \JsonException on failure

        try {
            return json_encode($value, $flags);
        } catch (\JsonException) {
            // Unserializable value (e.g. a resource, or a float NaN/Infinity).
            // Return 'null' rather than crashing — the caller can detect this
            // if needed by comparing the output to the string "null".
            return 'null';
        }
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /**
     * Manual JS string escaper used as a fallback when json_encode() fails.
     *
     * This covers all the same dangerous characters as the json_encode() path.
     * The replacement strings are carefully ordered: backslash MUST be replaced
     * first, otherwise it would double-encode the backslashes we're inserting.
     *
     * @param string $value UTF-8 string that failed json_encode().
     * @return string       Manually escaped string.
     */
    private static function fallbackEscapeJs(string $value): string
    {
        // Order matters: \\ must come first so we don't double-escape the
        // backslashes introduced by subsequent replacements.
        $replacements = [
            '\\'  => '\\\\',    // backslash → double backslash (must be first)
            '"'   => '\\"',     // double quote → escaped double quote
            "'"   => "\\'",     // single quote → escaped single quote
            "\n"  => '\\n',     // newline → literal \n sequence
            "\r"  => '\\r',     // carriage return → literal \r sequence
            "\t"  => '\\t',     // tab → literal \t sequence
            '<'   => '\\u003C', // less-than → Unicode escape (</script> prevention)
            '>'   => '\\u003E', // greater-than → Unicode escape
            '&'   => '\\u0026', // ampersand → Unicode escape (entity prevention)
            "\u{2028}" => '\\u2028',  // U+2028 Line Separator (JS line break in strings)
            "\u{2029}" => '\\u2029',  // U+2029 Paragraph Separator (same risk)
        ];

        // strtr() applies all replacements in a single pass, which is both
        // faster than chained str_replace() calls and avoids cascading issues
        // (a replacement string cannot itself be replaced in the same pass).
        return strtr($value, $replacements);
    }
}
