<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Sanitize;

use Piplup\Sanitize\Core\Encoding;

/**
 * Sanitize CSS declarations suitable for inline `style` attributes.
 *
 * This class removes unsafe properties (e.g. `expression()`, `behavior:`)
 * and sanitizes `url()` tokens using `UrlSanitizer`. It is intentionally
 * conservative and returns a minimal, safe CSS fragment suitable for
 * embedding inside an HTML `style` attribute.
 *
 * @api
 */
final class CssSanitizer
{
    /** @var array<string,bool> Allow-list of safe CSS properties */
    private const ALLOWED_PROPERTIES = [
        // Colors and backgrounds
        'color' => true,
        'background' => true,
        'background-color' => true,
        'background-image' => true,
        'background-repeat' => true,
        'background-position' => true,
        'background-size' => true,
        'background-attachment' => true,
        'background-clip' => true,
        'background-origin' => true,

        // Font
        'font-size' => true,
        'font-family' => true,
        'font-weight' => true,

        // Box model
        'width' => true,
        'height' => true,
        'max-width' => true,
        'max-height' => true,
        'min-width' => true,
        'min-height' => true,
        'margin' => true,
        'margin-top' => true,
        'margin-right' => true,
        'margin-bottom' => true,
        'margin-left' => true,
        'padding' => true,
        'padding-top' => true,
        'padding-right' => true,
        'padding-bottom' => true,
        'padding-left' => true,
        'box-sizing' => true,
        'border' => true,
        'border-top' => true,
        'border-right' => true,
        'border-bottom' => true,
        'border-left' => true,
        'border-width' => true,
        'border-style' => true,
        'border-color' => true,
        'border-radius' => true,
        'box-shadow' => true,

        // Layout & positioning
        'display' => true,
        'top' => true,
        'right' => true,
        'bottom' => true,
        'left' => true,
        'z-index' => true,
        'float' => true,
        'clear' => true,

        // Flex / grid helpers (simple whitelist)
        'flex' => true,
        'flex-basis' => true,
        'flex-direction' => true,
        'flex-flow' => true,
        'flex-grow' => true,
        'flex-shrink' => true,
        'flex-wrap' => true,
        'gap' => true,
        'grid' => true,

        // Text & decoration
        'text-align' => true,
        'vertical-align' => true,
        'text-decoration' => true,
        'line-height' => true,
        'letter-spacing' => true,
        'word-spacing' => true,
        'white-space' => true,
        'list-style' => true,
        'opacity' => true,
        'visibility' => true,
        'cursor' => true,

        // Transform / transitions / animation
        'transform' => true,
        'transform-origin' => true,
        'transition' => true,
        'transition-property' => true,
        'transition-duration' => true,
        'transition-timing-function' => true,
        'transition-delay' => true,
        'animation' => true,
        'animation-name' => true,
        'animation-duration' => true,
        'animation-timing-function' => true,
        'animation-delay' => true,
        'animation-iteration-count' => true,

        // Misc
        'overflow' => true,
        'overflow-x' => true,
        'overflow-y' => true,
        'overflow-wrap' => true,
        'word-wrap' => true,
        'word-break' => true,
        'hyphens' => true,
        'outline' => true,
        'outline-width' => true,
        'outline-style' => true,
        'outline-color' => true,
        'text-transform' => true,
        'text-overflow' => true,
        'text-indent' => true,
        'text-shadow' => true,
        'list-style-type' => true,
        'list-style-position' => true,
        'list-style-image' => true,
        'column-count' => true,
        'column-gap' => true,
        'column-rule' => true,
        'column-rule-color' => true,
        'column-rule-style' => true,
        'column-rule-width' => true,
        'columns' => true,
        'grid-template-columns' => true,
        'grid-template-rows' => true,
        'grid-column' => true,
        'grid-row' => true,
        'grid-area' => true,
        'grid-auto-flow' => true,
        'place-items' => true,
        'place-content' => true,
        'align-items' => true,
        'align-self' => true,
        'align-content' => true,
        'justify-content' => true,
        'justify-items' => true,
        'justify-self' => true,
        'order' => true,
        'resize' => true,
        'pointer-events' => true,
        'mix-blend-mode' => true,
        'background-blend-mode' => true,
        'background-position-x' => true,
        'background-position-y' => true,
        'font-style' => true,
        'font-variant' => true,
        'font-stretch' => true,
        'font-kerning' => true,
        'font-feature-settings' => true,
        'font-variant-ligatures' => true,
    ];

    /**
     * Sanitize a CSS fragment suitable for an HTML `style` attribute.
     *
     * This is intentionally conservative: unknown properties and any values
     * that contain `expression()`, `behavior:`, or `url()` with a rejected
     * protocol (javascript:, data:, vbscript:) are removed.
     *
     * @param string $css Raw CSS from an attribute value.
     * @return string Cleaned CSS (may be empty).
     */
    public static function sanitize(string $css, array $allowedUrlHosts = []): string
    {
        // Ensure valid UTF-8 and decode any HTML entities attackers may use
        // to obfuscate dangerous tokens (e.g. j&#097;vascript).
        $css = Encoding::toUtf8($css);
        $css = html_entity_decode($css, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Remove C-style comments
        $css = (string) preg_replace('!/\*.*?\*/!s', '', $css);

        // Split declarations on semicolon, but ignore semicolons inside
        // parentheses or quoted strings (e.g. data: URIs). This is a
        // lightweight stateful parser that is still cheaper than a full
        // CSS parser.
        $declarations = [];
        $start = 0;
        $len = mb_strlen($css);
        $depth = 0;
        $inQuote = null;

        for ($i = 0; $i < $len; $i++) {
            $ch = mb_substr($css, $i, 1);

            if ($inQuote !== null) {
                if ($ch === $inQuote) {
                    // Count consecutive backslashes before the quote. If the
                    // count is even, the quote closes the string; if odd,
                    // the quote is escaped and remains inside the string.
                    $backslashCount = 0;
                    $j = $i - 1;
                    while ($j >= 0 && mb_substr($css, $j, 1) === '\\') {
                        $backslashCount++;
                        $j--;
                    }
                    if ($backslashCount % 2 === 0) {
                        $inQuote = null;
                    }
                }
                continue;
            }

            if ($ch === '"' || $ch === "'") {
                $inQuote = $ch;
                continue;
            }

            if ($ch === '(') {
                $depth++;
                continue;
            }

            if ($ch === ')') {
                if ($depth > 0) {
                    $depth--;
                }
                continue;
            }

            if ($ch === ';' && $depth === 0) {
                $declarations[] = trim(mb_substr($css, $start, $i - $start));
                $start = $i + 1;
            }
        }

        $remaining = trim(mb_substr($css, $start));
        if ($remaining !== '') {
            $declarations[] = $remaining;
        }

        $out = [];

        foreach ($declarations as $decl) {
            $decl = trim($decl);
            if ($decl === '') {
                continue;
            }

            if (!str_contains($decl, ':')) {
                continue;
            }

            [$prop, $val] = array_map('trim', explode(':', $decl, 2));
            $prop = strtolower($prop);

            // Denylist known dangerous property names (preserve legacy behavior)
            // such as IE's `behavior` and Mozilla's `-moz-binding` which can
            // introduce executable content. Also deny `position` to prevent
            // full-page overlay/usability redress attack vectors (fixed/sticky).
            if ($prop === 'behavior' || $prop === '-moz-binding' || $prop === 'position') {
                continue;
            }

            // Allow all standard properties, vendor-prefixed properties
            // (e.g. -webkit-transform) and CSS custom properties (e.g. --my-var).
            // If the property is explicitly allowlisted, accept it. Otherwise,
            // accept any token that looks like a valid CSS property name
            // (optionally starting with one or two hyphens). Reject anything
            // that doesn't match the identifier pattern.
            if (!isset(self::ALLOWED_PROPERTIES[$prop])) {
                if (!preg_match('/^-{0,2}[a-z_][a-z0-9_-]*$/', $prop)) {
                    continue;
                }
            }

            // Remove raw control characters
            $val = (string) preg_replace('/[\x00-\x1F\x7F]/', '', $val);

            $lowVal = strtolower($val);

            // Dangerous constructs
            if (preg_match('/expression\s*\(/i', $val)) {
                continue;
            }

            if (str_contains($lowVal, 'behavior:')) {
                continue;
            }

            // Disallow angle brackets inside values
            if (str_contains($val, '<') || str_contains($val, '>')) {
                continue;
            }

            // Handle all url(...) occurrences — sanitize each inner URL and
            // remove only the unsafe ones instead of dropping the whole
            // declaration. This uses a callback so multiple urls are handled.
            // Find all url(...) occurrences and sanitize each one. Use a
            // simple balanced-paren scanner that respects quoted strings so
            // values like url("data(...)") are handled correctly.
            $replacements = [];
            $lower = mb_strtolower($val);
            $offset = 0;
            $len = mb_strlen($val);

            while (($p = mb_stripos($lower, 'url(', $offset)) !== false) {
                $startParen = mb_strpos($val, '(', $p);
                if ($startParen === false) {
                    break;
                }

                $i = $startParen + 1;
                $depth = 1;
                $inQuote = null;
                $endParen = null;

                while ($i < $len && $depth > 0) {
                    $ch = mb_substr($val, $i, 1);

                    if ($inQuote !== null) {
                        // End quote (ignore escaped quotes). Count preceding
                        // backslashes to determine whether the quote is escaped.
                        if ($ch === $inQuote) {
                            $backslashCount = 0;
                            $j = $i - 1;
                            while ($j >= 0 && mb_substr($val, $j, 1) === '\\') {
                                $backslashCount++;
                                $j--;
                            }
                            if ($backslashCount % 2 === 0) {
                                $inQuote = null;
                            }
                        }
                        $i++;
                        continue;
                    }

                    if ($ch === '"' || $ch === "'") {
                        $inQuote = $ch;
                        $i++;
                        continue;
                    }

                    if ($ch === '(') {
                        $depth++;
                    } elseif ($ch === ')') {
                        $depth--;
                        if ($depth === 0) {
                            $endParen = $i;
                            break;
                        }
                    }

                    $i++;
                }

                if ($endParen === null) {
                    break; // unmatched, bail out
                }

                $full = mb_substr($val, $p, $endParen - $p + 1);
                $inner = mb_substr($val, $startParen + 1, $endParen - $startParen - 1);

                // Normalize inner and decode entities
                $innerNorm = Encoding::toUtf8($inner);
                $innerNorm = html_entity_decode($innerNorm, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                $innerNorm = trim($innerNorm, "'\" \t\n\r\0\x0B");

                // Nested url(...) is suspicious
                    if (preg_match('/url\s*\(/i', $innerNorm)) {
                        $replacement = '';
                    } else {
                        $clean = UrlSanitizer::escUrlRaw($innerNorm);
                        if ($clean === '') {
                            $replacement = '';
                        } else {
                            // If the caller supplied an allowlist of hosts, enforce
                            // it here by checking the parsed host of the cleaned URL.
                            // Special sentinel: ['same-origin'] means "only allow
                            // relative URLs (no absolute scheme/host)", which is a
                            // conservative default for HTML sanitization when the
                            // sanitizer does not know the application's origin.
                            if (!empty($allowedUrlHosts)) {
                                $host = parse_url($clean, PHP_URL_HOST);
                                $scheme = parse_url($clean, PHP_URL_SCHEME);

                                // If caller explicitly requested same-origin-only,
                                // treat any URL with a scheme or host as external
                                // and therefore disallowed. Relative URLs (no
                                // scheme/host) are permitted.
                                if ($allowedUrlHosts === ['same-origin']) {
                                    if ($scheme !== null || ($host !== null && $host !== '')) {
                                        $replacement = '';
                                    } else {
                                        $replacement = 'url(' . $clean . ')';
                                    }
                                } else {
                                    if ($host !== null && $host !== '' && !in_array($host, $allowedUrlHosts, true)) {
                                        $replacement = '';
                                    } else {
                                        $replacement = 'url(' . $clean . ')';
                                    }
                                }
                            } else {
                                $replacement = 'url(' . $clean . ')';
                            }
                        }
                    }

                $replacements[] = [$p, $endParen, $replacement];
                $offset = $endParen + 1;
            }

            // Apply replacements from end to start to preserve offsets
            if (!empty($replacements)) {
                for ($r = count($replacements) - 1; $r >= 0; $r--) {
                    [$s, $e, $rep] = $replacements[$r];
                    $val = mb_substr($val, 0, $s) . $rep . mb_substr($val, $e + 1);
                }
            }

            // Clean up leftover commas / whitespace after removing some url(...)
            $val = preg_replace('/\s*,\s*,+/', ',', $val);
            $val = preg_replace('/^\s*,\s*/', '', $val);
            $val = preg_replace('/\s*,\s*$/', '', $val);
            $val = trim($val);

            // If removing unsafe url(...) left the value empty, drop it.
            if ($val === '') {
                continue;
            }

            // Reject inline javascript/data tokens that survived
            if (preg_match('/javascript\s*:/i', $val) || preg_match('/data\s*:/i', $val) || preg_match('/vbscript\s*:/i', $val)) {
                continue;
            }

            $out[] = $prop . ': ' . $val;
        }

        return implode('; ', $out);
    }
}
