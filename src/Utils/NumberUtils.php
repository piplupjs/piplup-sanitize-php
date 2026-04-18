<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Utils;

/**
 * Number sanitization and clamping helpers.
 *
 * WHY THIS CLASS EXISTS
 * ─────────────────────
 * User input arrives as strings.  Database values arrive as strings or
 * mixed types.  Without explicit casting and validation, a value like "-5",
 * "3.7", "0xFF", or null can cause subtle bugs when used in arithmetic,
 * comparisons, or database queries.
 *
 * This class provides a small set of "safe cast" helpers that:
 *   • Always return the expected PHP type (int or float) — never a string
 *   • Never throw or emit warnings on unexpected input
 *   • Document their exact behavior for edge cases (null, bool, array, …)
 */
final class NumberUtils
{
    /**
     * Convert any value to a non-negative (absolute) integer.
     *
     * WHY "ABSOLUTE"?
     * ────────────────
     * Many application values are inherently non-negative: counts, IDs,
     * ages, quantities, pagination page numbers, etc.  Storing a negative
     * value for "number of items" is almost certainly a bug or injection
     * attempt.  absint() is the simplest, most explicit way to express
     * "this must be a non-negative integer".
     *
     * CASTING RULES (match WordPress absint() behavior):
     *   int     → abs(int)                  5  → 5,  -5  → 5
     *   float   → abs((int)float)           3.9 → 3,  -3.9 → 3
     *   string  → (int) then abs()         "42" → 42, "-5" → 5, "3.7" → 3
     *   bool    → (int) bool               true → 1, false → 0
     *   null    → (int)null → abs(0) → 0
     *   array   → (int)[] → 0 (empty), (int)[x] → 1 (non-empty) then abs()
     *   object  → (int)$obj → 0 or error depending on __cast; we default to 0
     *
     * WHY THE SPECIAL CASE FOR bool?
     * ────────────────────────────────
     * (int)true = 1 and (int)false = 0, which is expected.
     * Without the special case, abs((int)true) = 1 and abs((int)false) = 0 —
     * the same result.  However, the explicit branch documents the intent and
     * makes it clear that booleans are handled intentionally rather than
     * accidentally through the generic (int) cast.
     *
     * Equivalent to WordPress absint().
     *
     * @param mixed $value Any PHP value.
     * @return int         Non-negative integer.
     */
    public static function absint(mixed $value): int
    {
        // Booleans cast correctly to 1/0 with (int), but document intent.
        if (is_bool($value)) {
            return (int) $value;  // true → 1, false → 0 (already non-negative)
        }

        // (int) cast handles strings, floats, null, and arrays.
        // abs() ensures the result is non-negative.
        return abs((int) $value);
    }

    /**
     * Clamp an integer to an inclusive [$min, $max] range.
     *
     * "Clamping" means: if the value is below $min, return $min; if it is
     * above $max, return $max; otherwise return the value unchanged.
     *
     * USE CASES:
     *   • Limiting pagination page numbers: clampInt($page, 1, $totalPages)
     *   • Bounding user-supplied image dimensions: clampInt($width, 1, 2000)
     *   • Restricting a rating to a valid range: clampInt($stars, 1, 5)
     *
     * WHY NOT JUST USE min() AND max() INLINE?
     * ──────────────────────────────────────────
     * max($min, min($max, $value)) works but is easy to get backwards.
     * This named method makes the intent clear and is hard to mis-use.
     *
     * @param int $value The input integer.
     * @param int $min   Lower bound (inclusive).
     * @param int $max   Upper bound (inclusive).
     * @return int       Value clamped to [$min, $max].
     */
    public static function clampInt(int $value, int $min, int $max): int
    {
        // max($min, …) ensures value is at least $min.
        // min($max, …) ensures value is at most $max.
        // The nesting: max($min, min($max, $value)) — evaluate inner min first.
        return max($min, min($max, $value));
    }

    /**
     * Clamp a float to an inclusive [$min, $max] range.
     *
     * Same logic as clampInt(), but for floating-point values.
     *
     * USE CASES:
     *   • Bounding a percentage: clampFloat($pct, 0.0, 100.0)
     *   • Limiting an opacity: clampFloat($alpha, 0.0, 1.0)
     *   • Constraining a score: clampFloat($score, -10.0, 10.0)
     *
     * @param float $value The input float.
     * @param float $min   Lower bound (inclusive).
     * @param float $max   Upper bound (inclusive).
     * @return float       Value clamped to [$min, $max].
     */
    public static function clampFloat(float $value, float $min, float $max): float
    {
        return max($min, min($max, $value));
    }

    /**
     * Return true if $value is a number or a numeric string.
     *
     * This is a named wrapper around PHP's is_numeric() that makes it easier
     * to use in pipeline code and makes the intent explicit.
     *
     * is_numeric() returns true for:
     *   • Integers:          42, -7
     *   • Floats:            3.14, -0.5, 1e10
     *   • Numeric strings:   "42", "3.14", "0x1A" (hex in older PHP)
     *   • Leading whitespace is allowed: " 42 " → true (PHP quirk)
     *
     * Returns false for:
     *   • Non-numeric strings: "abc", "12px", "3.14abc"
     *   • null, bool, arrays, objects
     *
     * @param mixed $value Any PHP value.
     * @return bool        True if the value is numeric.
     */
    public static function isNumeric(mixed $value): bool
    {
        return is_numeric($value);
    }

    /**
     * Safely cast any value to a float.
     *
     * WHY NOT JUST USE (float) INLINE?
     * ──────────────────────────────────
     * (float)'abc' = 0.0 without any indication that the input was invalid.
     * This method documents the contract explicitly: non-numeric input returns 0.0.
     * Using this method over a bare (float) cast communicates intent to future
     * readers: "I know non-numeric input will become 0.0 and that is correct here".
     *
     * EDGE CASES:
     *   "3.14"  → 3.14    numeric string
     *   "abc"   → 0.0     non-numeric string (silent, per the contract)
     *   true    → 1.0     boolean true
     *   false   → 0.0     boolean false
     *   null    → 0.0
     *
     * @param mixed $value Any PHP value.
     * @return float       The numeric value, or 0.0 for non-numeric input.
     */
    public static function toFloat(mixed $value): float
    {
        // Reject non-numeric, non-boolean values explicitly.
        // is_numeric() covers int, float, and numeric strings.
        // is_bool() covers true/false which cast to 1.0/0.0.
        if (!is_numeric($value) && !is_bool($value)) {
            return 0.0;
        }

        return (float) $value;
    }

    /**
     * Safely cast any value to a signed integer.
     *
     * Unlike absint(), this method preserves the sign.  Use it when negative
     * integers are a valid result (e.g. sort order offsets, temperature in °C,
     * financial amounts where negative = debit).
     *
     * EDGE CASES:
     *   "42.9" → 42    float string truncated toward zero
     *   "-5"   → -5    negative string preserved
     *   "abc"  → 0     non-numeric string
     *   null   → 0
     *   true   → 1
     *   false  → 0
     *
     * @param mixed $value Any PHP value.
     * @return int         The value cast to int (sign preserved).
     */
    public static function toInt(mixed $value): int
    {
        // (int) cast is defined for all PHP types and never throws.
        return (int) $value;
    }
}
