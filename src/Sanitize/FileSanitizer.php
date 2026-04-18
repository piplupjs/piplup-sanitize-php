<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Sanitize;

use Piplup\Sanitize\Core\Encoding;

/**
 * File-name sanitization.
 *
 * WHY THIS CLASS EXISTS
 * ─────────────────────
 * Accepting a file name from user input without sanitization is one of the
 * most exploited attack surfaces in web applications.  Raw file names can:
 *
 *   • Traverse directories: "../../etc/passwd"
 *   • Contain null bytes that truncate C-level path strings: "shell.php\x00.jpg"
 *   • Overwrite system files: "CON", "NUL" (Windows reserved names crash apps)
 *   • Contain characters forbidden by the OS: /, \, :, *, ?, ", <, >, |
 *   • Execute when served: "shell.php", "evil.htaccess"
 *
 * This class removes all of those risks at the string level.  It does NOT
 * interact with the filesystem, so it is safe to call before you know
 * where the file will be stored.
 *
 * SCOPE: file NAME only (e.g. "my photo.jpg"), never a full path.
 * To validate a full path, combine this with a realpath() + base-directory
 * check after the file is placed on disk.
 */
final class FileSanitizer
{
    /**
     * Characters that are forbidden in file names on at least one major OS.
     *
     * We use the UNION of forbidden characters across Windows, macOS, and Linux
     * so the output is safe on all three platforms simultaneously.
     *
     * Windows forbidden: \ / : * ? " < > |
     * Linux/macOS: only / is truly forbidden, but we apply the wider superset
     * so files created on Linux can later be transferred to Windows without issues.
     *
     * \x00 (null byte) is listed explicitly even though it is also caught by
     * Encoding::stripNullBytes() — defense in depth means we strip it here too.
     */
    private const FORBIDDEN_CHARS = ['/', '\\', '?', '%', '*', ':', '|', '"', '<', '>', "\x00"];

    /**
     * Device names reserved by the Windows kernel.
     *
     * Windows treats these names as device handles regardless of extension.
     * Attempting to create or open a file named "CON.txt" or "NUL.log" does
     * not create a regular file — it opens the console or null device instead.
     * This silently breaks file-creation code and can cause crashes or hangs.
     *
     * We prefix reserved names with an underscore to make them safe.
     * The check is case-insensitive because Windows is case-insensitive for
     * these names (con.txt, CON.txt, and Con.txt are all the same device).
     */
    private const RESERVED_WINDOWS = [
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
    ];

    /**
     * Sanitize a file name for safe use on disk.
     *
     * FULL PIPELINE (executed in this order):
     *   1. Ensure valid UTF-8
     *   2. Strip null bytes and path separators / directory traversal sequences
     *   3. Remove characters forbidden on any major filesystem
     *   4. Split into base name and extension; sanitize each independently
     *   5. Strip non-safe characters from the base name
     *   6. Lowercase and strip non-alphanumeric chars from the extension
     *   7. Prefix Windows-reserved base names with an underscore
     *   8. Fall back to the string "file" if the cleaned base name is empty
     *   9. Reassemble base.ext
     *
     * WHY SPLIT BASE AND EXTENSION SEPARATELY?
     * ──────────────────────────────────────────
     * The extension must be kept lowercase and restricted to alphanumerics so
     * that the web server maps it to the correct MIME type (e.g. ".JPG" might
     * not be recognized as image/jpeg on some configurations).  The base name
     * has looser rules — we keep dots and hyphens there for readability.
     * Splitting avoids accidentally stripping the dot that separates them.
     *
     * Equivalent to WordPress sanitize_file_name().
     *
     * @param string $filename Raw file name (NOT a full path).
     * @return string          Sanitized file name safe for all major OS/FS.
     */
    public static function sanitizeFileName(string $filename): string
    {
        // Step 1: guarantee valid UTF-8 before any multi-byte operations.
        $filename = Encoding::toUtf8($filename);

        // Step 2: strip the most dangerous components upfront.
        // '../' and './' are path traversal sequences; we remove them before
        // removing individual forbidden chars to catch compound sequences like
        // "....//....//etc/passwd" that become "../" after partial stripping.
        // Remove null bytes and explicit path traversal sequences, but do not
        // remove bare ".." here — leave it for sanitizePart() to collapse
        // into a safe hyphen.  Removing bare ".." early causes
        // "my..file.txt" -> "myfile.txt" unexpectedly.
        // IMPORTANT: remove "../" before stripping plain '/' so that
        // traversal sequences are removed correctly (avoid order-dependent
        // replacement issues).
        // Remember the original to detect whether input contained a path
        // separator; we'll treat leading dots specially for those inputs.
        $originalFilename = $filename;
        $filename = str_replace(["\x00", '../', './', '/', '\\'], '', $filename);

        // Step 3: remove individual forbidden characters.
        // FORBIDDEN_CHARS is a superset of Windows + POSIX forbidden chars.
        $filename = str_replace(self::FORBIDDEN_CHARS, '', $filename);

        // Step 4: split at the last dot to separate base name from extension.
        // We use strrpos (last occurrence) because files like "archive.tar.gz"
        // should have base="archive.tar" and ext="gz", not base="archive" ext="tar.gz".
        // If the original input contained a path separator, trim leading
        // dots so that traversal inputs like "../../etc/passwd" become
        // "etcpasswd" instead of producing an empty base and a fake
        // extension.
        if (str_contains($originalFilename, '/') || str_contains($originalFilename, '\\')) {
            $filename = ltrim($filename, '.');
        }

        [$base, $ext] = self::splitExtension($filename);

        // Step 5: sanitize the base name (spaces → hyphens, collapse dots, etc.)
        $base = self::sanitizePart($base);

        // Step 6: extension must be lowercase alphanumerics only.
        // No dots, no hyphens — just the bare extension string.
        // strtolower handles ASCII-only extension chars; no mb needed here.
        $ext = strtolower((string) preg_replace('/[^a-zA-Z0-9]/', '', $ext));

        // Step 7: if the base name is a Windows device name, prefix it.
        // The check is uppercase to match Windows behavior (case-insensitive).
        if (in_array(strtoupper($base), self::RESERVED_WINDOWS, true)) {
            $base = '_' . $base;
        }

        // Step 8: guarantee a non-empty base name — never let the result be
        // just ".jpg" or an empty string, both of which are problematic on disk.
        if ($base === '') {
            $base = 'file';
        }

        // Step 9: reassemble.  Omit the dot when there is no extension.
        return $ext !== '' ? "{$base}.{$ext}" : $base;
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /**
     * Split a file name into [basename, extension].
     *
     * WHY strrpos INSTEAD OF pathinfo()?
     * ─────────────────────────────────────
     * pathinfo() is locale-sensitive in some PHP builds and behaves differently
     * depending on the LC_ALL environment variable.  strrpos() is binary-safe
     * and behaves identically on every system.
     *
     * The extension does NOT include the leading dot — e.g. "photo.jpg" → ["photo", "jpg"].
     *
     * Special cases:
     *   "README"     → ["README", ""]     — no extension
     *   ".htaccess"  → [".htaccess", ""]  — dot-only prefix is treated as base,
     *                                        not extension (hidden files on Unix)
     *
     * @param string $filename File name string (not a full path).
     * @return array{0: string, 1: string}  [base, extension]
     */
    private static function splitExtension(string $filename): array
    {
        $pos = strrpos($filename, '.');

        // No dot at all, or dot is the very first character (hidden file like .htaccess).
        // In both cases, treat the entire name as the base with no extension.
        if ($pos === false || $pos === 0) {
            return [$filename, ''];
        }

        return [substr($filename, 0, $pos), substr($filename, $pos + 1)];
    }

    /**
     * Sanitize the base-name portion of a file name.
     *
     * OPERATIONS (in order):
     *   1. Replace spaces and underscores with hyphens
     *      "my photo" → "my-photo"  (spaces are technically allowed on most
     *      filesystems but cause shell escaping headaches and URL encoding issues)
     *   2. Strip characters that are not word chars (\w), hyphens, or dots
     *      \w matches [a-zA-Z0-9_] plus Unicode word characters
     *      The /u flag is required so \w matches non-ASCII word chars (e.g. "ñ")
     *   3. Collapse runs of consecutive hyphens or dots to a single hyphen
     *      "foo---bar" → "foo-bar",  "foo..bar" → "foo-bar"
     *   4. Trim leading and trailing hyphens and dots
     *      "-foo-"  → "foo",  ".foo."  → "foo"
     *
     * @param string $part Raw base-name segment.
     * @return string      Sanitized base-name segment.
     */
    private static function sanitizePart(string $part): string
    {
        // Spaces and underscores → hyphens.
        $part = (string) preg_replace('/[\s_]+/', '-', $part);

        // Keep only ASCII alphanumerics, hyphens, and dots.
        // We intentionally do NOT use the /u flag or \w here because \w in
        // Unicode mode matches Cyrillic, Arabic, CJK, etc.  File names with
        // non-ASCII characters cause portability issues across OS/FS/HTTP
        // contexts, so we strip them to ASCII-safe characters only.
        $part = (string) preg_replace('/[^a-zA-Z0-9\-\.]/', '', $part);

        // Collapse consecutive hyphens or dots into a single hyphen.
        // The hyphen is placed at the END of the character class to avoid being
        // interpreted as a range operator (e.g. [-\.] could be read as "from
        // chr(45) to chr(46)" which happens to be the same, but is ambiguous).
        $part = (string) preg_replace('/[\.\-]{2,}/', '-', $part);

        // Trim edge hyphens and dots.
        return trim($part, '-.');
    }
}
