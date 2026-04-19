# piplup/sanitize

A **framework-agnostic PHP 8.1+ Composer library** providing WordPress-style
sanitization and escaping utilities — rebuilt on modern PHP standards, without
any WordPress dependency.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
  - [Core](#core)
  - [TextSanitizer](#textsanitizer)
  - [FileSanitizer](#filesanitizer)
  - [EmailSanitizer](#emailsanitizer)
  - [UrlSanitizer](#urlsanitizer)
  - [HtmlEscaper](#htmlescaper)
  - [JsEscaper](#jsescaper)
  - [Kses](#kses)
  - [AllowedHtml presets](#allowedhtml-presets)
  - [StringUtils](#stringutils)
  - [NumberUtils](#numberutils)
  - [Global helper functions](#global-helper-functions)
- [Security Model](#security-model)
- [Testing](#testing)
- [Requirements](#requirements)

---

## Installation

```bash
composer require piplup/sanitize
```

The `ext-mbstring` PHP extension is required.
Installing `ext-intl` is strongly recommended — it enables full Unicode
transliteration in `StringUtils::removeAccents()`.

---

## Quick Start

### Class-based (recommended)

```php
use Piplup\Sanitize\Sanitize\TextSanitizer;
use Piplup\Sanitize\Escape\HtmlEscaper;
use Piplup\Sanitize\Kses\Kses;
use Piplup\Sanitize\Kses\AllowedHtml;

// Sanitize incoming data
$title   = TextSanitizer::sanitizeTextField($_POST['title']);
$content = $_POST['content'];  // raw, will be filtered on output

// Escape on the way out
echo '<h1>' . HtmlEscaper::escHtml($title) . '</h1>';

// Filter HTML through an allow-list
echo Kses::filter($content, AllowedHtml::post());
```

### WordPress-style global helpers

The library ships optional global functions that mirror WordPress's API.
They are auto-loaded by Composer when the `"files"` entry is present in
`composer.json`.

```php
$title   = sanitize_text_field($_POST['title']);
$content = wp_kses_post($_POST['content']);

echo '<h1>' . esc_html($title) . '</h1>';
echo esc_url($url);
```

> **Tip:** Remove the `"files"` key from `composer.json` if you prefer to
> avoid global function pollution and use the classes directly instead.

---

## API Reference

### Core

#### `Encoding` — `Piplup\Sanitize\Core\Encoding`

Low-level UTF-8 helpers. Called internally by every other class.

| Method | Description |
|---|---|
| `toUtf8(string): string` | Ensure valid UTF-8; replace invalid bytes |
| `isValidUtf8(string): bool` | Check validity without modifying |
| `stripNullBytes(string): string` | Remove `\x00` bytes |
| `stripControlCharacters(string): string` | Remove C0 controls (except HT, LF, CR) |
| `byteLength(string): int` | Raw byte count |
| `charLength(string): int` | Unicode character count |

#### `Normalization` — `Piplup\Sanitize\Core\Normalization`

| Method | Description |
|---|---|
| `normalizeLineEndings(string): string` | Normalize `\r\n` / `\r` → `\n` |
| `collapseWhitespace(string): string` | Collapse runs of horizontal space; trim |
| `removeAllWhitespace(string): string` | Strip every whitespace character |
| `trimUnicode(string): string` | Trim including non-breaking spaces |
| `toLower(string): string` | Multibyte-safe lowercase |
| `toUpper(string): string` | Multibyte-safe uppercase |
| `clean(string): string` | toUtf8 + stripNullBytes + stripControl + collapse |

---

### TextSanitizer

`Piplup\Sanitize\Sanitize\TextSanitizer`

```php
use Piplup\Sanitize\Sanitize\TextSanitizer;

TextSanitizer::sanitizeTextField('  <b>Hello</b>  ');   // → 'Hello'
TextSanitizer::sanitizeTextareaField("line1\r\nline2");  // → "line1\nline2"
TextSanitizer::sanitizeKey('My Key!');                   // → 'my-key'  (wait: 'mykey')
TextSanitizer::sanitizeTitle('<h1>Post Title</h1>');     // → 'Post Title'
TextSanitizer::sanitizeSlug('Hello Wörld');              // → 'hello-world'
```

| Method | WordPress equivalent |
|---|---|
| `sanitizeTextField(string): string` | `sanitize_text_field()` |
| `sanitizeTextareaField(string): string` | `sanitize_textarea_field()` |
| `sanitizeKey(string): string` | `sanitize_key()` |
| `sanitizeTitle(string): string` | `sanitize_title()` (display) |
| `sanitizeSlug(string): string` | `sanitize_title()` (save/slug) |

---

### FileSanitizer

`Piplup\Sanitize\Sanitize\FileSanitizer`

```php
use Piplup\Sanitize\Sanitize\FileSanitizer;

FileSanitizer::sanitizeFileName('../../etc/passwd');  // → 'etcpasswd'
FileSanitizer::sanitizeFileName('My Photo.JPG');      // → 'My-Photo.jpg'
FileSanitizer::sanitizeFileName('CON.txt');           // → '_CON.txt'
```

| Method | WordPress equivalent |
|---|---|
| `sanitizeFileName(string): string` | `sanitize_file_name()` |

Handles path traversal, null bytes, Windows-reserved names, forbidden
filesystem characters, and normalises the extension to lowercase.

Note: `FileSanitizer::sanitizeFileName()` strips dangerous embedded
extensions from the base name to prevent multi-extension bypasses
(for example `shell.php8.jpg` → `shell.jpg`). The blocklist includes
versioned PHP suffixes and other server-side/executable extensions
(for example: `php2`, `php6`, `php8`, `php9`, `phtml`, `phar`, `shtml`,
`cgi`, `pl`, `py`, `rb`, `sh`, `exe`, `bat`, `ps1`, `htaccess`). This
reduces risk but does not replace server-side MIME/type validation;
validate uploads with `finfo` and prefer an explicit allowlist of
permitted extensions when possible.

---

### EmailSanitizer

`Piplup\Sanitize\Sanitize\EmailSanitizer`

```php
use Piplup\Sanitize\Sanitize\EmailSanitizer;

EmailSanitizer::sanitizeEmail('USER@EXAMPLE.COM');  // → 'user@example.com'
EmailSanitizer::sanitizeEmail('not-an-email');      // → ''
EmailSanitizer::isValidEmail('user@example.com');   // → true
```

| Method | WordPress equivalent |
|---|---|
| `sanitizeEmail(string): string` | `sanitize_email()` |
| `isValidEmail(string): bool` | *(no WP equivalent)* |

---

### UrlSanitizer

`Piplup\Sanitize\Sanitize\UrlSanitizer`

```php
use Piplup\Sanitize\Sanitize\UrlSanitizer;

// For HTML attributes — output is HTML-encoded
UrlSanitizer::escUrl('https://example.com/?a=1&b=2');
// → 'https://example.com/?a=1&amp;b=2'

// For HTTP redirects / storage — NOT HTML-encoded
UrlSanitizer::escUrlRaw('https://example.com/?a=1&b=2');
// → 'https://example.com/?a=1&b=2'

// Dangerous protocols rejected
UrlSanitizer::escUrl('javascript:alert(1)');  // → ''

// Custom protocol allow-list
UrlSanitizer::escUrl('myapp://deep-link', ['myapp']);
```


| Method | WordPress equivalent |
|---|---|
| `escUrl(string $url, array $allowedProtocols = [], bool $allowProtocolRelative = false): string` | `esc_url()` |
| `escUrlRaw(string $url, array $allowedProtocols = [], bool $allowProtocolRelative = false): string` | `esc_url_raw()` |

Default allowed protocols: `http`, `https`, `ftp`, `ftps`, `mailto`, `news`,
`irc`, `gopher`, `nntp`, `feed`, `telnet`, `mms`, `rtsp`, `sms`, `svn`,
`tel`, `fax`, `xmpp`, `webcal`.

Notes:
- `UrlSanitizer` decodes HTML entities and numeric character references before checking the scheme (defeats obfuscations such as `javascript&#58;`), strips null bytes and control/whitespace characters, and percent-encodes unsafe characters while preserving existing `%XX` escapes.
- Protocol-relative URLs (`//example.com/path`) are treated as external and are rejected by default; pass `$allowProtocolRelative = true` to allow them explicitly.

---

### CssSanitizer

`Piplup\Sanitize\Sanitize\CssSanitizer`

```php
use Piplup\Sanitize\Sanitize\CssSanitizer;

// Default usage (Kses::filter() passes ['same-origin'] by default):
$clean = CssSanitizer::sanitize('cursor: url("/c.cur"), auto', ['same-origin']);

// Allow specific hosts for url(...) tokens:
$clean = CssSanitizer::sanitize($css, ['example.com', 'cdn.example.com']);
```

| Method | Notes |
|---|---|
| `sanitize(string, array $allowedUrlHosts = []): string` | The optional second parameter controls which hosts are permitted in `url()` tokens. When passed `['same-origin']` (used by `Kses::filter()` by default), absolute URLs that include a scheme or host are removed and only relative URLs are allowed. Passing a non-empty list allows only those hostnames; an empty array (default) permits all cleaned URLs. |


---

### HtmlEscaper

`Piplup\Sanitize\Escape\HtmlEscaper`

```php
use Piplup\Sanitize\Escape\HtmlEscaper;

echo '<p>'         . HtmlEscaper::escHtml($text)      . '</p>';
echo '<input value="' . HtmlEscaper::escAttr($val)   . '">';
echo '<textarea>'  . HtmlEscaper::escTextarea($val)   . '</textarea>';

// Undo escaping (do NOT echo result directly into HTML)
$decoded = HtmlEscaper::decodeEntities($encoded);
```

| Method | WordPress equivalent |
|---|---|
| `escHtml(string): string` | `esc_html()` |
| `escAttr(string): string` | `esc_attr()` |
| `escTextarea(string): string` | `esc_textarea()` |
| `decodeEntities(string): string` | *(utility)* |

---

### JsEscaper

`Piplup\Sanitize\Escape\JsEscaper`

```php
use Piplup\Sanitize\Escape\JsEscaper;

// Embed a PHP string in a JS string literal
$safe = JsEscaper::escJs($userInput);
// Use in template: <script>var msg = '<?= $safe ?>';</script>

// Serialize a PHP value as JSON for inline script
$json = JsEscaper::jsonEncode(['key' => $value]);
// Use in template: <script>var data = <?= $json ?>;</script>
```

| Method | WordPress equivalent |
|---|---|
| `escJs(string): string` | `esc_js()` |
| `jsonEncode(mixed): string` | `wp_json_encode()` |

`jsonEncode()` automatically escapes `<`, `>`, `&`, `'`, `"` so the output is
safe inside a `<script>` block without additional escaping.

---

### Kses

`Piplup\Sanitize\Kses\Kses`

```php
use Piplup\Sanitize\Kses\Kses;
use Piplup\Sanitize\Kses\AllowedHtml;

// Filter with a custom allow-list
$clean = Kses::filter($html, [
  'a'  => ['href' => true, 'title' => true],
  'b'  => [],
  'em' => [],
]);

// Or use a preset
$clean = Kses::filter($html, AllowedHtml::post());
```

| Method | WordPress equivalent |
|---|---|
| `Kses::filter(string, array): string` | `wp_kses()` |

Uses **DOMDocument** (not regex) for parsing.  Event handler attributes
(`onclick`, `onerror`, etc.) are **always** stripped regardless of the
allow-list.  URL-bearing attributes (`href`, `src`, `action`, …) are run
through `UrlSanitizer::escUrlRaw()` to block `javascript:` and other
dangerous schemes.

Additional notes:

- When an `<a>` element has `target="_blank"` and the allow-list
  permits the `rel` attribute, `Kses::filter()` will ensure the `rel`
  value includes `noopener` and `noreferrer` to prevent reverse
  tabnapping attacks.
- Inline `style` attributes are sanitized via `CssSanitizer::sanitize()`.
  `Kses::filter()` passes a conservative `['same-origin']` sentinel by
  default which removes absolute external `url()` tokens from inline CSS
  (only relative URLs are permitted). If your application legitimately
  requires external CSS resources, pre-sanitize style values with
  `CssSanitizer::sanitize($css, ['example.com'])` or modify the sanitizer
  call to allow specific hosts.

---

### AllowedHtml presets

`Piplup\Sanitize\Kses\AllowedHtml`

| Method | WordPress equivalent | Description |
|---|---|---|
| `AllowedHtml::post()` | `wp_kses_post()` allow-list | Full rich-text: headings, links, images, tables, … |
| `AllowedHtml::data()` | `wp_kses_data()` allow-list | Minimal inline: `<a>`, `<b>`, `<em>`, `<code>`, … |
| `AllowedHtml::inline()` | *(no direct equivalent)* | Inline only, no block elements |

---

### StringUtils

`Piplup\Sanitize\Utils\StringUtils`

```php
use Piplup\Sanitize\Utils\StringUtils;

StringUtils::removeAccents('café');           // → 'cafe'
StringUtils::stripAllTags('<p>Hello</p>');    // → 'Hello'
StringUtils::truncate('Long string…', 10);   // → 'Long str…'
StringUtils::startsWith('Hello', 'He');       // → true
StringUtils::endsWith('Hello', 'lo');         // → true
```

| Method | WordPress equivalent |
|---|---|
| `removeAccents(string): string` | `remove_accents()` |
| `stripAllTags(string, bool): string` | `wp_strip_all_tags()` |
| `truncate(string, int, string): string` | *(no direct equivalent)* |

---

### NumberUtils

`Piplup\Sanitize\Utils\NumberUtils`

```php
use Piplup\Sanitize\Utils\NumberUtils;

NumberUtils::absint(-5);              // → 5
NumberUtils::absint('3.9');           // → 3
NumberUtils::clampInt(15, 1, 10);     // → 10
NumberUtils::clampFloat(-0.5, 0, 1); // → 0.0
NumberUtils::toFloat('3.14');         // → 3.14
NumberUtils::toInt('42abc');          // → 42
```

| Method | WordPress equivalent |
|---|---|
| `absint(mixed): int` | `absint()` |

---

### Global helper functions

When the `"files": ["src/functions.php"]` autoload entry is present, the
following global functions are available:

| Function | Proxies to |
|---|---|
| `sanitize_text_field($v)` | `TextSanitizer::sanitizeTextField()` |
| `sanitize_textarea_field($v)` | `TextSanitizer::sanitizeTextareaField()` |
| `sanitize_key($v)` | `TextSanitizer::sanitizeKey()` |
| `sanitize_title($v)` | `TextSanitizer::sanitizeTitle()` |
| `sanitize_title_with_dashes($v)` | `TextSanitizer::sanitizeSlug()` |
| `sanitize_email($v)` | `EmailSanitizer::sanitizeEmail()` |
| `sanitize_file_name($v)` | `FileSanitizer::sanitizeFileName()` |
| `esc_html($v)` | `HtmlEscaper::escHtml()` |
| `esc_attr($v)` | `HtmlEscaper::escAttr()` |
| `esc_textarea($v)` | `HtmlEscaper::escTextarea()` |
| `esc_js($v)` | `JsEscaper::escJs()` |
| `esc_url($v, $protocols)` | `UrlSanitizer::escUrl()` |
| `esc_url_raw($v, $protocols)` | `UrlSanitizer::escUrlRaw()` |
| `wp_kses($html, $allowed)` | `Kses::filter()` |
| `wp_kses_post($html)` | `Kses::filter(…, AllowedHtml::post())` |
| `wp_kses_data($html)` | `Kses::filter(…, AllowedHtml::data())` |
| `absint($v)` | `NumberUtils::absint()` |
| `remove_accents($v)` | `StringUtils::removeAccents()` |
| `wp_strip_all_tags($v, $breaks)` | `StringUtils::stripAllTags()` |

All functions are guarded with `function_exists()` checks so they will not
conflict if you load this library alongside WordPress.

---

## Security Model

### Escape on output; sanitize on input

- **Sanitize** when data enters your system (form submission, API response, file upload).
  Strip or transform characters that shouldn't be stored.
- **Escape** immediately before output.
  Encode characters that have special meaning in the target context (HTML, JS, SQL, …).

### What this library does NOT do

- **SQL escaping** — use parameterised queries / prepared statements.
- **Shell escaping** — use `escapeshellarg()` / `escapeshellcmd()`.
- **Path validation** — use `realpath()` and compare against an allowed base directory.
- **Content-type validation** — validate MIME type with `finfo` for file uploads.
- **DNS / MX validation** — use a dedicated SMTP library to verify deliverability.

### KSES implementation notes

- Parsing is done with `DOMDocument` — not regex — to correctly handle
  adversarial markup.
- `on*` event-handler attributes are blocked unconditionally.
- URL-bearing attributes (`href`, `src`, `action`, `cite`, `formaction`, …)
  are passed through `UrlSanitizer` to block `javascript:`, `data:`, and
  `vbscript:` schemes.
- The `<script>`, `<object>`, `<embed>`, `<iframe>`, and `<form>` tags are
  not included in any preset.

---

## Testing

```bash
composer install
./vendor/bin/phpunit
```

Generate an HTML coverage report:

```bash
./vendor/bin/phpunit --coverage-html coverage/
```

The test suite covers:

- XSS payloads (OWASP Top 10 vectors)
- Malformed and adversarial HTML
- Invalid / partial UTF-8 byte sequences
- Null bytes and control characters
- Windows-reserved filenames and path traversal
- Edge cases: empty strings, `null`, booleans, arrays

---

## Requirements

| Requirement | Version |
|---|---|
| PHP | ^8.1 |
| ext-mbstring | required |
| ext-intl | optional (better accent removal) |
| phpunit/phpunit | ^10 (dev only) |

## License

MIT
