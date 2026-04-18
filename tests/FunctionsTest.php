<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Smoke tests for the optional global helper functions defined in functions.php.
 *
 * These test that the helpers are callable and proxy correctly to their
 * underlying class methods.
 */
final class FunctionsTest extends TestCase
{
    // -------------------------------------------------------------------------
    // Sanitize helpers
    // -------------------------------------------------------------------------

    public function testSanitizeTextField(): void
    {
        $this->assertSame('hello', sanitize_text_field('<b>hello</b>'));
    }

    public function testSanitizeTextareaField(): void
    {
        $result = sanitize_textarea_field("line1\nline2");
        $this->assertStringContainsString("\n", $result);
    }

    public function testSanitizeKey(): void
    {
        $this->assertSame('my_key', sanitize_key('My_Key!'));
    }

    public function testSanitizeTitle(): void
    {
        $this->assertSame('Hello World', sanitize_title('<h1>Hello World</h1>'));
    }

    public function testSanitizeTitleWithDashes(): void
    {
        $this->assertSame('hello-world', sanitize_title_with_dashes('Hello World'));
    }

    public function testSanitizeEmail(): void
    {
        $this->assertSame('user@example.com', sanitize_email('USER@EXAMPLE.COM'));
    }

    public function testSanitizeFileName(): void
    {
        $this->assertSame('file.txt', sanitize_file_name('  file.txt  '));
    }

    // -------------------------------------------------------------------------
    // Escape helpers
    // -------------------------------------------------------------------------

    public function testEscHtml(): void
    {
        $this->assertSame('&lt;b&gt;text&lt;/b&gt;', esc_html('<b>text</b>'));
    }

    public function testEscAttr(): void
    {
        $this->assertStringNotContainsString('"', esc_attr('"value"'));
    }

    public function testEscTextarea(): void
    {
        $this->assertSame('&lt;script&gt;', esc_textarea('<script>'));
    }

    public function testEscJs(): void
    {
        $result = esc_js("it's here");
        $this->assertStringContainsString("\\'", $result);
    }

    public function testEscUrl(): void
    {
        $this->assertSame('', esc_url('javascript:alert(1)'));
    }

    public function testEscUrlRaw(): void
    {
        $result = esc_url_raw('https://example.com?a=1&b=2');
        $this->assertStringContainsString('&', $result);
        $this->assertStringNotContainsString('&amp;', $result);
    }

    // -------------------------------------------------------------------------
    // KSES helpers
    // -------------------------------------------------------------------------

    public function testWpKses(): void
    {
        $result = wp_kses('<script>alert(1)</script><b>bold</b>', ['b' => []]);
        $this->assertStringNotContainsString('<script>', $result);
        $this->assertStringContainsString('<b>', $result);
    }

    public function testWpKsesPost(): void
    {
        $result = wp_kses_post('<h2>Title</h2><script>evil()</script>');
        $this->assertStringContainsString('<h2>', $result);
        $this->assertStringNotContainsString('<script>', $result);
    }

    public function testWpKsesData(): void
    {
        $result = wp_kses_data('<em>text</em><div>block</div>');
        $this->assertStringContainsString('<em>', $result);
        $this->assertStringNotContainsString('<div>', $result);
    }

    // -------------------------------------------------------------------------
    // Utility helpers
    // -------------------------------------------------------------------------

    public function testAbsint(): void
    {
        $this->assertSame(5, absint(-5));
        $this->assertSame(0, absint(null));
    }

    public function testRemoveAccents(): void
    {
        $this->assertSame('cafe', remove_accents('café'));
    }

    public function testWpStripAllTags(): void
    {
        $this->assertSame('hello', wp_strip_all_tags('<b>hello</b>'));
    }
}
