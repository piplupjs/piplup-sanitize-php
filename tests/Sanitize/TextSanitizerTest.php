<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Tests\Sanitize;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Piplup\Sanitize\Sanitize\TextSanitizer;

final class TextSanitizerTest extends TestCase
{
    // -------------------------------------------------------------------------
    // sanitizeTextField
    // -------------------------------------------------------------------------

    public function testSanitizeTextFieldStripsHtml(): void
    {
        $this->assertSame('Hello World', TextSanitizer::sanitizeTextField('<b>Hello</b> World'));
    }

    public function testSanitizeTextFieldStripsScript(): void
    {
        $this->assertSame(
            'alert(1)',
            TextSanitizer::sanitizeTextField('<script>alert(1)</script>')
        );
    }

    public function testSanitizeTextFieldCollapsesWhitespace(): void
    {
        $this->assertSame('foo bar', TextSanitizer::sanitizeTextField("  foo   bar  "));
    }

    public function testSanitizeTextFieldStripsNullBytes(): void
    {
        $this->assertSame('hello', TextSanitizer::sanitizeTextField("hel\x00lo"));
    }

    public function testSanitizeTextFieldStripsControlChars(): void
    {
        $this->assertSame('hello', TextSanitizer::sanitizeTextField("hel\x07lo"));
    }

    public function testSanitizeTextFieldEmptyString(): void
    {
        $this->assertSame('', TextSanitizer::sanitizeTextField(''));
    }

    public function testSanitizeTextFieldPreservesUnicode(): void
    {
        $this->assertSame('日本語テスト', TextSanitizer::sanitizeTextField('日本語テスト'));
    }

    /** @return array<string, array{0: string, 1: string}> */
    public static function xssPayloadProvider(): array
    {
        return [
            'img onerror'     => ['<img src=x onerror=alert(1)>', ''],
            'svg onload'      => ['<svg onload=alert(1)>', ''],
            'iframe src'      => ['<iframe src="javascript:alert(1)"></iframe>', ''],
            'nested tags'     => ['<b><i>text</i></b>', 'text'],
            'entity encoded'  => ['&lt;script&gt;', '&lt;script&gt;'],
        ];
    }

    #[DataProvider('xssPayloadProvider')]
    public function testSanitizeTextFieldXssPayloads(string $input, string $expected): void
    {
        $result = TextSanitizer::sanitizeTextField($input);
        $this->assertSame($expected, $result);
    }

    // -------------------------------------------------------------------------
    // sanitizeTextareaField
    // -------------------------------------------------------------------------

    public function testSanitizeTextareaFieldPreservesNewlines(): void
    {
        $input    = "line one\nline two\nline three";
        $expected = "line one\nline two\nline three";
        $this->assertSame($expected, TextSanitizer::sanitizeTextareaField($input));
    }

    public function testSanitizeTextareaFieldNormalizesLineEndings(): void
    {
        $input  = "line one\r\nline two\rline three";
        $result = TextSanitizer::sanitizeTextareaField($input);
        $this->assertStringNotContainsString("\r", $result);
        $this->assertSubstringCount(2, "\n", $result);
    }

    public function testSanitizeTextareaFieldStripsHtml(): void
    {
        $this->assertSame(
            "hello\nworld",
            TextSanitizer::sanitizeTextareaField("<b>hello</b>\n<i>world</i>")
        );
    }

    // -------------------------------------------------------------------------
    // sanitizeKey
    // -------------------------------------------------------------------------

    /** @return array<string, array{0: string, 1: string}> */
    public static function keyProvider(): array
    {
        return [
            'lowercase'          => ['hello',       'hello'],
            'uppercase converted' => ['Hello_World', 'hello_world'],
            'hyphens allowed'    => ['my-key',       'my-key'],
            'spaces stripped'    => ['my key',       'mykey'],
            'specials stripped'  => ['key!@#$',      'key'],
            'unicode stripped'   => ['héllo',        'hllo'],
            'empty'              => ['',              ''],
        ];
    }

    #[DataProvider('keyProvider')]
    public function testSanitizeKey(string $input, string $expected): void
    {
        $this->assertSame($expected, TextSanitizer::sanitizeKey($input));
    }

    // -------------------------------------------------------------------------
    // sanitizeTitle
    // -------------------------------------------------------------------------

    public function testSanitizeTitleStripsTagsPreservesText(): void
    {
        $this->assertSame(
            'My Post Title',
            TextSanitizer::sanitizeTitle('<h1>My Post Title</h1>')
        );
    }

    public function testSanitizeTitleDecodesEntities(): void
    {
        $this->assertSame('Hello & World', TextSanitizer::sanitizeTitle('Hello &amp; World'));
    }

    public function testSanitizeTitlePreservesAccents(): void
    {
        $this->assertSame('Héllo Wörld', TextSanitizer::sanitizeTitle('Héllo Wörld'));
    }

    // -------------------------------------------------------------------------
    // sanitizeSlug
    // -------------------------------------------------------------------------

    /** @return array<string, array{0: string, 1: string}> */
    public static function slugProvider(): array
    {
        return [
            'basic'               => ['Hello World',        'hello-world'],
            'accents'             => ['Héllo Wörld',        'hello-world'],
            'multiple spaces'     => ['foo   bar',          'foo-bar'],
            'underscores'         => ['foo_bar',            'foo-bar'],
            'leading/trailing'    => ['--my slug--',        'my-slug'],
            'consecutive hyphens' => ['foo---bar',          'foo-bar'],
            'numbers'             => ['post 123',           'post-123'],
            'html tags'           => ['<b>Bold</b> Title',  'bold-title'],
            'empty'               => ['',                   ''],
        ];
    }

    #[DataProvider('slugProvider')]
    public function testSanitizeSlug(string $input, string $expected): void
    {
        $this->assertSame($expected, TextSanitizer::sanitizeSlug($input));
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private function assertSubstringCount(int $expected, string $needle, string $haystack): void
    {
        $this->assertSame($expected, substr_count($haystack, $needle));
    }
}
