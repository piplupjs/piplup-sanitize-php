<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Tests\Escape;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Piplup\Sanitize\Escape\HtmlEscaper;

final class HtmlEscaperTest extends TestCase
{
    // -------------------------------------------------------------------------
    // escHtml
    // -------------------------------------------------------------------------

    /** @return array<string, array{0: string, 1: string}> */
    public static function escHtmlProvider(): array
    {
        return [
            'ampersand'            => ['Hello & World',          'Hello &amp; World'],
            'double quote'         => ['"quoted"',               '&quot;quoted&quot;'],
            'single quote'         => ["it's fine",              'it&#039;s fine'],
            'less than'            => ['1 < 2',                  '1 &lt; 2'],
            'greater than'         => ['2 > 1',                  '2 &gt; 1'],
            'script tag'           => ['<script>alert(1)</script>', '&lt;script&gt;alert(1)&lt;/script&gt;'],
            'plain text noop'      => ['Hello World',            'Hello World'],
            'empty string'         => ['',                       ''],
            'multibyte preserved'  => ['日本語',                 '日本語'],
            'combined xss'         => ['"><img src=x onerror=alert(1)>', '&quot;&gt;&lt;img src=x onerror=alert(1)&gt;'],
        ];
    }

    #[DataProvider('escHtmlProvider')]
    public function testEscHtml(string $input, string $expected): void
    {
        $this->assertSame($expected, HtmlEscaper::escHtml($input));
    }

    // -------------------------------------------------------------------------
    // escAttr — same encoding, different semantic intent
    // -------------------------------------------------------------------------

    public function testEscAttrEncodesQuotes(): void
    {
        $result = HtmlEscaper::escAttr('" onmouseover="alert(1)"');
        $this->assertStringNotContainsString('"', $result);
        $this->assertStringNotContainsString("'", $result);
    }

    public function testEscAttrSafeForHtmlAttribute(): void
    {
        $value  = 'value with <special> chars & "quotes"';
        $result = HtmlEscaper::escAttr($value);
        $this->assertStringNotContainsString('"quotes"', $result);
        $this->assertStringContainsString('&lt;special&gt;', $result);
        $this->assertStringContainsString('&amp;', $result);
        $this->assertMatchesRegularExpression('/&quot;|&#034;/', $result);
    }

    // -------------------------------------------------------------------------
    // escTextarea
    // -------------------------------------------------------------------------

    public function testEscTextareaPreservesNewlines(): void
    {
        $input  = "line one\nline two";
        $result = HtmlEscaper::escTextarea($input);
        $this->assertStringContainsString("\n", $result);
    }

    public function testEscTextareaEncodesHtml(): void
    {
        $result = HtmlEscaper::escTextarea('<script>alert(1)</script>');
        $this->assertStringNotContainsString('<script>', $result);
    }

    // -------------------------------------------------------------------------
    // decodeEntities
    // -------------------------------------------------------------------------

    public function testDecodeEntitiesRoundTrip(): void
    {
        $original = 'Hello & "World" <test>';
        $encoded  = HtmlEscaper::escHtml($original);
        $decoded  = HtmlEscaper::decodeEntities($encoded);
        $this->assertSame($original, $decoded);
    }
}
