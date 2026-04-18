<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Tests\Utils;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Piplup\Sanitize\Utils\StringUtils;

final class StringUtilsTest extends TestCase
{
    // -------------------------------------------------------------------------
    // removeAccents
    // -------------------------------------------------------------------------

    /** @return array<string, array{0: string, 1: string}> */
    public static function accentProvider(): array
    {
        return [
            'é → e'          => ['café',          'cafe'],
            'ü → u'          => ['über',           'uber'],
            'ñ → n'          => ['España',         'Espana'],
            'ß → ss'         => ['Straße',         'Strasse'],
            'Ø → O'          => ['Børn',           'Born'],
            'Æ → AE'         => ['Ærø',            'AEro'],
            'ASCII unchanged' => ['hello world',   'hello world'],
            'empty string'   => ['',               ''],
        ];
    }

    #[DataProvider('accentProvider')]
    public function testRemoveAccents(string $input, string $expected): void
    {
        $this->assertSame($expected, StringUtils::removeAccents($input));
    }

    // -------------------------------------------------------------------------
    // stripAllTags
    // -------------------------------------------------------------------------

    public function testStripAllTagsRemovesHtml(): void
    {
        $this->assertSame('Hello World', StringUtils::stripAllTags('<b>Hello</b> World'));
    }

    public function testStripAllTagsRemovesScriptContent(): void
    {
        $result = StringUtils::stripAllTags('<script>alert(1)</script>text');
        $this->assertStringNotContainsString('alert', $result);
        $this->assertStringContainsString('text', $result);
    }

    public function testStripAllTagsRemovesStyleContent(): void
    {
        $result = StringUtils::stripAllTags('<style>body{color:red}</style>text');
        $this->assertStringNotContainsString('color', $result);
    }

    public function testStripAllTagsDecodesEntities(): void
    {
        $result = StringUtils::stripAllTags('Hello &amp; World');
        $this->assertSame('Hello & World', $result);
    }

    public function testStripAllTagsPreservesMultilineWithTrimLines(): void
    {
        $html   = "<p>line one</p>\n<p>line two</p>";
        $result = StringUtils::stripAllTags($html, true);
        $this->assertStringContainsString('line one', $result);
        $this->assertStringContainsString('line two', $result);
    }

    // -------------------------------------------------------------------------
    // truncate
    // -------------------------------------------------------------------------

    public function testTruncateShortStringUnchanged(): void
    {
        $this->assertSame('hello', StringUtils::truncate('hello', 10));
    }

    public function testTruncateLongStringCut(): void
    {
        $result = StringUtils::truncate('Hello World', 8);
        $this->assertSame(8, mb_strlen($result, 'UTF-8'));
        $this->assertStringContainsString('…', $result);
    }

    public function testTruncateMultibyteString(): void
    {
        // Each Japanese character is 1 char, 3 bytes
        $result = StringUtils::truncate('日本語テスト', 4);
        $this->assertLessThanOrEqual(4, mb_strlen($result, 'UTF-8'));
    }

    public function testTruncateZeroLimitReturnsEmpty(): void
    {
        $this->assertSame('', StringUtils::truncate('hello', 0));
    }

    public function testTruncateExactLimitUnchanged(): void
    {
        $this->assertSame('hello', StringUtils::truncate('hello', 5));
    }

    // -------------------------------------------------------------------------
    // startsWith / endsWith
    // -------------------------------------------------------------------------

    public function testStartsWithTrue(): void
    {
        $this->assertTrue(StringUtils::startsWith('Hello World', 'Hello'));
    }

    public function testStartsWithFalse(): void
    {
        $this->assertFalse(StringUtils::startsWith('Hello World', 'World'));
    }

    public function testEndsWithTrue(): void
    {
        $this->assertTrue(StringUtils::endsWith('Hello World', 'World'));
    }

    public function testEndsWithFalse(): void
    {
        $this->assertFalse(StringUtils::endsWith('Hello World', 'Hello'));
    }
}
