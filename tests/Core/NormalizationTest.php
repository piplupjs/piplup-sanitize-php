<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Tests\Core;

use PHPUnit\Framework\TestCase;
use Piplup\Sanitize\Core\Normalization;

final class NormalizationTest extends TestCase
{
    public function testNormalizeLineEndingsCRLF(): void
    {
        $this->assertSame("line1\nline2", Normalization::normalizeLineEndings("line1\r\nline2"));
    }

    public function testNormalizeLineEndingsCR(): void
    {
        $this->assertSame("line1\nline2", Normalization::normalizeLineEndings("line1\rline2"));
    }

    public function testNormalizeLineEndingsLFNoop(): void
    {
        $this->assertSame("line1\nline2", Normalization::normalizeLineEndings("line1\nline2"));
    }

    public function testCollapseWhitespaceMultipleSpaces(): void
    {
        $this->assertSame('hello world', Normalization::collapseWhitespace('  hello   world  '));
    }

    public function testCollapseWhitespaceTabs(): void
    {
        $this->assertSame('a b', Normalization::collapseWhitespace("a\t\tb"));
    }

    public function testRemoveAllWhitespace(): void
    {
        $this->assertSame('helloworld', Normalization::removeAllWhitespace("hello \t world\n"));
    }

    public function testTrimUnicodeNonBreakingSpace(): void
    {
        $nbsp  = "\u{00A0}";
        $zwsp  = "\u{200B}";
        $value = $nbsp . $zwsp . 'text' . $zwsp . $nbsp;
        $this->assertSame('text', Normalization::trimUnicode($value));
    }

    public function testToLowerMultibyte(): void
    {
        $this->assertSame('über', Normalization::toLower('ÜBER'));
    }

    public function testToUpperMultibyte(): void
    {
        $this->assertSame('ÜBER', Normalization::toUpper('über'));
    }

    public function testCleanCombinesAll(): void
    {
        $input  = "  Hello\x00\x07  World  ";
        $result = Normalization::clean($input);
        $this->assertSame('Hello World', $result);
    }
}
