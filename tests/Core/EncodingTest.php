<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Tests\Core;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Piplup\Sanitize\Core\Encoding;

final class EncodingTest extends TestCase
{
    public function testToUtf8PreservesValidUtf8(): void
    {
        $input = 'café';
        $this->assertSame($input, Encoding::toUtf8($input));
        $this->assertTrue(Encoding::isValidUtf8($input));
    }

    public function testToUtf8RepairsInvalidSequences(): void
    {
        $input = "bad\xC3\x28input"; // malformed UTF-8
        $out = Encoding::toUtf8($input);

        $this->assertIsString($out);
        $this->assertTrue(mb_check_encoding($out, 'UTF-8'));
        $this->assertStringContainsString('bad', $out);
        $this->assertStringContainsString('input', $out);
    }

    public function testToUtf8ReturnsValidAsciiUnchanged(): void
    {
        $this->assertSame('Hello World', Encoding::toUtf8('Hello World'));
    }

    public function testToUtf8ReturnsValidMultibyteUnchanged(): void
    {
        $this->assertSame('こんにちは', Encoding::toUtf8('こんにちは'));
    }

    public function testToUtf8EmptyStringReturnsEmpty(): void
    {
        $this->assertSame('', Encoding::toUtf8(''));
    }

    public function testIsValidUtf8TrueForAscii(): void
    {
        $this->assertTrue(Encoding::isValidUtf8('abc123'));
    }

    public function testIsValidUtf8TrueForMultibyte(): void
    {
        $this->assertTrue(Encoding::isValidUtf8('Ü ö ñ'));
    }

    public function testIsValidUtf8FalseForInvalidBytes(): void
    {
        $this->assertFalse(Encoding::isValidUtf8("\x80\x81"));
    }

    public function testStripNullBytesRemovesNuls(): void
    {
        $input = "hel\x00lo";
        $this->assertSame('hello', Encoding::stripNullBytes($input));
    }

    #[DataProvider('controlCharProvider')]
    public function testStripControlCharactersRemovesGivenChar(string $input, string $expected): void
    {
        $this->assertSame($expected, Encoding::stripControlCharacters($input));
    }

    public static function controlCharProvider(): array
    {
        return [
            'BEL (0x07)'   => ["hel\x07lo", 'hello'],
            'ESC (0x1B)'   => ["es\x1Bcape", 'escape'],
            'DEL (0x7F)'   => ["de\x7Flete", 'delete'],
            'keeps tab'    => ["ta\tbs", "ta\tbs"],
            'keeps LF'     => ["new\nline", "new\nline"],
            'keeps CR'     => ["car\rriage", "car\rriage"],
        ];
    }

    public function testByteLengthVsCharLength(): void
    {
        $value = 'héllo'; // é is 2 bytes in UTF-8
        $this->assertSame(6, Encoding::byteLength($value));
        $this->assertSame(5, Encoding::charLength($value));
    }
}
