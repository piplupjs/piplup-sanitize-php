<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Tests\Utils;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Piplup\Sanitize\Utils\NumberUtils;

final class NumberUtilsTest extends TestCase
{
    // -------------------------------------------------------------------------
    // absint
    // -------------------------------------------------------------------------

    /** @return array<string, array{0: mixed, 1: int}> */
    public static function absintProvider(): array
    {
        return [
            'positive int'     => [5,          5],
            'negative int'     => [-5,         5],
            'zero'             => [0,           0],
            'positive float'   => [3.9,         3],
            'negative float'   => [-3.9,        3],
            'numeric string'   => ['42',        42],
            'negative string'  => ['-10',       10],
            'float string'     => ['3.7',       3],
            'empty string'     => ['',          0],
            'null'             => [null,         0],
            'true'             => [true,         1],
            'false'            => [false,        0],
            'non-numeric str'  => ['abc',        0],
        ];
    }

    #[DataProvider('absintProvider')]
    public function testAbsint(mixed $input, int $expected): void
    {
        $this->assertSame($expected, NumberUtils::absint($input));
    }

    // -------------------------------------------------------------------------
    // clampInt
    // -------------------------------------------------------------------------

    public function testClampIntWithinRange(): void
    {
        $this->assertSame(5, NumberUtils::clampInt(5, 1, 10));
    }

    public function testClampIntBelowMin(): void
    {
        $this->assertSame(1, NumberUtils::clampInt(-5, 1, 10));
    }

    public function testClampIntAboveMax(): void
    {
        $this->assertSame(10, NumberUtils::clampInt(20, 1, 10));
    }

    public function testClampIntAtBoundaries(): void
    {
        $this->assertSame(1, NumberUtils::clampInt(1, 1, 10));
        $this->assertSame(10, NumberUtils::clampInt(10, 1, 10));
    }

    // -------------------------------------------------------------------------
    // clampFloat
    // -------------------------------------------------------------------------

    public function testClampFloatWithinRange(): void
    {
        $this->assertSame(3.5, NumberUtils::clampFloat(3.5, 0.0, 5.0));
    }

    public function testClampFloatBelowMin(): void
    {
        $this->assertSame(0.0, NumberUtils::clampFloat(-1.5, 0.0, 5.0));
    }

    // -------------------------------------------------------------------------
    // isNumeric
    // -------------------------------------------------------------------------

    public function testIsNumericInteger(): void
    {
        $this->assertTrue(NumberUtils::isNumeric(42));
    }

    public function testIsNumericString(): void
    {
        $this->assertTrue(NumberUtils::isNumeric('3.14'));
    }

    public function testIsNumericFalseForText(): void
    {
        $this->assertFalse(NumberUtils::isNumeric('abc'));
    }

    // -------------------------------------------------------------------------
    // toFloat / toInt
    // -------------------------------------------------------------------------

    public function testToFloat(): void
    {
        $this->assertSame(3.14, NumberUtils::toFloat('3.14'));
        $this->assertSame(0.0, NumberUtils::toFloat('not a number'));
    }

    public function testToInt(): void
    {
        $this->assertSame(42, NumberUtils::toInt('42.9'));
        $this->assertSame(0, NumberUtils::toInt('nope'));
    }
}
