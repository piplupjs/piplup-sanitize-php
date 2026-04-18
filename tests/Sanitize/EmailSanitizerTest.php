<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Tests\Sanitize;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Piplup\Sanitize\Sanitize\EmailSanitizer;

final class EmailSanitizerTest extends TestCase
{
    /** @return array<string, array{0: string, 1: string}> */
    public static function emailProvider(): array
    {
        return [
            'valid simple'          => ['user@example.com',          'user@example.com'],
            'valid subdomain'       => ['user@mail.example.com',     'user@mail.example.com'],
            'uppercase normalised'  => ['USER@EXAMPLE.COM',          'user@example.com'],
            'leading whitespace'    => ['  user@example.com  ',      'user@example.com'],
            'plus addressing'       => ['user+tag@example.com',      'user+tag@example.com'],
            'dot in local'          => ['first.last@example.com',    'first.last@example.com'],
            'invalid no @'          => ['notanemail',                 ''],
            'invalid double @'      => ['user@@example.com',         ''],
            'invalid empty local'   => ['@example.com',              ''],
            'invalid empty domain'  => ['user@',                     ''],
            'invalid spaces'        => ['us er@example.com',         ''],
            'null bytes'            => ["user\x00@example.com",      ''],
            'empty string'          => ['',                           ''],
            'consecutive dots local'=> ['user..name@example.com',    ''],
        ];
    }

    #[DataProvider('emailProvider')]
    public function testSanitizeEmail(string $input, string $expected): void
    {
        $this->assertSame($expected, EmailSanitizer::sanitizeEmail($input));
    }

    public function testIsValidEmailTrue(): void
    {
        $this->assertTrue(EmailSanitizer::isValidEmail('user@example.com'));
    }

    public function testIsValidEmailFalse(): void
    {
        $this->assertFalse(EmailSanitizer::isValidEmail('not-an-email'));
    }

    public function testSanitizeEmailAlwaysReturnsString(): void
    {
        $this->assertIsString(EmailSanitizer::sanitizeEmail('anything'));
    }
}
