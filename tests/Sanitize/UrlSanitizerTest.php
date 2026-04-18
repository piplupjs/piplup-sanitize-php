<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Tests\Sanitize;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Piplup\Sanitize\Sanitize\UrlSanitizer;

final class UrlSanitizerTest extends TestCase
{
    // -------------------------------------------------------------------------
    // escUrl — dangerous protocols must return empty string
    // -------------------------------------------------------------------------

    /** @return array<string, array{0: string}> */
    public static function dangerousUrlProvider(): array
    {
        return [
            'javascript'                => ['javascript:alert(1)'],
            'javascript uppercase'      => ['JAVASCRIPT:alert(1)'],
            'javascript with spaces'    => ['java script:alert(1)'],
            'javascript entity encoded' => ['javascript&#58;alert(1)'],
            'data uri'                  => ['data:text/html,<script>alert(1)</script>'],
            'vbscript'                  => ['vbscript:MsgBox(1)'],
        ];
    }

    #[DataProvider('dangerousUrlProvider')]
    public function testEscUrlRejectsDangerousProtocols(string $url): void
    {
        $this->assertSame('', UrlSanitizer::escUrl($url));
    }

    // -------------------------------------------------------------------------
    // escUrl — valid URLs must survive
    // -------------------------------------------------------------------------

    /** @return array<string, array{0: string}> */
    public static function validUrlProvider(): array
    {
        return [
            'http'         => ['http://example.com'],
            'https'        => ['https://example.com/path?q=1#anchor'],
            'ftp'          => ['ftp://files.example.com/file.zip'],
            'mailto'       => ['mailto:user@example.com'],
            'relative'     => ['/path/to/page'],
            'root-relative'=> ['//example.com/path'],
        ];
    }

    #[DataProvider('validUrlProvider')]
    public function testEscUrlAllowsValidUrls(string $url): void
    {
        $result = UrlSanitizer::escUrl($url);
        $this->assertNotSame('', $result, "Expected non-empty result for: {$url}");
    }

    public function testEscUrlHtmlEncodesAmpersands(): void
    {
        $result = UrlSanitizer::escUrl('https://example.com/?a=1&b=2');
        $this->assertStringContainsString('&amp;', $result);
    }

    public function testEscUrlHtmlEncodesQuotes(): void
    {
        $result = UrlSanitizer::escUrl('https://example.com/?q="test"');
        $this->assertStringNotContainsString('"', $result);
    }

    // -------------------------------------------------------------------------
    // escUrlRaw — no HTML encoding
    // -------------------------------------------------------------------------

    public function testEscUrlRawDoesNotEncodeAmpersand(): void
    {
        $result = UrlSanitizer::escUrlRaw('https://example.com/?a=1&b=2');
        $this->assertStringContainsString('&', $result);
        $this->assertStringNotContainsString('&amp;', $result);
    }

    public function testEscUrlRawRejectsDangerousProtocol(): void
    {
        $this->assertSame('', UrlSanitizer::escUrlRaw('javascript:void(0)'));
    }

    // -------------------------------------------------------------------------
    // Custom allowed protocols
    // -------------------------------------------------------------------------

    public function testEscUrlRejectsHttpWhenNotInCustomAllowList(): void
    {
        $result = UrlSanitizer::escUrl('http://example.com', ['https']);
        $this->assertSame('', $result);
    }

    public function testEscUrlAllowsCustomProtocol(): void
    {
        $result = UrlSanitizer::escUrl('myapp://deep-link', ['myapp']);
        $this->assertNotSame('', $result);
    }

    // -------------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------------

    public function testEscUrlEmptyString(): void
    {
        $this->assertSame('', UrlSanitizer::escUrl(''));
    }

    public function testEscUrlStripsNullBytes(): void
    {
        $result = UrlSanitizer::escUrl("https://example.com/\x00path");
        $this->assertStringNotContainsString("\x00", $result);
    }

    /** @return array<string, array{0: string}> */
    public static function obfuscatedDangerousProvider(): array
    {
        return [
            'entity hex'    => ['javascript&#x3A;alert(1)'],
            'entity decimal'=> ['javascript&#58;alert(1)'],
            'newline entity' => ['java&#10;script:alert(1)'],
            'carriage return entity' => ['java&#13;script:alert(1)'],
            'mixed case with entity' => ['JaVaScRiPt&#58;alert(1)'],
        ];
    }

    #[DataProvider('obfuscatedDangerousProvider')]
    public function testEscUrlRejectsEntityObfuscatedProtocols(string $url): void
    {
        $this->assertSame('', UrlSanitizer::escUrl($url));
        $this->assertSame('', UrlSanitizer::escUrlRaw($url));
    }

    public function testEscUrlPercentEncodesUnicodeCharacters(): void
    {
        $result = UrlSanitizer::escUrlRaw('https://example.com/äöü');
        $this->assertStringContainsString('%C3%A4', $result);
        $this->assertStringContainsString('%C3%B6', $result);
        $this->assertStringContainsString('%C3%BC', $result);
    }
}
