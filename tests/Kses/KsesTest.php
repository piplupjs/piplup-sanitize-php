<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Tests\Kses;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Piplup\Sanitize\Kses\AllowedHtml;
use Piplup\Sanitize\Kses\Kses;

final class KsesTest extends TestCase
{
    // -------------------------------------------------------------------------
    // Basic tag filtering
    // -------------------------------------------------------------------------

    public function testAllowedTagPassesThrough(): void
    {
        $html   = '<b>bold text</b>';
        $result = Kses::filter($html, ['b' => []]);
        $this->assertStringContainsString('<b>', $result);
        $this->assertStringContainsString('bold text', $result);
    }

    public function testDisallowedTagIsStripped(): void
    {
        $html   = '<script>alert(1)</script>';
        $result = Kses::filter($html, ['b' => []]);
        $this->assertStringNotContainsString('<script>', $result);
        $this->assertStringNotContainsString('alert(1)', $result);
    }

    public function testDisallowedTagPreservesTextContent(): void
    {
        // Text inside a stripped tag should survive as text
        $html   = '<div>some text</div>';
        $result = Kses::filter($html, []);
        $this->assertStringContainsString('some text', $result);
        $this->assertStringNotContainsString('<div>', $result);
    }

    public function testAllowedAttributePassesThrough(): void
    {
        $html   = '<a href="https://example.com">link</a>';
        $result = Kses::filter($html, ['a' => ['href' => true]]);
        $this->assertStringContainsString('href=', $result);
    }

    public function testDisallowedAttributeIsStripped(): void
    {
        $html   = '<a href="https://example.com" data-evil="bad">link</a>';
        $result = Kses::filter($html, ['a' => ['href' => true]]);
        $this->assertStringNotContainsString('data-evil', $result);
        $this->assertStringContainsString('href=', $result);
    }

    // -------------------------------------------------------------------------
    // Event handlers always blocked
    // -------------------------------------------------------------------------

    /** @return array<string, array{0: string}> */
    public static function eventHandlerProvider(): array
    {
        return [
            'onclick'      => ['<a href="#" onclick="alert(1)">click</a>'],
            'onmouseover'  => ['<span onmouseover="steal()">hover</span>'],
            'onerror'      => ['<img src="x" onerror="alert(1)">'],
            'onload'       => ['<body onload="evil()">'],
            'onfocus'      => ['<input onfocus="bad()">'],
            'ONCLICK upper'=> ['<a ONCLICK="alert(1)">click</a>'],
        ];
    }

    #[DataProvider('eventHandlerProvider')]
    public function testEventHandlersAlwaysStripped(string $html): void
    {
        $result = Kses::filter($html, AllowedHtml::post());
        // The on* attribute should not appear in output
        $this->assertDoesNotMatchRegularExpression('/\bon\w+\s*=/i', $result);
    }

    // -------------------------------------------------------------------------
    // XSS payloads
    // -------------------------------------------------------------------------

    /** @return array<string, array{0: string}> */
    public static function xssPayloadProvider(): array
    {
        return [
            'script tag'            => ['<script>alert("xss")</script>'],
            'javascript href'       => ['<a href="javascript:alert(1)">click</a>'],
            'data uri img'          => ['<img src="data:text/html,<script>alert(1)</script>">'],
            'vbscript href'         => ['<a href="vbscript:MsgBox(1)">click</a>'],
            'svg with script'       => ['<svg><script>alert(1)</script></svg>'],
            'iframe'                => ['<iframe src="https://evil.com"></iframe>'],
            'style with expression' => ['<div style="behavior:url(evil.htc)">x</div>'],
            'img onerror'           => ['<img src=x onerror=alert(1)>'],
            'meta refresh'          => ['<meta http-equiv="refresh" content="0;url=javascript:alert(1)">'],
            'form action js'        => ['<form action="javascript:alert(1)"></form>'],
            'object tag'            => ['<object data="evil.swf"></object>'],
            'embed tag'             => ['<embed src="evil.swf">'],
        ];
    }

    #[DataProvider('xssPayloadProvider')]
    public function testXssPayloadsBlocked(string $html): void
    {
        $result = Kses::filter($html, AllowedHtml::post());
        // No script execution vectors should survive
        $this->assertDoesNotMatchRegularExpression('/javascript\s*:/i', $result);
        $this->assertDoesNotMatchRegularExpression('/<script/i', $result);
        $this->assertDoesNotMatchRegularExpression('/vbscript\s*:/i', $result);
    }

    // -------------------------------------------------------------------------
    // URL attributes sanitized
    // -------------------------------------------------------------------------

    public function testJavascriptHrefStripped(): void
    {
        $html   = '<a href="javascript:alert(1)">click</a>';
        $result = Kses::filter($html, AllowedHtml::post());
        $this->assertStringNotContainsString('javascript:', $result);
    }

    public function testValidHrefPreserved(): void
    {
        $html   = '<a href="https://example.com">link</a>';
        $result = Kses::filter($html, AllowedHtml::post());
        $this->assertStringContainsString('https://example.com', $result);
    }

    // -------------------------------------------------------------------------
    // Malformed / adversarial HTML
    // -------------------------------------------------------------------------

    public function testMalformedTagsHandledGracefully(): void
    {
        $html   = '<b>unclosed <i>nested';
        $result = Kses::filter($html, AllowedHtml::post());
        // Should not throw; output should contain the text
        $this->assertStringContainsString('unclosed', $result);
        $this->assertStringContainsString('nested', $result);
    }

    public function testNullBytesInHtml(): void
    {
        $html   = "<b>hel\x00lo</b>";
        $result = Kses::filter($html, AllowedHtml::post());
        $this->assertStringNotContainsString("\x00", $result);
    }

    // -------------------------------------------------------------------------
    // Backtick / malformed attributes
    // -------------------------------------------------------------------------

    public function testBacktickDelimitedAttributeIsSanitized(): void
    {
        $html = '<img src=`javascript:alert(1)` alt="x">';
        $result = Kses::filter($html, AllowedHtml::post());

        $this->assertStringNotContainsString('javascript:', strtolower($result));
        $this->assertStringNotContainsString('src=', $result);
    }

    public function testDoubleAngleScriptRemoved(): void
    {
        $html = '<<SCRIPT>alert(1)//<</SCRIPT>';
        $result = Kses::filter($html, AllowedHtml::post());

        $this->assertDoesNotMatchRegularExpression('/<script/i', $result);
        $this->assertStringNotContainsString('javascript:', strtolower($result));
    }

    // -------------------------------------------------------------------------
    // Obfuscated / encoded hrefs
    // -------------------------------------------------------------------------

    public function testEntityEncodedJavascriptHrefStripped(): void
    {
        $html = '<a href="javascript&#58;alert(1)">click</a>';
        $result = Kses::filter($html, AllowedHtml::post());

        $this->assertStringNotContainsString('javascript:', $result);
        $this->assertStringNotContainsString('href="javascript', $result);
    }

    public function testWhitespaceObfuscatedJavascriptHrefStripped(): void
    {
        $html = '<a href="java script:alert(1)">click</a>';
        $result = Kses::filter($html, AllowedHtml::post());

        $this->assertStringNotContainsString('javascript:', $result);
        $this->assertStringNotContainsString('href=', $result);
    }

    public function testMixedCaseJavascriptHrefStripped(): void
    {
        $html = '<a href="JaVaScRiPt:alert(1)">click</a>';
        $result = Kses::filter($html, AllowedHtml::post());

        $this->assertStringNotContainsString('javascript:', strtolower($result));
    }

    // -------------------------------------------------------------------------
    // Style attributes & tags
    // -------------------------------------------------------------------------

    public function testRemovesJavascriptUrlInStyle(): void
    {
        $html = '<div style="background:url(javascript:alert(1))">x</div>';
        $result = Kses::filter($html, AllowedHtml::post());

        $this->assertStringNotContainsString('javascript:', strtolower($result));
        $this->assertStringNotContainsString('style=', $result);
    }

    public function testRemovesExpressionInStyle(): void
    {
        $html = '<div style="width:expression(alert(1))">x</div>';
        $result = Kses::filter($html, AllowedHtml::post());

        $this->assertStringNotContainsString('expression(', strtolower($result));
        $this->assertStringNotContainsString('style=', $result);
    }

    public function testKeepsSafeStyle(): void
    {
        $html = '<div style="color: red; font-size: 12px;">ok</div>';
        $result = Kses::filter($html, AllowedHtml::post());

        $this->assertStringContainsString('style=', $result);
        $this->assertStringContainsString('color', $result);
    }

    public function testRemovesEntityObfuscatedCssUrl(): void
    {
        $html = '<div style="background:url(\'j&#097;vascript:alert(1)\')">x</div>';
        $result = Kses::filter($html, AllowedHtml::post());

        $this->assertStringNotContainsString('javascript:', strtolower($result));
        $this->assertStringNotContainsString('style=', $result);
    }

    public function testRemovesBehaviorUrlInStyle(): void
    {
        $html = '<div style="behavior:url(evil.htc)">x</div>';
        $result = Kses::filter($html, AllowedHtml::post());

        $this->assertStringNotContainsString('behavior:', strtolower($result));
        $this->assertStringNotContainsString('style=', $result);
    }

    public function testRemovesDataUriInCssUrl(): void
    {
        $html = '<div style="background:url(data:text/html,<script>alert(1)</script>)">x</div>';
        $result = Kses::filter($html, AllowedHtml::post());

        $this->assertStringNotContainsString('data:text/html', strtolower($result));
        $this->assertStringNotContainsString('style=', $result);
    }

    // -------------------------------------------------------------------------
    // Style tags
    // -------------------------------------------------------------------------

    public function testStyleTagRemoved(): void
    {
        $html = '<style>body{background:url("javascript:alert(1)");}</style>';
        $result = Kses::filter($html, AllowedHtml::post());

        $this->assertDoesNotMatchRegularExpression('/<style\b/i', $result);
        $this->assertStringNotContainsString('javascript:', strtolower($result));
        $this->assertStringNotContainsString('alert(1)', $result);
    }

    public function testStyleTagWithCdataRemoved(): void
    {
        $html = '<style><![CDATA[body{background:url("javascript:alert(1)");}]]></style>';
        $result = Kses::filter($html, AllowedHtml::post());

        $this->assertDoesNotMatchRegularExpression('/<style\b/i', $result);
        $this->assertStringNotContainsString('alert(1)', $result);
    }

    // -------------------------------------------------------------------------
    // SVG / CDATA
    // -------------------------------------------------------------------------

    public function testScriptCdataRemoved(): void
    {
        $html = '<svg><script><![CDATA[alert(1)]]></script></svg>';
        $result = Kses::filter($html, AllowedHtml::post());

        $this->assertDoesNotMatchRegularExpression('/<script/i', $result);
        $this->assertStringNotContainsString('alert(1)', $result);
    }

    public function testForeignObjectScriptRemoved(): void
    {
        $html = '<svg><foreignObject><script>alert(1)</script></foreignObject></svg>';
        $result = Kses::filter($html, AllowedHtml::post());

        $this->assertDoesNotMatchRegularExpression('/<script/i', $result);
        $this->assertStringNotContainsString('alert(1)', $result);
    }

    // -------------------------------------------------------------------------
    // XLink href attributes
    // -------------------------------------------------------------------------

    public function testXlinkHrefJavascriptStripped(): void
    {
        $allowed = ['use' => ['xlink:href' => true]];
        $html = '<use xlink:href="javascript:alert(1)"></use>';
        $result = Kses::filter($html, $allowed);

        $this->assertStringNotContainsString('javascript:', $result);
        $this->assertStringNotContainsString('xlink:href', $result);
    }

    public function testXlinkHrefHttpPreserved(): void
    {
        $allowed = ['use' => ['xlink:href' => true]];
        $html = '<use xlink:href="https://example.com/sprite.svg#icon"></use>';
        $result = Kses::filter($html, $allowed);

        $this->assertStringContainsString('https://example.com', $result);
        $this->assertStringContainsString('xlink:href', $result);
    }

    public function testSrcsetJavascriptStripped(): void
    {
        $allowed = AllowedHtml::post();
        $allowed['img']['srcset'] = true;

        $html = '<img srcset="javascript:alert(1) 2x">';
        $result = Kses::filter($html, $allowed);

        $this->assertStringNotContainsString('javascript:', strtolower($result));
        $this->assertStringNotContainsString('srcset=', $result);
    }

    public function testSrcsetMixedTokensKeepsSafeOnly(): void
    {
        $allowed = AllowedHtml::post();
        $allowed['img']['srcset'] = true;

        $html = '<img srcset="https://example.com/a.png 1x, javascript:alert(1) 2x">';
        $result = Kses::filter($html, $allowed);

        $this->assertStringContainsString('https://example.com/a.png', $result);
        $this->assertStringNotContainsString('javascript:', strtolower($result));
    }
}
