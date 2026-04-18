<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Tests\Sanitize;

use PHPUnit\Framework\TestCase;
use Piplup\Sanitize\Sanitize\CssSanitizer;

final class CssSanitizerTest extends TestCase
{
    public function testAllowsSimpleProperties(): void
    {
        $css = 'color: red; font-size: 12px;';
        $out = CssSanitizer::sanitize($css);
        $this->assertStringContainsString('color: red', $out);
        $this->assertStringContainsString('font-size: 12px', $out);
    }

    public function testRemovesJavascriptUrl(): void
    {
        $css = 'background: url(javascript:alert(1));';
        $this->assertSame('', CssSanitizer::sanitize($css));
    }

    public function testDecodesEntitiesAndRemoves(): void
    {
        $css = 'background: url(j&#097;vascript:alert(1));';
        $this->assertSame('', CssSanitizer::sanitize($css));
    }

    public function testAllowsHttpUrl(): void
    {
        $css = 'background: url("https://example.com/bg.png");';
        $out = CssSanitizer::sanitize($css);
        $this->assertStringContainsString('https://example.com/bg.png', $out);
    }

    public function testRemovesExpressionBehavior(): void
    {
        $this->assertSame('', CssSanitizer::sanitize('width: expression(alert(1));'));
        $this->assertSame('', CssSanitizer::sanitize('width: behavior:url(evil.htc);'));
    }

    public function testAllowsBackgroundSizeAndPosition(): void
    {
        $css = 'background-size: cover; background-position: center center;';
        $out = CssSanitizer::sanitize($css);
        $this->assertStringContainsString('background-size: cover', $out);
        $this->assertStringContainsString('background-position: center center', $out);
    }

    public function testAllowsBorderRadiusAndBoxShadow(): void
    {
        $css = 'border-radius: 4px; box-shadow: 0 0 5px #000;';
        $out = CssSanitizer::sanitize($css);
        $this->assertStringContainsString('border-radius: 4px', $out);
        $this->assertStringContainsString('box-shadow: 0 0 5px #000', $out);
    }

    public function testRemovesDataUrl(): void
    {
        $css = 'background-image: url("data:image/png;base64,AAAA");';
        $this->assertSame('', CssSanitizer::sanitize($css));
    }

    public function testSanitizesCursorUrl(): void
    {
        $css = 'cursor: url("https://example.com/cursor.cur"), auto;';
        $out = CssSanitizer::sanitize($css);
        $this->assertStringContainsString('https://example.com/cursor.cur', $out);
    }

    public function testAllowsTransformAndPosition(): void
    {
        $css = 'position: absolute; top: 0; left: 0; transform: rotate(45deg);';
        $out = CssSanitizer::sanitize($css);
        $this->assertStringContainsString('position: absolute', $out);
        $this->assertStringContainsString('transform: rotate(45deg)', $out);
    }

    public function testAllowsRgbaColors(): void
    {
        $css = 'color: rgba(255,0,0,0.5);';
        $out = CssSanitizer::sanitize($css);
        $this->assertStringContainsString('color: rgba(255,0,0,0.5)', $out);
    }

    public function testRemovesNestedJavascriptUrl(): void
    {
        $css = 'background-image: url("url(javascript:alert(1))");';
        $this->assertSame('', CssSanitizer::sanitize($css));
    }

    public function testDropsDeclarationIfAnyUrlUnsafe(): void
    {
        $css = 'background-image: url("https://example.com/a.png"), url("javascript:alert(1)");';
        $out = CssSanitizer::sanitize($css);
        $this->assertStringContainsString('https://example.com/a.png', $out);
        $this->assertStringNotContainsString('javascript:alert', $out);
    }

    public function testKeepsMultipleSafeUrls(): void
    {
        $css = 'background-image: url("https://example.com/a.png"), url("https://example.com/b.png");';
        $out = CssSanitizer::sanitize($css);
        $this->assertStringContainsString('https://example.com/a.png', $out);
        $this->assertStringContainsString('https://example.com/b.png', $out);
    }

    public function testRemovesDataUrlAmongMultiple(): void
    {
        $css = 'background-image: url("data:image/png;base64,AAAA"), url("https://example.com/b.png");';
        $out = CssSanitizer::sanitize($css);
        $this->assertStringContainsString('https://example.com/b.png', $out);
        $this->assertStringNotContainsString('data:image', $out);
    }
}
