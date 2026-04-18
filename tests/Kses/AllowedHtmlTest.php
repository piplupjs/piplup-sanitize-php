<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Tests\Kses;

use PHPUnit\Framework\TestCase;
use Piplup\Sanitize\Kses\AllowedHtml;
use Piplup\Sanitize\Kses\Kses;

final class AllowedHtmlTest extends TestCase
{
    public function testPostPresetAllowsHeadings(): void
    {
        $html   = '<h2 class="title">Heading</h2>';
        $result = Kses::filter($html, AllowedHtml::post());
        $this->assertStringContainsString('<h2', $result);
        $this->assertStringContainsString('class=', $result);
    }

    public function testDataPresetStripsDiv(): void
    {
        $html   = '<div class="wrapper"><em>text</em></div>';
        $result = Kses::filter($html, AllowedHtml::data());
        $this->assertStringNotContainsString('<div', $result);
        $this->assertStringContainsString('<em>', $result);
    }

    public function testEmptyHtmlReturnsEmpty(): void
    {
        $this->assertSame('', Kses::filter('', AllowedHtml::post()));
    }

    public function testPlainTextPassesThroughPost(): void
    {
        $text   = 'Just plain text with no HTML.';
        $result = Kses::filter($text, AllowedHtml::post());
        $this->assertStringContainsString($text, $result);
    }
}
