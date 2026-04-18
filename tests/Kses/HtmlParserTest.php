<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Tests\Kses;

use PHPUnit\Framework\TestCase;
use Piplup\Sanitize\Kses\HtmlParser;

final class HtmlParserTest extends TestCase
{
    public function testSerializeReturnsEmptyWhenRootMissing(): void
    {
        $doc = new \DOMDocument('1.0', 'UTF-8');
        $this->assertSame('', HtmlParser::serialize($doc));
    }

    public function testParseSerializePreservesEntitiesAndTags(): void
    {
        $html = '<b>1 &amp; 2</b><i>more</i>';
        $doc = HtmlParser::parse($html);
        $result = HtmlParser::serialize($doc);

        $this->assertStringContainsString('<b', $result);
        $this->assertStringContainsString('&amp;', $result);
        $this->assertStringContainsString('<i', $result);
        $this->assertStringContainsString('more', $result);
    }

    public function testWalkProcessesDeepestNodesFirst(): void
    {
        $html = '<div><b>text</b></div>';
        $doc = HtmlParser::parse($html);

        $order = [];
        HtmlParser::walk($doc, function (\DOMElement $node) use (&$order): void {
            if ($node->hasAttribute('id') && $node->getAttribute('id') === '__kses_root__') {
                return;
            }
            $order[] = strtolower($node->tagName);
        });

        $this->assertSame(['b', 'div'], $order);
    }

    public function testParseHandlesInvalidUtf8Gracefully(): void
    {
        // Intentionally malformed UTF-8 sequence (invalid continuation)
        $html = "bad\xC3\x28input";
        $doc = HtmlParser::parse($html);
        $result = HtmlParser::serialize($doc);

        $this->assertIsString($result);
        $this->assertTrue(mb_check_encoding($result, 'UTF-8'));
        $this->assertStringContainsString('bad', $result);
        $this->assertStringContainsString('input', $result);
    }
}
