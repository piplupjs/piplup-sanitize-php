<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Tests\Escape;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Piplup\Sanitize\Escape\JsEscaper;

final class JsEscaperTest extends TestCase
{
    // -------------------------------------------------------------------------
    // escJs
    // -------------------------------------------------------------------------

    /** @return array<string, array{0: string, 1: string}> */
    public static function escJsProvider(): array
    {
        return [
            'plain text noop'      => ['hello world',     'hello world'],
            'single quote escaped' => ["it's here",       "it\\'s here"],
            'double quote escaped' => ['"quoted"',        '\\"quoted\\"'],
            'backslash escaped'    => ['path\\to\\file',  'path\\\\to\\\\file'],
            'newline escaped'      => ["line1\nline2",    'line1\\nline2'],
            'carriage return'      => ["line1\rline2",    'line1\\rline2'],
            'tab escaped'          => ["col1\tcol2",      'col1\\tcol2'],
            'empty string'         => ['',                ''],
        ];
    }

    #[DataProvider('escJsProvider')]
    public function testEscJs(string $input, string $expected): void
    {
        $this->assertSame($expected, JsEscaper::escJs($input));
    }

    public function testEscJsClosingScriptTagEscaped(): void
    {
        $result = JsEscaper::escJs('</script>');
        // The closing tag must not survive intact
        $this->assertStringNotContainsString('</script>', $result);
    }

    public function testEscJsUnicodeSeparatorsEscaped(): void
    {
        // U+2028 Line Separator and U+2029 Paragraph Separator break JS strings
        $result = JsEscaper::escJs("\u{2028}");
        $this->assertStringNotContainsString("\u{2028}", $result);

        $result = JsEscaper::escJs("\u{2029}");
        $this->assertStringNotContainsString("\u{2029}", $result);
    }

    public function testEscJsOutputSafeInSingleQuotedJsString(): void
    {
        // If we embed the output in a single-quoted JS string, no breakout possible
        $malicious = "'; alert(1); var x='";
        $escaped   = JsEscaper::escJs($malicious);
        $jsString  = "var x='" . $escaped . "';";
        // The injected single quotes should be escaped
        // Count unescaped single quotes — should be exactly 2 (the outer delimiters)
        $unescapedSingleQuotes = preg_match_all("/(?<!\\\\)'/", $jsString);
        $this->assertSame(2, $unescapedSingleQuotes);
    }

    public function testEscJsEscapesBacktickAndTemplateExpressions(): void
    {
        $input = "hello`+alert(document.cookie)+`";
        $result = JsEscaper::escJs($input);
        $this->assertStringContainsString('\\`', $result);
        $this->assertStringNotContainsString('`', str_replace('\\`', '', $result));

        $input2 = '${alert(1)}';
        $result2 = JsEscaper::escJs($input2);
        $this->assertStringContainsString('\\${', $result2);
        $this->assertStringNotContainsString('${', str_replace('\\${', '', $result2));
    }

    // -------------------------------------------------------------------------
    // jsonEncode
    // -------------------------------------------------------------------------

    public function testJsonEncodeArray(): void
    {
        $result = JsEscaper::jsonEncode(['key' => 'value', 'num' => 42]);
        $decoded = json_decode($result, true);
        $this->assertSame(['key' => 'value', 'num' => 42], $decoded);
    }

    public function testJsonEncodeEscapesHtmlTags(): void
    {
        $result = JsEscaper::jsonEncode('<script>alert(1)</script>');
        $this->assertStringNotContainsString('<script>', $result);
        $this->assertStringNotContainsString('</script>', $result);
    }

    public function testJsonEncodeNull(): void
    {
        $this->assertSame('null', JsEscaper::jsonEncode(null));
    }

    public function testJsonEncodeScalar(): void
    {
        $this->assertSame('42', JsEscaper::jsonEncode(42));
        $this->assertSame('true', JsEscaper::jsonEncode(true));
    }
}
