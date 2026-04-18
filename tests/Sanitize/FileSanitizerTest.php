<?php

declare(strict_types=1);

namespace Piplup\Sanitize\Tests\Sanitize;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Piplup\Sanitize\Sanitize\FileSanitizer;

final class FileSanitizerTest extends TestCase
{
    /** @return array<string, array{0: string, 1: string}> */
    public static function fileNameProvider(): array
    {
        return [
            'simple'                  => ['photo.jpg',                   'photo.jpg'],
            'spaces to hyphens'       => ['my photo.jpg',                'my-photo.jpg'],
            'uppercase extension'     => ['photo.JPG',                   'photo.jpg'],
            'path traversal ../'      => ['../../etc/passwd',            'etcpasswd'],
            'path traversal backslash'=> ['..\\..\\windows\\system32',   'windowssystem32'],
            'null bytes'              => ["hello\x00.txt",               'hello.txt'],
            'forbidden chars'         => ['my:file?.txt',                'myfile.txt'],
            'windows reserved CON'    => ['CON.txt',                     '_CON.txt'],
            'windows reserved NUL'    => ['NUL',                         '_NUL'],
            'windows reserved COM1'   => ['COM1.log',                    '_COM1.log'],
            'consecutive dots'        => ['my..file.txt',                'my-file.txt'],
            'leading dot (hidden)'    => ['.htaccess',                   'htaccess'],
            'no extension'            => ['README',                      'README'],
            'multiple extensions'     => ['archive.tar.gz',              'archive.tar.gz'],
            'empty name'              => ['',                            'file'],
            'only forbidden'          => ['???',                         'file'],
            'unicode filename'         => ['фото.jpg',                   'file.jpg'],  // non-ASCII base stripped → fallback 'file'
            'long extension'          => ['file.php5',                   'file.php5'],
            'double dangerous ext'     => ['shell.php.jpg',               'shell.jpg'],
            'double dangerous ext 2'   => ['evil.php5.png',               'evil.png'],
        ];
    }

    #[DataProvider('fileNameProvider')]
    public function testSanitizeFileName(string $input, string $expected): void
    {
        $this->assertSame($expected, FileSanitizer::sanitizeFileName($input));
    }

    public function testSanitizeFileNameDoesNotContainSlash(): void
    {
        $result = FileSanitizer::sanitizeFileName('path/to/file.txt');
        $this->assertStringNotContainsString('/', $result);
    }

    public function testSanitizeFileNameDoesNotContainNullByte(): void
    {
        $result = FileSanitizer::sanitizeFileName("file\x00name.txt");
        $this->assertStringNotContainsString("\x00", $result);
    }

    public function testSanitizeFileNameAlwaysReturnsString(): void
    {
        $this->assertIsString(FileSanitizer::sanitizeFileName(''));
    }
}
