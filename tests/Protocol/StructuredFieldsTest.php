<?php

namespace DreamFactory\Core\AAuth\Tests\Protocol;

use DreamFactory\Core\AAuth\Protocol\SfBytes;
use DreamFactory\Core\AAuth\Protocol\SfToken;
use DreamFactory\Core\AAuth\Protocol\StructuredFields as SF;
use PHPUnit\Framework\TestCase;

final class StructuredFieldsTest extends TestCase
{
    public function testDictionaryBasics(): void
    {
        $d = SF::parseDictionary('a=1, b="x y", c=?0, d, e=tok;p=1;q, f=:AQID:, g=-1.5');
        $this->assertSame(1, $d['a']['value']);
        $this->assertSame('x y', $d['b']['value']);
        $this->assertFalse($d['c']['value']);
        $this->assertTrue($d['d']['value']);
        $this->assertInstanceOf(SfToken::class, $d['e']['value']);
        $this->assertSame('tok', (string) $d['e']['value']);
        $this->assertSame(['p' => 1, 'q' => true], $d['e']['params']);
        $this->assertInstanceOf(SfBytes::class, $d['f']['value']);
        $this->assertSame("\x01\x02\x03", $d['f']['value']->bin);
        $this->assertSame(-1.5, $d['g']['value']);
    }

    public function testInnerListAndParams(): void
    {
        $v = 'sig=("@method" "@authority" "@path" "signature-key");created=1730217600;keyid="k1"';
        $d = SF::parseDictionary($v);
        $this->assertSame(['@method', '@authority', '@path', 'signature-key'], array_column($d['sig']['items'], 'value'));
        $this->assertSame(['created' => 1730217600, 'keyid' => 'k1'], $d['sig']['params']);
        $this->assertSame(substr($v, 4), SF::serializeMember($d['sig']));
        $this->assertSame($v, SF::serializeDictionary($d));
    }

    public function testWhitespaceTolerance(): void
    {
        $d = SF::parseDictionary("a=1 ,\tb=2,c=( 1  2 );x");
        $this->assertSame(1, $d['a']['value']);
        $this->assertSame(2, $d['b']['value']);
        $this->assertSame([1, 2], array_column($d['c']['items'], 'value'));
        $this->assertSame('a=1, b=2, c=(1 2);x', SF::serializeDictionary($d));
        $this->assertSame([], SF::parseDictionary(''));
        $this->assertSame([], SF::parseDictionary('   '));
    }

    public function testDuplicateKeyLastWins(): void
    {
        $d = SF::parseDictionary('a=1, b=2, a=3');
        $this->assertSame(3, $d['a']['value']);
        $this->assertSame(['b', 'a'], array_keys($d));
    }

    public function testStringEscapes(): void
    {
        $d = SF::parseDictionary('s="a\\"b\\\\c"');
        $this->assertSame('a"b\\c', $d['s']['value']);
        $this->assertSame('"a\\"b\\\\c"', SF::serializeString('a"b\\c'));
    }

    public function testListAndItem(): void
    {
        $l = SF::parseList('jwt, hwk;x=1, ("a" "b")');
        $this->assertSame('jwt', (string) $l[0]['value']);
        $this->assertSame(['x' => 1], $l[1]['params']);
        $this->assertSame(['a', 'b'], array_column($l[2]['items'], 'value'));
        $this->assertSame('Ed25519', (string) SF::parseList('Ed25519, ES256')[0]['value']);
        $this->assertSame(42, SF::parseItem(' 42 ')['value']);
    }

    public function testTokensWithSlashAndColon(): void
    {
        $i = SF::parseItem('foo/bar:baz');
        $this->assertSame('foo/bar:baz', (string) $i['value']);
    }

    public function testSerializeBareItems(): void
    {
        $this->assertSame('?1', SF::serializeBareItem(true));
        $this->assertSame('?0', SF::serializeBareItem(false));
        $this->assertSame('-7', SF::serializeBareItem(-7));
        $this->assertSame('1.5', SF::serializeBareItem(1.5));
        $this->assertSame('2.0', SF::serializeBareItem(2.0));
        $this->assertSame('tok', SF::serializeBareItem(new SfToken('tok')));
        $this->assertSame(':AQID:', SF::serializeBareItem(new SfBytes("\x01\x02\x03")));
        $this->assertSame(';a=1;b', SF::serializeParams(['a' => 1, 'b' => true]));
        $this->assertSame('("x" y);n=1', SF::serializeInnerList(['x', new SfToken('y')], ['n' => 1]));
    }

    /** @return array<string, array{string}> */
    public static function badDictionaries(): array
    {
        return [
            'trailing comma' => ['a=1,'],
            'upper key' => ['A=1'],
            'unterminated string' => ['a="x'],
            'bad escape' => ['a="\\x"'],
            'non-ascii string' => ["a=\"\xc3\xa9\""],
            'unterminated inner list' => ['a=(1 2'],
            'bad byte seq' => ['a=:%%:'],
            'unterminated bytes' => ['a=:AQID'],
            'bad boolean' => ['a=?2'],
            'junk after member' => ['a=1 b=2'],
            'integer too long' => ['a=1234567890123456'],
            'decimal fraction too long' => ['a=1.2345'],
            'dangling decimal point' => ['a=1.'],
            'bad leading char' => ['a=%'],
            'no separator in inner list' => ['a=("x""y")'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('badDictionaries')]
    public function testRejectsMalformed(string $v): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SF::parseDictionary($v);
    }

    public function testSerializerRejectsBadInput(): void
    {
        foreach ([fn () => SF::serializeString("tab\there"), fn () => SF::serializeToken('1abc'), fn () => SF::serializeKey('Bad')] as $fn) {
            try {
                $fn();
                $this->fail('accepted invalid input');
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }
}
