<?php

namespace DreamFactory\Core\AAuth\Protocol;

/** @internal RFC 8941 §4.2 parser state. */
final class SfParser
{
    public int $pos = 0;
    private int $len;

    public function __construct(private string $s)
    {
        $this->len = strlen($s);
    }

    public function eof(): bool
    {
        return $this->pos >= $this->len;
    }

    public function peek(): string
    {
        return $this->pos < $this->len ? $this->s[$this->pos] : '';
    }

    public function skipSp(): void
    {
        while ($this->pos < $this->len && $this->s[$this->pos] === ' ') {
            $this->pos++;
        }
    }

    private function skipOws(): void
    {
        while ($this->pos < $this->len && ($this->s[$this->pos] === ' ' || $this->s[$this->pos] === "\t")) {
            $this->pos++;
        }
    }

    private function fail(string $why): never
    {
        throw new \InvalidArgumentException("Structured field parse error at {$this->pos}: {$why}");
    }

    /** After a list/dictionary member: true if another member follows. */
    public function afterMember(): bool
    {
        $this->skipOws();
        if ($this->eof()) {
            return false;
        }
        if ($this->s[$this->pos] !== ',') {
            $this->fail('expected ","');
        }
        $this->pos++;
        $this->skipOws();
        if ($this->eof()) {
            $this->fail('trailing comma');
        }
        return true;
    }

    public function parseItemOrInnerList(): array
    {
        if ($this->peek() === '(') {
            return $this->parseInnerList();
        }
        return $this->parseItem();
    }

    public function parseInnerList(): array
    {
        $this->pos++; // (
        $items = [];
        while (!$this->eof()) {
            $this->skipSp();
            if ($this->peek() === ')') {
                $this->pos++;
                return ['items' => $items, 'params' => $this->parseParameters()];
            }
            $items[] = $this->parseItem();
            $c = $this->peek();
            if ($c !== ' ' && $c !== ')') {
                $this->fail('expected SP or ")" in inner list');
            }
        }
        $this->fail('unterminated inner list');
    }

    public function parseItem(): array
    {
        $v = $this->parseBareItem();
        return ['value' => $v, 'params' => $this->parseParameters()];
    }

    public function parseParameters(): array
    {
        $params = [];
        while ($this->peek() === ';') {
            $this->pos++;
            $this->skipSp();
            $k = $this->parseKey();
            $v = true;
            if ($this->peek() === '=') {
                $this->pos++;
                $v = $this->parseBareItem();
            }
            unset($params[$k]);
            $params[$k] = $v;
        }
        return $params;
    }

    public function parseKey(): string
    {
        if (!preg_match('/\G[a-z*][a-z0-9_\-.*]*/', $this->s, $m, 0, $this->pos)) {
            $this->fail('expected key');
        }
        $this->pos += strlen($m[0]);
        return $m[0];
    }

    public function parseBareItem(): mixed
    {
        $c = $this->peek();
        if ($c === '-' || ctype_digit($c)) {
            return $this->parseNumber();
        }
        if ($c === '"') {
            return $this->parseString();
        }
        if ($c === ':') {
            return $this->parseBytes();
        }
        if ($c === '?') {
            return $this->parseBoolean();
        }
        if ($c !== '' && (ctype_alpha($c) || $c === '*')) {
            return $this->parseToken();
        }
        $this->fail('unexpected character');
    }

    private function parseNumber(): int|float
    {
        if (!preg_match('/\G(-?)(\d+)(?:\.(\d+))?/', $this->s, $m, 0, $this->pos)) {
            $this->fail('bad number');
        }
        $this->pos += strlen($m[0]);
        if (isset($m[3]) && $m[3] !== '') {
            if (strlen($m[2]) > 12 || strlen($m[3]) > 3) {
                $this->fail('decimal too long');
            }
            return (float) $m[0];
        }
        if ($this->peek() === '.') {
            $this->fail('decimal without fraction');
        }
        if (strlen($m[2]) > 15) {
            $this->fail('integer too long');
        }
        return (int) $m[0];
    }

    private function parseString(): string
    {
        $this->pos++;
        $out = '';
        while ($this->pos < $this->len) {
            $c = $this->s[$this->pos++];
            if ($c === '\\') {
                if ($this->pos >= $this->len) {
                    $this->fail('dangling escape');
                }
                $n = $this->s[$this->pos++];
                if ($n !== '"' && $n !== '\\') {
                    $this->fail('bad escape');
                }
                $out .= $n;
            } elseif ($c === '"') {
                return $out;
            } else {
                $o = ord($c);
                if ($o < 0x20 || $o > 0x7e) {
                    $this->fail('non-printable in string');
                }
                $out .= $c;
            }
        }
        $this->fail('unterminated string');
    }

    private function parseToken(): SfToken
    {
        preg_match('/\G[A-Za-z*][!#$%&\'*+\-.^_`|~0-9A-Za-z:\/]*/', $this->s, $m, 0, $this->pos);
        $this->pos += strlen($m[0]);
        return new SfToken($m[0]);
    }

    private function parseBytes(): SfBytes
    {
        $end = strpos($this->s, ':', $this->pos + 1);
        if ($end === false) {
            $this->fail('unterminated byte sequence');
        }
        $b64 = substr($this->s, $this->pos + 1, $end - $this->pos - 1);
        try {
            $bin = B64::stdDecode($b64);
        } catch (\InvalidArgumentException) {
            $this->fail('bad base64 in byte sequence');
        }
        $this->pos = $end + 1;
        return new SfBytes($bin);
    }

    private function parseBoolean(): bool
    {
        $n = $this->s[$this->pos + 1] ?? '';
        if ($n !== '0' && $n !== '1') {
            $this->fail('bad boolean');
        }
        $this->pos += 2;
        return $n === '1';
    }
}
