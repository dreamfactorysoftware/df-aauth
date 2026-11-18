<?php

namespace DreamFactory\Core\AAuth\Protocol;

/**
 * Just enough RFC 8941 / RFC 9651 Structured Fields for AAuth headers.
 *
 * Bare items map to PHP values: Integer => int, Decimal => float, Boolean => bool, String => string,
 * Token => SfToken, Byte Sequence => SfBytes.
 *
 * Parsed shapes:
 *   item       ['value' => bare, 'params' => [name => bare]]
 *   inner list ['items' => [item, ...], 'params' => [name => bare]]
 * parseDictionary() returns [key => item|inner list]; parseList() returns [item|inner list, ...].
 *
 * Parse failures throw \InvalidArgumentException.
 */
final class StructuredFields
{
    // ----------------------------------------------------------------- parsing

    public static function parseDictionary(string $v): array
    {
        $p = new SfParser($v);
        $out = [];
        $p->skipSp();
        if ($p->eof()) {
            return $out;
        }
        while (true) {
            $key = $p->parseKey();
            if ($p->peek() === '=') {
                $p->pos++;
                $member = $p->parseItemOrInnerList();
            } else {
                $member = ['value' => true, 'params' => $p->parseParameters()];
            }
            unset($out[$key]); // last one wins, but keep insertion order of the latest
            $out[$key] = $member;
            if (!$p->afterMember()) {
                return $out;
            }
        }
    }

    public static function parseList(string $v): array
    {
        $p = new SfParser($v);
        $out = [];
        $p->skipSp();
        if ($p->eof()) {
            return $out;
        }
        while (true) {
            $out[] = $p->parseItemOrInnerList();
            if (!$p->afterMember()) {
                return $out;
            }
        }
    }

    public static function parseItem(string $v): array
    {
        $p = new SfParser($v);
        $p->skipSp();
        $item = $p->parseItem();
        $p->skipSp();
        if (!$p->eof()) {
            throw new \InvalidArgumentException('Trailing characters after item');
        }
        return $item;
    }

    /** Convert a bare value to plain PHP (SfToken => string, SfBytes => binary string). */
    public static function plain(mixed $bare): mixed
    {
        if ($bare instanceof SfToken) {
            return $bare->value;
        }
        if ($bare instanceof SfBytes) {
            return $bare->bin;
        }
        return $bare;
    }

    // ----------------------------------------------------------- serializing

    public static function serializeString(string $s): string
    {
        if (preg_match('/[^\x20-\x7e]/', $s)) {
            throw new \InvalidArgumentException('SF strings allow printable ASCII only');
        }
        return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $s) . '"';
    }

    public static function serializeToken(string $t): string
    {
        if (!preg_match('/^[A-Za-z*][!#$%&\'*+\-.^_`|~0-9A-Za-z:\/]*$/', $t)) {
            throw new \InvalidArgumentException('Invalid SF token');
        }
        return $t;
    }

    public static function serializeKey(string $k): string
    {
        if (!preg_match('/^[a-z*][a-z0-9_\-.*]*$/', $k)) {
            throw new \InvalidArgumentException('Invalid SF key: ' . $k);
        }
        return $k;
    }

    public static function serializeBareItem(mixed $v): string
    {
        return match (true) {
            is_bool($v) => $v ? '?1' : '?0',
            is_int($v) => self::serializeInteger($v),
            is_float($v) => self::serializeDecimal($v),
            is_string($v) => self::serializeString($v),
            $v instanceof SfToken => self::serializeToken($v->value),
            $v instanceof SfBytes => ':' . base64_encode($v->bin) . ':',
            default => throw new \InvalidArgumentException('Unsupported SF bare item'),
        };
    }

    public static function serializeInteger(int $i): string
    {
        if ($i > 999999999999999 || $i < -999999999999999) {
            throw new \InvalidArgumentException('SF integer out of range');
        }
        return (string) $i;
    }

    public static function serializeDecimal(float $f): string
    {
        $r = round($f, 3, PHP_ROUND_HALF_EVEN);
        if (abs($r) >= 1e12) {
            throw new \InvalidArgumentException('SF decimal out of range');
        }
        $s = rtrim(number_format($r, 3, '.', ''), '0');
        return str_ends_with($s, '.') ? $s . '0' : $s;
    }

    public static function serializeParams(array $params): string
    {
        $out = '';
        foreach ($params as $k => $v) {
            $out .= ';' . self::serializeKey((string) $k);
            if ($v !== true) {
                $out .= '=' . self::serializeBareItem($v);
            }
        }
        return $out;
    }

    /** $items: list of bare values or ['value'=>..,'params'=>..] arrays. */
    public static function serializeInnerList(array $items, array $params = []): string
    {
        $parts = [];
        foreach ($items as $it) {
            $parts[] = is_array($it)
                ? self::serializeBareItem($it['value']) . self::serializeParams($it['params'] ?? [])
                : self::serializeBareItem($it);
        }
        return '(' . implode(' ', $parts) . ')' . self::serializeParams($params);
    }

    /** Serialize a parsed member (item or inner list shape). */
    public static function serializeMember(array $m): string
    {
        if (array_key_exists('items', $m)) {
            return self::serializeInnerList($m['items'], $m['params'] ?? []);
        }
        return self::serializeBareItem($m['value']) . self::serializeParams($m['params'] ?? []);
    }

    /** $dict: key => member shape. A Boolean true item is serialized as the bare key. */
    public static function serializeDictionary(array $dict): string
    {
        $parts = [];
        foreach ($dict as $k => $m) {
            $key = self::serializeKey((string) $k);
            if (!array_key_exists('items', $m) && ($m['value'] ?? null) === true) {
                $parts[] = $key . self::serializeParams($m['params'] ?? []);
            } else {
                $parts[] = $key . '=' . self::serializeMember($m);
            }
        }
        return implode(', ', $parts);
    }
}
