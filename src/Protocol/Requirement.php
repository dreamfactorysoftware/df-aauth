<?php

namespace DreamFactory\Core\AAuth\Protocol;

/** AAuth-Requirement header (§11.6.1): SF Dictionary with member `requirement` (a Token) plus parameters. */
final class Requirement
{
    /**
     * `requirement=<token>; k="v"; ...` — strings become SF Strings, ints Integers, bools Booleans,
     * SfToken Tokens. Parameter separator "; " matches the spec examples (valid SF).
     */
    public static function header(string $requirement, array $params = []): string
    {
        $out = 'requirement=' . StructuredFields::serializeToken($requirement);
        foreach ($params as $k => $v) {
            $out .= '; ' . StructuredFields::serializeKey((string) $k);
            if ($v !== true) {
                $out .= '=' . StructuredFields::serializeBareItem($v);
            }
        }
        return $out;
    }

    /**
     * ['requirement' => 'auth-token', 'resource-token' => '...', ...] with plain values.
     * Returns [] for an empty, malformed or requirement-less header.
     */
    public static function parse(string $v): array
    {
        try {
            $dict = StructuredFields::parseDictionary($v);
        } catch (\InvalidArgumentException) {
            return [];
        }
        $m = $dict['requirement'] ?? null;
        if ($m === null || isset($m['items']) || !($m['value'] instanceof SfToken)) {
            return [];
        }
        $out = ['requirement' => $m['value']->value];
        foreach ($m['params'] as $k => $pv) {
            if ($k !== 'requirement') {
                $out[$k] = StructuredFields::plain($pv);
            }
        }
        return $out;
    }
}
