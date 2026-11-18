"""RFC 8941 structured fields: the subset AAuth headers use (Signature-Input, Signature,
Signature-Key, AAuth-Requirement, Signature-Error)."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Union


class Token(str):
    """An RFC 8941 token (unquoted), e.g. the ``jwt`` in ``sig=jwt;jwt="..."``."""


@dataclass
class ByteSeq:
    b64: str

    @property
    def value(self) -> bytes:
        return base64.b64decode(self.b64)


@dataclass
class Item:
    value: Any
    params: Dict[str, Any] = field(default_factory=dict)
    raw: str = ""


@dataclass
class InnerList:
    items: List[Item]
    params: Dict[str, Any] = field(default_factory=dict)
    raw: str = ""


Member = Union[Item, InnerList]

_KEY = re.compile(r"[a-z*][a-z0-9_.*-]*")
_NUM = re.compile(r"-?\d+(\.\d+)?")
_TOKEN = re.compile(r"[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*")
_B64 = re.compile(r"[A-Za-z0-9+/=]*")


class SfError(ValueError):
    pass


class _Parser:
    def __init__(self, s: str):
        self.s = s or ""
        self.i = 0

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def sp(self) -> None:
        while self.peek() == " ":
            self.i += 1

    def ows(self) -> None:
        while self.peek() in (" ", "\t") and self.peek():
            self.i += 1

    def fail(self, what: str):
        raise SfError(f"structured field parse error at {self.i}: {what}")

    def key(self) -> str:
        m = _KEY.match(self.s, self.i)
        if not m:
            self.fail("key")
        self.i = m.end()
        return m.group(0)

    def bare(self) -> Any:
        c = self.peek()
        if c == '"':
            out = []
            self.i += 1
            while True:
                if self.i >= len(self.s):
                    self.fail("unterminated string")
                ch = self.s[self.i]
                self.i += 1
                if ch == "\\":
                    if self.i >= len(self.s) or self.s[self.i] not in '"\\':
                        self.fail("bad escape")
                    out.append(self.s[self.i])
                    self.i += 1
                elif ch == '"':
                    return "".join(out)
                elif ord(ch) < 0x20 or ord(ch) > 0x7E:
                    self.fail("bad string character")
                else:
                    out.append(ch)
        if c == ":":
            end = self.s.find(":", self.i + 1)
            if end < 0:
                self.fail("unterminated bytes")
            b = self.s[self.i + 1 : end]
            if not _B64.fullmatch(b):
                self.fail("bad bytes")
            self.i = end + 1
            return ByteSeq(b)
        if c == "?":
            v = self.s[self.i + 1 : self.i + 2]
            if v not in ("0", "1"):
                self.fail("bad boolean")
            self.i += 2
            return v == "1"
        m = _NUM.match(self.s, self.i)
        if m:
            self.i = m.end()
            return float(m.group(0)) if m.group(1) else int(m.group(0))
        m = _TOKEN.match(self.s, self.i)
        if m:
            self.i = m.end()
            return Token(m.group(0))
        self.fail("bare item")

    def params(self) -> Dict[str, Any]:
        p: Dict[str, Any] = {}
        while self.peek() == ";":
            self.i += 1
            self.sp()
            k = self.key()
            v: Any = True
            if self.peek() == "=":
                self.i += 1
                v = self.bare()
            p[k] = v
        return p

    def item_or_list(self) -> Member:
        start = self.i
        if self.peek() == "(":
            self.i += 1
            items: List[Item] = []
            while True:
                self.sp()
                if self.peek() == ")":
                    self.i += 1
                    break
                v = self.bare()
                items.append(Item(v, self.params()))
                if self.peek() not in (" ", ")"):
                    self.fail("inner list")
            m: Member = InnerList(items, self.params())
        else:
            v = self.bare()
            m = Item(v, self.params())
        m.raw = self.s[start : self.i]
        return m


def parse_dictionary(header: str) -> Dict[str, Member]:
    """Parse a Dictionary. Each member keeps its exact text in ``.raw`` (needed for @signature-params)."""
    p = _Parser(header)
    out: Dict[str, Member] = {}
    p.sp()
    if p.i >= len(p.s):
        return out
    while True:
        p.sp()
        k = p.key()
        if p.peek() == "=":
            p.i += 1
            out[k] = p.item_or_list()
        else:
            start = p.i
            out[k] = Item(True, p.params())
            out[k].raw = p.s[start : p.i]
        p.ows()
        if p.i >= len(p.s):
            return out
        if p.peek() != ",":
            p.fail("expected ,")
        p.i += 1
        p.ows()


def serialize_string(s: str) -> str:
    if any(ord(c) < 0x20 or ord(c) > 0x7E for c in s):
        raise SfError("only printable ASCII can be serialized as an sf-string")
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _plain(v: Any) -> Any:
    if isinstance(v, ByteSeq):
        return v.b64
    if isinstance(v, Token):
        return str(v)
    return v


def parse_requirement(value: str) -> Dict[str, Any]:
    """AAuth-Requirement -> {"requirement": ..., <param>: ...}. Tolerant: {} on garbage."""
    if not value:
        return {}
    try:
        d = parse_dictionary(value)
    except SfError:
        return {}
    m = d.get("requirement")
    if not isinstance(m, Item):
        return {}
    out = {"requirement": _plain(m.value)}
    for k, v in m.params.items():
        out[k] = _plain(v)
    return out


def parse_signature_error(value: str) -> Dict[str, Any]:
    """Signature-Error: error=<token>[, required_input=(...)] -> {"error": ..., ...}."""
    if not value:
        return {}
    try:
        d = parse_dictionary(value)
    except SfError:
        return {"error": str(value)}
    out: Dict[str, Any] = {}
    for k, v in d.items():
        out[k] = [_plain(i.value) for i in v.items] if isinstance(v, InnerList) else _plain(v.value)
    return out
