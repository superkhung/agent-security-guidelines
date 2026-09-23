# SPDX-License-Identifier: Apache-2.0
"""Strict JSON parsing with the rejection rules of Section 4.3.

Values are returned as: ``dict`` (members in received order), ``list``,
``str``, ``bool``, ``None`` and ``float`` for every number. Every number
that survives the ``E_NUMBER`` rule is exactly one binary64 value, so
``float`` loses nothing.

Error precedence (the spec does not define one when several rules apply):

1. ill-formed UTF-8 or a raw U+0000 anywhere in the text: ``E_BAD_UTF8``;
2. any grammar violation anywhere in the text: ``E_JSON``;
3. otherwise the first of ``E_BAD_UTF8`` (escapes), ``E_NOT_NFC``,
   ``E_DUP_KEY``, ``E_NUMBER`` in document order.
"""

from __future__ import annotations

import re
from decimal import Decimal

from . import encoding
from .errors import (
    AabError,
    E_BAD_UTF8,
    E_DUP_KEY,
    E_JSON,
    E_NUMBER,
)

# SPEC-AMBIGUITY: 4.3: no precedence between E_BAD_UTF8/E_JSON/E_NOT_NFC/
# E_DUP_KEY/E_NUMBER when one text violates several rules. We use: byte-level
# UTF-8 first, then grammar over the whole text, then document order.

# SPEC-AMBIGUITY: 4.3: no nesting depth limit is defined. We reject deeper
# nesting with E_JSON; other implementations may accept or fail differently.
MAX_DEPTH = 256

_NUMBER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_WS = " \t\n\r"


class _Syntax(Exception):
    pass


class _Parser:
    def __init__(self, text: str, spans: bool):
        self.s = text
        self.i = 0
        self.first_error = None  # first semantic AabError, document order
        self.spans = {} if spans else None

    def semantic(self, code: str, detail: str) -> None:
        if self.first_error is None:
            self.first_error = AabError(code, detail)

    def ws(self) -> None:
        s, i = self.s, self.i
        while i < len(s) and s[i] in _WS:
            i += 1
        self.i = i

    def value(self, path: tuple, depth: int):
        if depth > MAX_DEPTH:
            raise _Syntax("nesting deeper than %d (implementation limit)" % MAX_DEPTH)
        self.ws()
        if self.i >= len(self.s):
            raise _Syntax("unexpected end of text")
        start = self.i
        c = self.s[self.i]
        if c == "{":
            v = self.obj(path, depth)
        elif c == "[":
            v = self.arr(path, depth)
        elif c == '"':
            v = self.string()
        elif c == "-" or "0" <= c <= "9":
            v = self.number()
        elif self.s.startswith("true", self.i):
            self.i += 4
            v = True
        elif self.s.startswith("false", self.i):
            self.i += 5
            v = False
        elif self.s.startswith("null", self.i):
            self.i += 4
            v = None
        else:
            raise _Syntax("unexpected character %r at %d" % (c, self.i))
        if self.spans is not None:
            self.spans[path] = (start, self.i)
        return v

    def obj(self, path: tuple, depth: int) -> dict:
        self.i += 1
        out = {}
        self.ws()
        if self.i < len(self.s) and self.s[self.i] == "}":
            self.i += 1
            return out
        while True:
            self.ws()
            if self.i >= len(self.s) or self.s[self.i] != '"':
                raise _Syntax("expected member name at %d" % self.i)
            name = self.string()
            if name in out:
                self.semantic(E_DUP_KEY, "duplicate member name %r" % name)
            self.ws()
            if self.i >= len(self.s) or self.s[self.i] != ":":
                raise _Syntax("expected ':' at %d" % self.i)
            self.i += 1
            v = self.value(path + (name,), depth + 1)
            if name not in out:
                out[name] = v
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == ",":
                self.i += 1
                continue
            if self.i < len(self.s) and self.s[self.i] == "}":
                self.i += 1
                return out
            raise _Syntax("expected ',' or '}' at %d" % self.i)

    def arr(self, path: tuple, depth: int) -> list:
        self.i += 1
        out = []
        self.ws()
        if self.i < len(self.s) and self.s[self.i] == "]":
            self.i += 1
            return out
        while True:
            out.append(self.value(path + (len(out),), depth + 1))
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == ",":
                self.i += 1
                continue
            if self.i < len(self.s) and self.s[self.i] == "]":
                self.i += 1
                return out
            raise _Syntax("expected ',' or ']' at %d" % self.i)

    def _hex4(self) -> int:
        h = self.s[self.i:self.i + 4]
        if len(h) != 4 or any(ch not in "0123456789abcdefABCDEF" for ch in h):
            raise _Syntax("bad \\u escape at %d" % self.i)
        self.i += 4
        return int(h, 16)

    def string(self) -> str:
        s = self.s
        self.i += 1  # opening quote
        parts = []
        bad = False
        while True:
            if self.i >= len(s):
                raise _Syntax("unterminated string")
            c = s[self.i]
            if c == '"':
                self.i += 1
                break
            if c == "\\":
                self.i += 1
                if self.i >= len(s):
                    raise _Syntax("unterminated escape")
                e = s[self.i]
                self.i += 1
                simple = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f",
                          "n": "\n", "r": "\r", "t": "\t"}
                if e in simple:
                    parts.append(simple[e])
                elif e == "u":
                    cu = self._hex4()
                    if 0xD800 <= cu <= 0xDBFF and s.startswith("\\u", self.i):
                        save = self.i
                        self.i += 2
                        lo = self._hex4()
                        if 0xDC00 <= lo <= 0xDFFF:
                            parts.append(chr(0x10000 + ((cu - 0xD800) << 10) + (lo - 0xDC00)))
                            continue
                        self.i = save
                    if 0xD800 <= cu <= 0xDFFF:
                        bad = True
                        self.semantic(E_BAD_UTF8, "unpaired surrogate escape \\u%04X" % cu)
                    elif cu == 0:
                        bad = True
                        self.semantic(E_BAD_UTF8, "escaped U+0000")
                    parts.append(chr(cu))
                else:
                    raise _Syntax("invalid escape \\%s" % e)
                continue
            if ord(c) < 0x20:
                raise _Syntax("unescaped control character U+%04X in string" % ord(c))
            parts.append(c)
            self.i += 1
        out = "".join(parts)
        if not bad:
            try:
                encoding.check_text(out)
            except AabError as exc:
                self.semantic(exc.code, exc.detail)
        return out

    def number(self) -> float:
        m = _NUMBER_RE.match(self.s, self.i)
        if not m or m.end() == self.i:
            raise _Syntax("bad number at %d" % self.i)
        lit = m.group(0)
        self.i = m.end()
        # Import here to avoid a cycle: jcs imports jsonstrict for types only.
        from .jcs import number_to_string

        f = float(lit)
        if f in (float("inf"), float("-inf")):
            self.semantic(E_NUMBER, "number %s overflows binary64" % lit)
            return 0.0
        ser = number_to_string(f)
        if Decimal(ser) != Decimal(lit):
            self.semantic(E_NUMBER, "number %s serializes as %s" % (lit, ser))
        return f


def _decode_text(data) -> str:
    if isinstance(data, str):
        text = data
        try:
            text.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise AabError(E_BAD_UTF8, str(exc))
    else:
        try:
            text = bytes(data).decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise AabError(E_BAD_UTF8, str(exc))
    # SPEC-AMBIGUITY: 4.1/4.3: a raw (unescaped) U+0000 is both invalid JSON
    # (RFC 8259 requires escaping controls) and "U+0000 in a string". We
    # report E_BAD_UTF8 for a raw U+0000 anywhere in the text.
    if "\x00" in text:
        raise AabError(E_BAD_UTF8, "raw U+0000 in JSON text")
    return text


def parse(data, spans: bool = False):
    """Parse JSON text (``bytes`` or ``str``) under Section 4.3.

    Returns the value, or ``(value, spans)`` when ``spans`` is true, where
    ``spans`` maps a path tuple to the ``(start, end)`` character offsets of
    that value in the decoded text.
    """
    text = _decode_text(data)
    p = _Parser(text, spans)
    try:
        v = p.value((), 0)
        p.ws()
        if p.i != len(text):
            raise _Syntax("trailing characters at %d" % p.i)
    except _Syntax as exc:
        raise AabError(E_JSON, str(exc))
    if p.first_error is not None:
        raise p.first_error
    if spans:
        return v, (text, p.spans)
    return v


def raw_span(text_and_spans, path: tuple) -> bytes:
    """Return the exact UTF-8 bytes of the value at ``path`` as received."""
    text, spans = text_and_spans
    a, b = spans[path]
    return text[a:b].encode("utf-8")
