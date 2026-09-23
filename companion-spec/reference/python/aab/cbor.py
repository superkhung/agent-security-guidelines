# SPDX-License-Identifier: Apache-2.0
"""Minimal strict CBOR (RFC 8949) decoder and deterministic encoder.

Used for the evidence container (Section 7.1), COSE_Sign1 (Section 7.3,
RFC 9052) and the extensions of authenticatorData (Section 7.2 step 6).

``decode(data, deterministic=True)`` enforces the core deterministic
encoding requirements of RFC 8949 section 4.2.1: preferred (shortest) argument
encoding, definite lengths only, map keys in bytewise lexicographic order
of their encodings. Every mode rejects duplicate map keys, ill-formed
UTF-8 in text strings, reserved additional-information values and
trailing bytes. Callers map ``CborError`` to the error code of their step.
"""

from __future__ import annotations

import struct

MAX_DEPTH = 64


class CborError(Exception):
    pass


class Tag:
    """A tagged data item."""

    __slots__ = ("tag", "value")

    def __init__(self, tag: int, value):
        self.tag = tag
        self.value = value

    def __eq__(self, other):
        return isinstance(other, Tag) and (self.tag, self.value) == (other.tag, other.value)

    def __repr__(self):
        return "Tag(%d, %r)" % (self.tag, self.value)


class _Undefined:
    def __repr__(self):
        return "undefined"


UNDEFINED = _Undefined()


class _Decoder:
    def __init__(self, data: bytes, deterministic: bool):
        self.d = bytes(data)
        self.i = 0
        self.det = deterministic

    def need(self, n: int) -> bytes:
        if len(self.d) - self.i < n:
            raise CborError("truncated")
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def arg(self, ai: int):
        """Return the argument for additional information ``ai`` (None = indefinite)."""
        if ai < 24:
            return ai
        if ai == 24:
            v = self.need(1)[0]
            if self.det and v < 24:
                raise CborError("non-preferred 1-byte argument")
            return v
        if ai == 25:
            v = int.from_bytes(self.need(2), "big")
            if self.det and v <= 0xFF:
                raise CborError("non-preferred 2-byte argument")
            return v
        if ai == 26:
            v = int.from_bytes(self.need(4), "big")
            if self.det and v <= 0xFFFF:
                raise CborError("non-preferred 4-byte argument")
            return v
        if ai == 27:
            v = int.from_bytes(self.need(8), "big")
            if self.det and v <= 0xFFFFFFFF:
                raise CborError("non-preferred 8-byte argument")
            return v
        if ai == 31:
            return None
        raise CborError("reserved additional information %d" % ai)

    def item(self, depth: int):
        if depth > MAX_DEPTH:
            raise CborError("nesting too deep")
        ib = self.need(1)[0]
        mt, ai = ib >> 5, ib & 0x1F
        if mt == 7:
            return self.simple(ai)
        n = self.arg(ai)
        if n is None:
            if mt in (0, 1, 6):
                raise CborError("indefinite length not allowed for major type %d" % mt)
            if self.det:
                raise CborError("indefinite length")
            return self.indefinite(mt, depth)
        if mt == 0:
            return n
        if mt == 1:
            return -1 - n
        if mt == 2:
            return self.need(n)
        if mt == 3:
            try:
                return self.need(n).decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                raise CborError("ill-formed UTF-8 in text string")
        if mt == 4:
            return [self.item(depth + 1) for _ in range(n)]
        if mt == 5:
            return self.map_items(n, depth)
        return Tag(n, self.item(depth + 1))

    def map_items(self, n, depth):
        out = {}
        prev = None
        for _ in range(n):
            start = self.i
            k = self.item(depth + 1)
            kenc = self.d[start:self.i]
            if self.det and prev is not None and not (prev < kenc):
                raise CborError("map keys not in bytewise order")
            prev = kenc
            if isinstance(k, bool) or not isinstance(k, (int, str, bytes)):
                raise CborError("unsupported map key type (only int, tstr, bstr)")
            if k in out:
                raise CborError("duplicate map key")
            out[k] = self.item(depth + 1)
        return out

    def indefinite(self, mt, depth):
        if mt in (2, 3):
            chunks = []
            while True:
                if self.d[self.i:self.i + 1] == b"\xff":
                    self.i += 1
                    break
                ib = self.need(1)[0]
                if ib >> 5 != mt or (ib & 0x1F) == 31:
                    raise CborError("bad chunk in indefinite string")
                chunks.append(self.need(self.arg(ib & 0x1F)))
            raw = b"".join(chunks)
            if mt == 2:
                return raw
            try:
                return raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                raise CborError("ill-formed UTF-8 in text string")
        if mt == 4:
            out = []
            while self.d[self.i:self.i + 1] != b"\xff":
                out.append(self.item(depth + 1))
            self.i += 1
            return out
        out = {}
        while self.d[self.i:self.i + 1] != b"\xff":
            k = self.item(depth + 1)
            if isinstance(k, bool) or not isinstance(k, (int, str, bytes)):
                raise CborError("unsupported map key type (only int, tstr, bstr)")
            if k in out:
                raise CborError("duplicate map key")
            out[k] = self.item(depth + 1)
        self.i += 1
        return out

    def simple(self, ai):
        if ai < 20:
            raise CborError("unassigned simple value")
        if ai == 20:
            return False
        if ai == 21:
            return True
        if ai == 22:
            return None
        if ai == 23:
            return UNDEFINED
        if ai == 24:
            v = self.need(1)[0]
            raise CborError("simple value %d not supported" % v)
        if ai == 25:
            raw = self.need(2)
            v = struct.unpack(">e", raw)[0]
            return v
        if ai == 26:
            v = struct.unpack(">f", self.need(4))[0]
            if self.det and _fits_half(v):
                raise CborError("non-preferred float")
            return v
        if ai == 27:
            v = struct.unpack(">d", self.need(8))[0]
            if self.det and (_fits_half(v) or _fits_single(v)):
                raise CborError("non-preferred float")
            return v
        if ai == 31:
            raise CborError("unexpected break")
        raise CborError("reserved simple encoding")


def _fits_half(v: float) -> bool:
    try:
        return struct.unpack(">e", struct.pack(">e", v))[0] == v or v != v
    except (OverflowError, struct.error):
        return False


def _fits_single(v: float) -> bool:
    try:
        return struct.unpack(">f", struct.pack(">f", v))[0] == v or v != v
    except (OverflowError, struct.error):
        return False


def decode(data: bytes, deterministic: bool = True):
    """Decode exactly one data item filling ``data``."""
    dec = _Decoder(data, deterministic)
    v = dec.item(0)
    if dec.i != len(dec.d):
        raise CborError("%d trailing bytes" % (len(dec.d) - dec.i))
    return v


def decode_prefix(data: bytes, pos: int = 0, deterministic: bool = False):
    """Decode one data item starting at ``pos``; return ``(value, end)``."""
    dec = _Decoder(data, deterministic)
    dec.i = pos
    v = dec.item(0)
    return v, dec.i


# --- deterministic encoder (for building vectors and Sig_structure) --------


def _head(mt: int, n: int) -> bytes:
    if n < 24:
        return bytes([(mt << 5) | n])
    if n <= 0xFF:
        return bytes([(mt << 5) | 24, n])
    if n <= 0xFFFF:
        return bytes([(mt << 5) | 25]) + n.to_bytes(2, "big")
    if n <= 0xFFFFFFFF:
        return bytes([(mt << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(mt << 5) | 27]) + n.to_bytes(8, "big")


def encode(v) -> bytes:
    """Deterministic encoding (RFC 8949 section 4.2.1) of int/bytes/str/list/dict/Tag/bool/None."""
    if v is False:
        return b"\xf4"
    if v is True:
        return b"\xf5"
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, (bytes, bytearray)):
        return _head(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, (list, tuple)):
        return _head(4, len(v)) + b"".join(encode(x) for x in v)
    if isinstance(v, dict):
        items = sorted((encode(k), encode(val)) for k, val in v.items())
        return _head(5, len(items)) + b"".join(k + val for k, val in items)
    if isinstance(v, Tag):
        return _head(6, v.tag) + encode(v.value)
    raise TypeError("cannot encode %r" % type(v))
