# SPDX-License-Identifier: Apache-2.0
"""Encoding primitives: integers, ``lp()``, base64url, strings (Section 2.2, 4.1, 4.4).

String checks follow Section 4.1. The Unicode pin (16.0.0, ``[OI-16]``)
can only be honoured when Python's ``unicodedata`` carries exactly that
version; ``UNICODE_PIN_OK`` tells callers whether it does. With any other
version, NFC and General_Category results may differ from a conforming
implementation for code points whose properties changed between versions.
"""

from __future__ import annotations

import base64
import binascii
import struct
import unicodedata
import warnings

from .errors import AabError, E_BAD_UTF8, E_LENGTH, E_NOT_NFC

# SPEC-AMBIGUITY: 4.1 rule 3 / [OI-16]: "an implementation with newer Unicode
# data MUST still apply the 16.0.0 assignments" requires shipping 16.0.0
# tables; the spec does not say how, nor what an implementation with *older*
# data must do. We use the interpreter's unicodedata and warn when it is not
# 16.0.0 (Python 3.14 has 16.0.0; 3.9-3.13 have 13.0-15.1).
PINNED_UNICODE_VERSION = "16.0.0"
UNICODE_VERSION = unicodedata.unidata_version
UNICODE_PIN_OK = UNICODE_VERSION == PINNED_UNICODE_VERSION

if not UNICODE_PIN_OK:  # pragma: no cover - depends on the interpreter
    warnings.warn(
        "aab: Python unicodedata is %s, the spec pins %s (Section 4.1); "
        "NFC/unassigned checks may disagree with a conforming implementation"
        % (UNICODE_VERSION, PINNED_UNICODE_VERSION),
        RuntimeWarning,
        stacklevel=2,
    )

#: Section 4.2 rule 5: maximum length of one value, including lp() values.
MAX_VALUE_LEN = 1 << 24


def u8(n: int) -> bytes:
    return struct.pack(">B", n)


def u16(n: int) -> bytes:
    return struct.pack(">H", n)


def u32(n: int) -> bytes:
    return struct.pack(">I", n)


def u64(n: int) -> bytes:
    return struct.pack(">Q", n)


def i64(n: int) -> bytes:
    return struct.pack(">q", n)


def lp(x: bytes) -> bytes:
    """``u32(len(x)) || x`` (Section 2.2)."""
    if len(x) > MAX_VALUE_LEN:
        raise AabError(E_LENGTH, "lp() value longer than 2^24 bytes")
    return u32(len(x)) + x


def read_fixed_uint(value: bytes, width: int) -> int:
    """Decode a fixed-width big-endian unsigned field (Section 4.2 rule 6)."""
    if len(value) != width:
        raise AabError(E_LENGTH, "fixed-width field: %d bytes, expected %d" % (len(value), width))
    return int.from_bytes(value, "big", signed=False)


def read_i64(value: bytes) -> int:
    if len(value) != 8:
        raise AabError(E_LENGTH, "i64 field: %d bytes, expected 8" % len(value))
    return int.from_bytes(value, "big", signed=True)


def read_id16(value: bytes) -> bytes:
    if len(value) != 16:
        raise AabError(E_LENGTH, "16-byte id field: %d bytes" % len(value))
    return value


def split_lp(data: bytes, count: int) -> list:
    """Split a sub-structure of exactly ``count`` lp() values (Section 4.2).

    The values must exactly fill ``data``; else ``E_LENGTH``.
    """
    out = []
    pos = 0
    for _ in range(count):
        if len(data) - pos < 4:
            raise AabError(E_LENGTH, "sub-structure: truncated lp() length")
        n = int.from_bytes(data[pos:pos + 4], "big")
        pos += 4
        if n > MAX_VALUE_LEN:
            raise AabError(E_LENGTH, "sub-structure: lp() value longer than 2^24")
        if n > len(data) - pos:
            raise AabError(E_LENGTH, "sub-structure: lp() length exceeds input")
        out.append(data[pos:pos + n])
        pos += n
    if pos != len(data):
        raise AabError(E_LENGTH, "sub-structure: %d unused bytes" % (len(data) - pos))
    return out


def read_lp(data: bytes, pos: int):
    """Read one lp() value at ``pos``; return (value, new_pos)."""
    if len(data) - pos < 4:
        raise AabError(E_LENGTH, "truncated lp() length")
    n = int.from_bytes(data[pos:pos + 4], "big")
    pos += 4
    if n > MAX_VALUE_LEN:
        raise AabError(E_LENGTH, "lp() value longer than 2^24")
    if n > len(data) - pos:
        raise AabError(E_LENGTH, "lp() length exceeds input")
    return data[pos:pos + n], pos + n


def b64u(x: bytes) -> str:
    """base64url without padding (RFC 4648 section 5)."""
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    """Strict inverse of :func:`b64u`: no padding, URL alphabet only, canonical."""
    if not isinstance(s, str) or "=" in s:
        raise ValueError("not unpadded base64url")
    for ch in s:
        if not (ch.isascii() and (ch.isalnum() or ch in "-_")):
            raise ValueError("not base64url")
    try:
        raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError(str(exc))
    if b64u(raw) != s:
        raise ValueError("non-canonical base64url")
    return raw


def check_text(s: str) -> str:
    """Apply Section 4.1 rules 2, 3 and 5 to an already decoded string.

    Surrogate code points (only reachable through JSON escapes) and U+0000
    are ``E_BAD_UTF8``; unassigned code points and non-NFC text are
    ``E_NOT_NFC``. The string is never normalized.
    """
    for ch in s:
        o = ord(ch)
        if o == 0 or 0xD800 <= o <= 0xDFFF:
            raise AabError(E_BAD_UTF8, "U+%04X not allowed" % o)
    for ch in s:
        if unicodedata.category(ch) == "Cn":
            raise AabError(E_NOT_NFC, "unassigned code point U+%04X" % ord(ch))
    if not unicodedata.is_normalized("NFC", s):
        raise AabError(E_NOT_NFC, "string not in NFC")
    return s


def check_string(b: bytes) -> str:
    """``utf8()`` in reverse: decode and check a string field (Section 4.1)."""
    try:
        s = bytes(b).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AabError(E_BAD_UTF8, str(exc))
    return check_text(s)


def utf8(s: str) -> bytes:
    """``utf8(s)`` of Section 2.2: check, then encode. Producers must emit NFC."""
    return check_text(s).encode("utf-8")
